#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""
Pytest fixtures for linotp tests
"""

# pylint: disable=redefined-outer-name

import contextlib
import copy
import os
import tempfile
from collections.abc import Callable, Iterator
from unittest.mock import patch

import flask
import pytest
from flask.globals import current_app
from flask.testing import FlaskClient

import linotp.app
import linotp.controllers
from linotp import app as app_py
from linotp.app import LinOTPApp, create_app
from linotp.cli.init_cmd import create_audit_keys, create_secret_key
from linotp.flap import setup_request_context
from linotp.flap import tmpl_context as c
from linotp.model import init_db_tables

from . import CompatibleTestResponse, TestController


def pytest_configure(config):
    add_marks = [
        "app_config(dict): add contents of dict to app configuration",
        "nightly: mark test to run only nightly",
        "exclude_sqlite: mark test to always skip with sqlite database",
        "smoketest: mark test to run on softhsm (we do not want to run the full test collection)",
    ]
    for mark in add_marks:
        config.addinivalue_line("markers", mark)


# Definition of Database


def pytest_addoption(parser):
    """Allow the developer to specify a database to test against directly"""

    parser.addoption(
        "--database-uri",
        dest="database_uri",
        action="store",
        default=os.environ.get("LINOTP_PYTEST_DATABASE_URI", "sqlite:///{}"),
        help=(
            "sqlalchemy database URI to allow tests to run "
            "against a particular database (envvar: LINOTP_PYTEST_DATABASE_URI)"
        ),
    )


@pytest.fixture(scope="session")
def key_directory(tmp_path_factory):
    """
    Returns a directory scoped for the complete session

    We generate keys in this directory so that the users' own configuration
    is not affected. But in order to avoid long delays in generating keys,
    we only generate them once per test sesison.
    """
    return tmp_path_factory.mktemp("keys")


@pytest.fixture
def sqlalchemy_uri(request):
    """The SQL alchemy URI to use to configure the database used for tests"""
    uri = request.config.getoption("database_uri")

    # Prevent override through the environment
    try:
        del os.environ["LINOTP_DATABASE_URI"]
    except KeyError:
        pass
    return uri


@pytest.fixture
def base_app(tmp_path, request, sqlalchemy_uri, key_directory):
    """
    App instance without context

    Creates and returns a bare app. If you wish
    an app with an initialised application context,
    use the `app` fixture instead
    """

    db_fd, db_path = None, None

    try:
        # ------------------------------------------------------------------ --

        # if sqlalchemy_uri is the fallback, establish a temp file

        if sqlalchemy_uri == "sqlite:///{}":
            db_fd, db_path = tempfile.mkstemp()
            sqlalchemy_uri = sqlalchemy_uri.format(db_path)

        # ------------------------------------------------------------------ --

        # Skip test if incompatible with sqlite

        if sqlalchemy_uri.startswith("sqlite:"):
            if request.node.get_closest_marker("exclude_sqlite"):
                pytest.skip("non sqlite database required for test")

        # ------------------------------------------------------------------ --

        # create the app with common test config

        base_app_config = {
            "ENV": "testing",  # doesn't make a huge difference for us
            "TESTING": True,
            "DATABASE_URI": sqlalchemy_uri,
            "AUDIT_DATABASE_URI": "SHARED",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "ROOT_DIR": tmp_path,
            "CACHE_DIR": tmp_path / "cache",
            "LOG_FILE_DIR": tmp_path / "logs",
            "AUDIT_PUBLIC_KEY_FILE": key_directory / "audit-public.pem",
            "AUDIT_PRIVATE_KEY_FILE": key_directory / "audit-private.pem",
            "SECRET_FILE": key_directory / "encKey",
            "LOG_LEVEL": "DEBUG",
            "LOG_CONSOLE_LEVEL": "DEBUG",
            "DISABLE_CONTROLLERS": "",
        }

        config = request.node.get_closest_marker("app_config")
        if config is not None:
            base_app_config.update(config.args[0])

        os.environ["LINOTP_CFG"] = ""

        # Pre-generate the important directories
        for key in ("CACHE_DIR", "LOG_FILE_DIR"):
            os.makedirs(base_app_config[key], mode=0o770, exist_ok=True)

        # -----------------------------------------------------------------------

        # Fake running `linotp init enc-key`
        secret_file = base_app_config["SECRET_FILE"]
        if not os.path.exists(secret_file):
            sec_key = 3 * "0123456789abcdef" * 4
            create_secret_key(filename=secret_file, data=sec_key)

        # Fake running `linotp init audit-keys`
        audit_private_key_file = str(base_app_config["AUDIT_PRIVATE_KEY_FILE"])
        if not os.path.exists(audit_private_key_file):
            create_audit_keys(
                audit_private_key_file,
                str(base_app_config["AUDIT_PUBLIC_KEY_FILE"]),
            )

        # -----------------------------------------------------------------------

        os.environ["LINOTP_CMD"] = "init-database"
        app = create_app("testing", base_app_config)

        # Fake running `linotp init database`
        with app.app_context():
            init_db_tables(app, drop_data=True, add_defaults=True)

        yield app

    finally:
        # ------------------------------------------------------------------ --

        # in case of sqlite tempfile fallback, we have to wipe the dishes here

        if db_fd:
            os.close(db_fd)

        if db_path:
            os.unlink(db_path)


@pytest.fixture
def app(base_app, monkeypatch):
    """
    Provide an app and configured application context
    """
    # Disable request time logging
    monkeypatch.setattr(app_py, "log_request_timedelta", lambda self: None)

    with base_app.app_context():
        setup_request_context()

        yield base_app


@pytest.fixture
def adminclient(client, request):
    """
    A client that provides admin authorisation.

    By default, the user is set to "admin". You can override the
    admin username with the following decorator used at the test
    fixture consumer:
    `@pytest.mark.parametrize("authorized_client", ["blub"], indirect=True)`

    Returns the client object with mocked authentication.
    """

    # extract the pytest parameterized username or use fallback if not set.
    admin_user = request.param if hasattr(request, "param") else "admin"

    with (
        patch(
            "linotp.controllers.base.verify_jwt_in_request",
            lambda: None,
        ),
        patch(
            "linotp.controllers.base.get_jwt_identity",
            lambda: {
                "username": admin_user,
                "realm": current_app.config["ADMIN_REALM_NAME"],
                "resolver": "useridresolver.PasswdIdResolver.IdResolver.myDefRes",
            },
        ),
    ):
        yield client


@pytest.fixture
def hsm_obj(app: LinOTPApp):
    """
    A fixture that initialises the HSM object

    The hsm object is returned
    """
    flask.request.environ["REMOTE_ADDR"] = "11.12.13.14"  # Any will do
    app.create_context()

    return c["hsm"]["obj"]


@pytest.fixture
def set_policy(adminclient):
    """
    Factory fixture that provides a function that can be used
    to set a policy
    """

    # We provide this as a fixture so that we can get access
    # to the client fixture within the function
    def _setPolicy(params: dict) -> None:
        """
        Set the given policy and assert that it can be retrieved
        """
        response = adminclient.post("system/setPolicy", json=params)
        assert response.status_code == 200
        assert response.json["result"]["status"]

        getResponse = adminclient.get("system/getPolicy", json=params)
        assert (
            getResponse.json["result"]["value"]["autosms"]["action"] == params["action"]
        )

    return _setPolicy


@pytest.fixture
def scoped_authclient(
    client: FlaskClient,
) -> Callable[[bool, str], contextlib.AbstractContextManager[FlaskClient]]:
    """This fixture returns a authentication client of type FlaskClient.
    With the parameter verify_jwt the jwt_check can be overwirtten, which will
    disable the validation of the request. The request will be done in the
    scope of the user which get provided by the parameter username (default: admin).

    example usage:
        with scoped_authclient(verify_jwt=False, username=user1) as client:
            client.post(...)

    Args:
        verify_jwt (bool): define if the jwt get verified
        username (str): set the username if the verification is disabled

    Returns:
        context manager (FlaskClient): a context manager which yields a FlaskClient
    """

    original_verify_jwt_in_request = linotp.controllers.base.verify_jwt_in_request
    original_get_jwt_identity = linotp.controllers.base.get_jwt_identity

    @contextlib.contextmanager
    def auth_context_manager(
        verify_jwt: bool = False,
        username: str = "admin",
        resolver: str = "useridresolver.PasswdIdResolver.IdResolver.def_resolver",
    ) -> Iterator[FlaskClient]:
        if not verify_jwt:
            with (
                patch(
                    "linotp.controllers.base.verify_jwt_in_request",
                    lambda: None,
                ),
                patch(
                    "linotp.controllers.base.get_jwt_identity",
                    lambda: {
                        "username": username,
                        "resolver": resolver,
                        "realm": current_app.config["ADMIN_REALM_NAME"],
                    },
                ),
            ):
                yield client

        else:
            with (
                patch(
                    "linotp.controllers.base.verify_jwt_in_request",
                    original_verify_jwt_in_request,
                ),
                patch(
                    "linotp.controllers.base.get_jwt_identity",
                    original_get_jwt_identity,
                ),
            ):
                yield client

    return auth_context_manager


class ResolverParams:
    """
    class which specify needed resolver parameters

    Args:
        name (str):
            the name of the resolver

        file_name (str):
            the path to the password file which define the
            users to create in the resolver

        resolver_type (str):
            the type of the resover e.g. passwdresolver
    """

    def __init__(
        self,
        name: str,
        file_name: str,
        resolver_type: str,
    ) -> None:
        self.name = name
        self.file_name = file_name
        self.resolver_type = resolver_type


def _create_realm(
    realm: str,
    resolvers: list[str],
    adminclient: FlaskClient,
) -> CompatibleTestResponse:
    """
    create a realm for test issues.

    Args:
        realm (str):
            name of the realm

        resolvers (list):
            list of the resovers e.g.:
            [
                "useridresolver.PasswdIdResolver.IdResolver.myResolverName1",
                "useridresolver.PasswdIdResolver.IdResolver.myResolverName2"
            ]

        adminclient (FlaskClient):
            the client which should be used for the request
    """

    params = {}
    params["realm"] = realm
    params["resolvers"] = ",".join(resolvers)

    resp = adminclient.post("/system/setRealm", data=params)
    return resp


def _create_resolver(
    resolver_params: ResolverParams,
    adminclient: FlaskClient,
) -> CompatibleTestResponse:
    """
    create a resolver.

    Args:
        resolver_parameters (ResolverParams):
            an instance of the class ResolverParams

        adminclient (FlaskClient):
            the client which should be used for the request

    """
    resolver_params = copy.deepcopy(resolver_params)

    body = {
        "name": resolver_params.name,
        "fileName": resolver_params.file_name,
        "type": resolver_params.resolver_type,
    }

    res = adminclient.post("/system/setResolver", data=body)
    assert res.json["result"]["status"] is True
    assert res.json["result"]["value"] is True

    return res


@pytest.fixture
def create_managed_resolvers(
    scoped_authclient: Callable[..., FlaskClient],
) -> Callable:
    import io
    import json

    def inner_fucntion(
        file_name: str = "def-passwd-plain.csv",
        resolver_name: str = "managed_resolver",
        plaintext: bool = True,
    ) -> None:
        fixture_path = TestController.fixture_path

        def_passwd_file = os.path.join(fixture_path, file_name)

        with open(def_passwd_file, encoding="utf-8") as f:
            content = f.read()

        params = {
            "resolver": resolver_name,
            "passwords_in_plaintext": plaintext,
            "dryrun": False,
            "format": "csv",
            "delimiter": ",",
            "quotechar": '"',
            "column_mapping": json.dumps(
                {
                    "username": 0,
                    "userid": 1,
                    "surname": 2,
                    "givenname": 3,
                    "email": 4,
                    "phone": 5,
                    "mobile": 6,
                    "password": 7,
                }
            ),
        }

        with scoped_authclient(verify_jwt=False, username="admin") as client:
            params.update({"file": (io.BytesIO(content.encode("utf-8")), "user_list")})
            headers = {}
            headers["Content-Type"] = "multipart/form-data"
            client.post("/tools/import_users", data=params, headers=headers)

    return inner_fucntion


@pytest.fixture
def create_common_resolvers(
    scoped_authclient: Callable[..., FlaskClient],
    client: FlaskClient,
) -> None:
    """create two resolver
    The users got import from the password files def-passwd and myDom-passwd

    Args:
        adminclient (FlaskClient):
            the client which should be used for the request
    """
    fixture_path = TestController.fixture_path

    resolver_params = [
        ResolverParams(
            name="def_resolver",
            file_name=os.path.join(fixture_path, "def-passwd"),
            resolver_type="passwdresolver",
        ),
        ResolverParams(
            name="dom_resolver",
            file_name=os.path.join(fixture_path, "myDom-passwd"),
            resolver_type="passwdresolver",
        ),
    ]

    with scoped_authclient(verify_jwt=False, username="admin") as client:
        for resolver_param in resolver_params:
            _create_resolver(resolver_params=resolver_param, adminclient=client)

        from linotp.model.local_admin_user import LocalAdminResolver

        local_admin_resoler = LocalAdminResolver(current_app)

        local_admin_resoler.add_user("nimda", "Test123!")
        local_admin_resoler.add_user("root@adomain", "Test123!")
        local_admin_resoler.add_user("admin", "Test123!")


@pytest.fixture
def create_common_realms(scoped_authclient: Callable) -> None:
    """
    create a set of three realms - if they do not already exist

    def_realm -> def_resolver (Default resolver)
    dom_realm -> dom_resolver
    mixed_realm -> def_resolver and dom_resolver

    Args:
        adminclient (FlaskClient):
            the client which should be used for the request

    """

    common_realms = {
        "def_realm": ["useridresolver.PasswdIdResolver.IdResolver.def_resolver"],
        "dom_realm": ["useridresolver.PasswdIdResolver.IdResolver.dom_resolver"],
        "mixed_realm": [
            "useridresolver.PasswdIdResolver.IdResolver.def_resolver",
            "useridresolver.PasswdIdResolver.IdResolver.dom_resolver",
        ],
    }

    with scoped_authclient(verify_jwt=False, username="admin") as client:
        response = client.post("/system/getRealms", data={})
        existing_realms = response.json["result"]["value"]

        for realm, resolver_definition in common_realms.items():
            # create the realm if it does not already exist

            if realm.lower() not in existing_realms:
                response = _create_realm(
                    realm=realm,
                    resolvers=resolver_definition,
                    adminclient=client,
                )

                assert response.json["result"]["status"] is True
                assert response.json["result"]["value"] is True

        params = {"realm": "def_realm"}
        response = client.post("/system/setDefaultRealm", data=params)

        assert response.json["result"]["status"] is True
        assert response.json["result"]["value"] is True

        response = client.post("/system/getRealms", data={})

        assert response.json["result"]["status"] is True
        realms = response.json["result"]["value"]

        lookup_realm = {"def_realm", "dom_realm", "mixed_realm"}
        assert lookup_realm == set(realms).intersection(lookup_realm)
        assert "def_realm" in realms
        assert "default" in realms["def_realm"]
        assert realms["def_realm"]["default"]

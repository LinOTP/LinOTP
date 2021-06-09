# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""
Pytest fixtures for linotp tests
"""

# pylint: disable=redefined-outer-name

from linotp import app as app_py
import flask
import os
from linotp.cli import Echo
import pytest
import tempfile
from unittest import mock

from linotp.app import create_app, init_logging
from linotp.flap import set_config, tmpl_context as c
from linotp.cli.init_cmd import create_secret_key, create_audit_keys
from linotp.model import db, init_db_tables
from . import TestController
from flask.testing import FlaskClient


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

        base_app_config = dict(
            ENV="testing",  # doesn't make a huge difference for us
            TESTING=True,
            DATABASE_URI=sqlalchemy_uri,
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            ROOT_DIR=tmp_path,
            CACHE_DIR=tmp_path / "cache",
            DATA_DIR=tmp_path / "data",
            LOGFILE_DIR=tmp_path / "logs",
            AUDIT_PUBLIC_KEY_FILE=key_directory / "audit-public.pem",
            AUDIT_PRIVATE_KEY_FILE=key_directory / "audit-private.pem",
            SECRET_FILE=key_directory / "encKey",
            LOGGING_LEVEL="DEBUG",
            LOGGING_CONSOLE_LEVEL="DEBUG",
        )

        config = request.node.get_closest_marker("app_config")
        if config is not None:
            base_app_config.update(config.args[0])

        os.environ["LINOTP_CFG"] = ""

        # Pre-generate the important directories
        for key in ("CACHE_DIR", "DATA_DIR", "LOGFILE_DIR"):
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
        set_config()

        yield base_app


@pytest.fixture
def adminclient(app, client):
    """
    A client that provides authorisation headers

    Use this client if you need to make a request
    that requires a session. This is the
    equivalent of using TestClient's make_authenticated_request
    """

    # if "session" not in params:
    #     params["session"] = self.session
    # if "admin_session" not in cookies:
    #     cookies["admin_session"] = self.session
    # if "Authorization" not in headers:
    #     if auth_type == "Basic":
    #         headers["Authorization"] = TestController.get_http_basic_header(
    #             username=auth_user
    #         )
    #     else:
    #         headers[
    #             "Authorization"
    #         ] = TestController.get_http_digest_header(username=auth_user)

    class AuthClient(FlaskClient):
        # def __init__(self, *args, **kwargs):
        #     super(AuthClient,self).__init__( *args, **kwargs)

        def open(self, *args, **kwargs):
            """
            Add authorization headers & cookies
            """
            session = "justatest"
            if "json" in kwargs:
                # Add session to JSON body
                kwargs["json"]["session"] = session
            else:
                # Add session to query_string parameter
                params = kwargs.setdefault("query_string", {})
                params["session"] = session

            headers = kwargs.setdefault("headers", {})
            headers["Authorization"] = TestController.get_http_digest_header(
                username="admin"
            )

            self.set_cookie("local", "admin_session", session)

            return super(AuthClient, self).open(*args, **kwargs)

    app.test_client_class = AuthClient
    client = app.test_client()

    return client


@pytest.fixture
def hsm_obj(app):
    """
    A fixture that initialises the HSM object

    The hsm object is returned
    """
    app.preprocess_request()

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
        assert response.json["result"]["status"] == True

        getResponse = adminclient.get("system/getPolicy", json=params)
        assert (
            getResponse.json["result"]["value"]["autosms"]["action"]
            == params["action"]
        )

    return _setPolicy

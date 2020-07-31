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

import flask
import os
import pytest
import tempfile

from linotp.app import create_app
from linotp.flap import set_config, tmpl_context as c
from linotp.model import meta
from . import TestController
from flask.testing import FlaskClient


def pytest_configure(config):
    add_marks = [
        "nightly: mark test to run only nightly",
        "exclude_sqlite: mark test to always skip with sqlite database",
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
        default=os.environ.get(
            'LINOTP_DATABASE_URL', "sqlite:///{}"),
        help=("sqlalchemy database URI to allow tests to run "
              "against a particular database")
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
    return uri


@pytest.fixture
def base_app(tmpdir, request, sqlalchemy_uri, key_directory):
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

        if sqlalchemy_uri == 'sqlite:///{}':
            db_fd, db_path = tempfile.mkstemp()
            sqlalchemy_uri = sqlalchemy_uri.format(db_path)

        # ------------------------------------------------------------------ --

        # Skip test if incompatible with sqlite

        if sqlalchemy_uri.startswith("sqlite:"):

            if request.node.get_closest_marker('exclude_sqlite'):
                pytest.skip("non sqlite database required for test")

        # ------------------------------------------------------------------ --

        # create the app with common test config

        base_app_config = dict(
            TESTING=True,
            SQLALCHEMY_DATABASE_URI=sqlalchemy_uri,
            ROOT_DIR=tmpdir,
            AUDIT_PUBLIC_KEY_FILE=key_directory / "audit-public.pem",
            AUDIT_PRIVATE_KEY_FILE=key_directory / "audit-private.pem",
            SECRET_FILE=key_directory / "encKey",
        )
        os.environ["LINOTP_CFG"] = ""

        app = create_app('testing', base_app_config)

        yield app

    finally:

        # ------------------------------------------------------------------ --

        # in case of sqlite tempfile fallback, we have to wipe the dishes here

        if db_fd:
            os.close(db_fd)

        if db_path:
            os.unlink(db_path)


from linotp import app as app_py

@pytest.fixture
def app(base_app, monkeypatch):
    """
    Provide an app and configured application context
    """
    # Disable request time logging
    monkeypatch.setattr(app_py, 'log_request_timedelta', lambda self: None)

    with base_app.app_context():
        set_config()

        yield base_app

        meta.Session.remove()

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
            session = 'justatest'
            if 'json' in kwargs:
                # Add session to JSON body
                kwargs['json']['session']=session
            else:
                # Add session to query_string parameter
                params = kwargs.setdefault('query_string', {})
                params['session'] = session

            headers = kwargs.setdefault('headers', {})
            headers["Authorization"] = TestController.get_http_digest_header(username='admin')

            self.set_cookie('local', "admin_session", session)

            return super(AuthClient,self).open( *args, **kwargs)

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

    return c['hsm']['obj']

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
            getResponse.json["result"]["value"]["autosms"]["action"] == params["action"]
        )

    return _setPolicy

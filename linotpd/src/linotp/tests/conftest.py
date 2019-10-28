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
from linotp.flap import set_config
from linotp.config.environment import load_environment
from linotp.model import meta
from . import TestController
from flask.testing import FlaskClient


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "nightly: mark test to run only nightly",
    )


@pytest.fixture
def base_app():
    """
    App instance without context

    Creates and returns a bare app. If you wish
    an app with an initialised application context,
    use the `app` fixture instead
    """

    # create a temporary file to isolate the database for each test
    db_fd, db_path = tempfile.mkstemp()

    # create the app with common test config
    app = create_app(
        'testing',
        {
            'TESTING': True,
            'SQLALCHEMY_DATABASE_URI': "sqlite:///{}".format(db_path),
        }
    )

    yield app

    # close and remove the temporary database
    os.close(db_fd)
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

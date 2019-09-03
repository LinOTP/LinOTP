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

@pytest.fixture
def app(base_app):
    """
    Provide an app and configured application context
    """
    with base_app.app_context():
        set_config()
        load_environment(flask.g, base_app.config)
        yield base_app
        meta.Session.remove()

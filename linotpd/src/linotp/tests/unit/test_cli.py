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

# pylint: disable=redefined-outer-name

"""
Command line tests
"""
import pytest
from sqlalchemy import create_engine

from linotp.app import LinOTPApp, init_db_command, setup_db
from linotp.defaults import set_defaults
from linotp.flap import set_config
from linotp.model import meta, Config


@pytest.fixture
def sqllitedb_url(tmpdir):
    """
    Return the URL for a sqlite database file

    This is created in the temporary directory tmpdir
    which will be removed afterwards
    """
    dbfile = tmpdir / 'testdb'
    return f'sqlite:///{dbfile}'


@pytest.fixture
def app(sqllitedb_url):
    """
    A minimal app for testing

    The app is configured with an unitialised database and Testing mode
    """
    app = LinOTPApp()
    config = {
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': sqllitedb_url,
    }
    app.config.update(config)
    return app


@pytest.fixture
def runner(app):
    """
    Return a test runner instance which can be used to run commands against
    """
    return app.test_cli_runner()


@pytest.fixture
def engine(sqllitedb_url):
    """
    Return an SQL Alchemy engine instance which can be used to
    test the app database
    """
    return create_engine(sqllitedb_url)


def test_init_db_creates_tables(runner, engine):
    # GIVEN an empty database
    assert 'Config' not in engine.table_names()

    # WHEN I call init-db without additional arguments
    result = runner.invoke(init_db_command)
    assert result.exit_code == 0, (str(result), result.output)

    # THEN the tables are created
    assert 'Creating database' in result.output
    assert 'Config' in engine.table_names()


@pytest.fixture
def db_with_config(app):
    """
    Set up the database with default config records
    """
    with app.app_context():
        setup_db(app)
        set_config()
        set_defaults(app)

    assert meta.Session.query(Config).count() > 0
    meta.Session.remove()


@pytest.mark.usefixtures('db_with_config')
@pytest.mark.parametrize('erase', (True, False))
def test_clear_db(runner, erase):
    if erase:
        args = '--erase-all-data --yes'
    else:
        args = None

    # GIVEN a database with records
    # WHEN I invoke init-db
    result = runner.invoke(init_db_command, args=args)
    assert result.exit_code == 0

    if erase:
        assert 'Recreating database' in result.output
    else:
        assert 'Creating database' in result.output

    # Then the database contains the base set of config entries

    rec_count = meta.Session.query(Config).count()
    assert rec_count > 0

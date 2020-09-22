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

import json
import os
from mock import patch
import flask
import pytest
from sqlalchemy.exc import OperationalError

from linotp.flap import config, HTTPUnauthorized
from linotp.model import db, Config, LoggingConfig

@pytest.mark.usefixtures("app")
class TestMaintenance(object):

    @patch('linotp.model.db.session')
    def test_check_status_ok(self, mock_session, client):
        """
        Test that 'check_status' returns the number of config entries
        """
        entries = 1

        mock_session.query.return_value.count.return_value = entries

        response = client.get('/maintenance/check_status')

        assert response.json['detail']['config']['entries'] == entries

    @patch('linotp.model.db.session')
    def test_000_check_status_error(self, mock_session, client):
        """
        Test that 'check_status' returns an error status code
        """
        op_error = OperationalError(statement="Error",
                                    params={},
                                    orig="Error")

        mock_session.query.side_effect = op_error

        response = client.get('/maintenance/check_status')

        assert response.status_code == 500

        return

    def test_set_loglevel(self, app, client):
        name = 'linotp.lib.user'
        config_entry = LoggingConfig.query.get(name)
        assert not config_entry

        params = dict(
            loggerName=name,
            level=10,
        )
        client.post('/maintenance/setLogLevel', json=params)

        config_entry = LoggingConfig.query.get(name)
        assert config_entry.level == 10


class TestMaintCertificateHandling(object):

    maint = None

    @pytest.fixture(autouse=True)
    def controller(self, app):
        self.app = app
        self.maint = app.blueprints['maintenance']

    def test_certificate_error(self):
        """
        Test that a request raises an exception if no certificate is available
        """

        config['MAINTENANCE_VERIFY_CLIENT_ENV_VAR'] = 'TEST_VAR_NOTSET'

        with pytest.raises(HTTPUnauthorized) as err:
            self.maint.__before__(action='check_status')

        assert err.value.code == 401

    def test_certificate_ok(self):
        """
        Test that a request raises an exception if no certificate is available
        """

        config['MAINTENANCE_VERIFY_CLIENT_ENV_VAR'] = 'TEST_VAR'

        with self.app.test_request_context('/matintenance/check_status'):
            flask.request.environ['TEST_VAR'] = 'OK'
            ret = self.maint.__before__(action='check_status')
            assert ret is None

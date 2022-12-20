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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

from mock import patch
import json
import unittest
from sqlalchemy.exc import OperationalError
from webob.exc import HTTPUnauthorized
from webob.exc import HTTPInternalServerError

from linotp.controllers.maintenance import MaintenanceController


class TestMaintenance(unittest.TestCase):

    @patch('linotp.controllers.system.BaseController.__init__',
           return_value=None)
    def setUp(self, mock_base):
        unittest.TestCase.setUp(self)
        self.maint = MaintenanceController()

    @patch('linotp.controllers.system.sendError')
    @patch('linotp.controllers.system.sendResult')
    @patch('linotp.controllers.maintenance.Session')
    @patch('linotp.controllers.maintenance.response')
    def test_check_status_ok(self, mock_response, mock_session,
                             mock_sendresult, mock_senderror):
        """
        Test that 'check_status' returns the number of config entries
        """
        entries = 1

        mock_session.query.return_value.count.return_value = entries
        mock_senderror.side_effect = lambda response, exx: exx
        mock_sendresult.side_effect = lambda response, obj, *args: obj

        ret = self.maint.check_status()

        ret = json.loads(ret)
        self.assertEqual(ret['detail']['config']['entries'], entries)

    @patch('linotp.controllers.system.sendResult')
    @patch('linotp.controllers.system.sendError')
    @patch('linotp.controllers.maintenance.Session')
    @patch('linotp.controllers.maintenance.response')
    def test_000_check_status_error(
            self, mock_response, mock_session, mock_senderror,
            mock_sendresult):
        """
        Test that 'check_status' returns an error status code
        """
        op_error = OperationalError(statement="Error",
                                    params={},
                                    orig="Error")

        mock_session.query.side_effect = op_error

        mock_senderror.side_effect = lambda response, exx: exx
        mock_sendresult.side_effect = lambda response, obj, *args: obj

        with self.assertRaises(HTTPInternalServerError) as err:
            self.maint.check_status()

        self.assertTrue(err.exception.status_code == 500)


        return

    @patch('linotp.controllers.maintenance.request_context')
    @patch('linotp.controllers.maintenance.request')
    def test_before_error(self, mock_request, mock_context):
        """
        Test that '__before' raises an exception if no certificate is available
        """

        mock_request.environ.get.return_value = None
        mock_context.__getitem__.return_value.get.return_value = True

        with self.assertRaises(HTTPUnauthorized) as err:
            self.maint.__before__(action='check_status')

        self.assertTrue(err.exception.status_code == 401)

        return

if __name__ == "__main__":
    unittest.main()

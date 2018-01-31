# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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
import copy
import unittest

from mock import mock

from linotp.controllers.admin import AdminController


class TestAdminController(unittest.TestCase):

    token = {
            'LinOtp.TokenId': 201,
            'LinOtp.TokenInfo':
                u'{\n"hashlib": "sha1", \n"timeShift": -10.0, \n"timeWindow": 180, \n"validity_period_end": "23/12/23 23:23", \n"validity_period_start": "01/01/01 01:01", \n"timeStep": "30"\n}',
            'LinOtp.OtpLen': 6,
            'LinOtp.TokenType': u'TOTP',
            'LinOtp.TokenSerialnumber': u'F722362',
            'LinOtp.CountWindow': 10,
            'User.username': u'passthru_user1',
            'LinOtp.TokenDesc': u'TestToken1',
        }

    token2 = {
            'LinOtp.TokenId': 201,
            'LinOtp.TokenInfo': '',
            'LinOtp.OtpLen': 6,
            'LinOtp.TokenType': u'TOTP',
            'LinOtp.TokenSerialnumber': u'F722362',
            'LinOtp.CountWindow': 10,
            'User.username': u'passthru_user1',
            'LinOtp.TokenDesc': u'TestToken1',
        }


    expected_subset = {'validity_period_start': '2001-01-01T01:01:00',
                       'validity_period_end': '2023-12-23T23:23:00'}

    def test_parse_tokeninfo(self):
        """"
        check if admin.parse_tokeninfo works
        """
        tok = copy.deepcopy(self.token)

        AdminController.parse_tokeninfo(tok)

        self.assertIsInstance(tok.get('LinOtp.TokenInfo'),
                              dict,
                              'TokenInfo is not of type dict!')
        self.assertDictContainsSubset(self.expected_subset,
                                      tok.get('LinOtp.TokenInfo'),
                                      tok.get('LinOtp.TokenInfo'))

    @mock.patch('linotp.controllers.admin.TokenIterator')
    @mock.patch('linotp.controllers.admin.c')
    @mock.patch('linotp.controllers.admin.checkPolicyPre')
    @mock.patch('linotp.controllers.admin.Session')
    @mock.patch('linotp.controllers.admin.response')
    @mock.patch('linotp.controllers.admin.request')
    @mock.patch('linotp.controllers.system.BaseController.__init__', return_value=None)
    def check_token(self, mock_base, mock_request, mock_response, mock_session,
                    mock_check_policy_pre, mock_c, mock_TokenIterator,
                    with_json):
        """
        call admin/show with/without argument tokeninfo_format
        and return if parse_tokeninfo has been called
        """
        mock_request.params = {
            'tokeninfo_format': with_json,
        }
        mock_check_policy_pre.return_value = {'active': False,
                                              'admin': 'unittest'}
        mock_c.audit = {}
        tok = copy.deepcopy(self.token)
        mock_TokenIterator.return_value = [tok]

        admin = AdminController()
        admin.show()

    @mock.patch('linotp.controllers.admin.AdminController.parse_tokeninfo')
    def test_with_tokeninfo_format(self, mock_parse_tokeninfo):
        self.check_token(with_json='json')
        mock_parse_tokeninfo.assert_called()

    @mock.patch('linotp.controllers.admin.AdminController.parse_tokeninfo')
    def test_without_tokeninfo_format(self,  mock_parse_tokeninfo,):
        self.check_token(with_json='')
        mock_parse_tokeninfo.assert_not_called()

    def test_parse_empty_tokeninfo(self):
        """
        verify that token info is valid even if it is initially empty
        """
        tok = copy.deepcopy(self.token2)
        AdminController.parse_tokeninfo(tok)

        self.assertTrue(tok['LinOtp.TokenInfo'] == {})

        return

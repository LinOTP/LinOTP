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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#


"""
unit test for the dynamoc mobile number policy of the smstoken
"""


import unittest
from mock import patch

from linotp.tokens.smstoken import SmsTokenClass

dynamic_mobile_policy = [{
    'name': 'sms_dynamic_mobile_number',
    'scope': 'authentication',
    'realm': '*',
    'user': 'passthru_user1',
    'action': 'sms_dynamic_mobile_number',
    'active': 'true',
    'client': ''}]

fake_context = {
    'translate': lambda x: x,
    'Client': '127.0.0.1'}


class FakeUser(object):

    def __init__(self, login, realm):
        self.login = login
        self.realm = realm

class TestSMSToken(unittest.TestCase):
    """
    test class for the SMS Token
    """

    @patch('linotp.tokens.smstoken.context', new=fake_context)
    @patch('linotp.tokens.smstoken.getUserDetail')
    @patch('linotp.tokens.smstoken.getPolicyActionValue')
    @patch('linotp.tokens.smstoken.get_client_policy')
    @patch('linotp.tokens.smstoken.SmsTokenClass._getPhone')
    @patch('linotp.tokens.smstoken.SmsTokenClass.__init__')
    def test_dynamic_mobile_number(
            self,
            mock__init__,
            mock_getPhone,
            mock_get_client_policy,
            mock_getPolicyActionValue,
            mock_getUserDetail):
        """
        test the ability to get the mobile number dynamicaly from the user
        via sms_synamic_mobile_number policy
        """

        # ------------------------------------------------------------------ --

        # test setup with different mobile numbers

        user_mobile = '12345678'
        token_mobile = "987654321"
        mock_getUserDetail.return_value = {'mobile': user_mobile}
        mock_getPhone.return_value = token_mobile

        # ------------------------------------------------------------------ --

        # token setup

        mock__init__.return_value = None
        sms_token = SmsTokenClass()
        fake_user = FakeUser('passthru_user1', 'myrealm')

        # ------------------------------------------------------------------ --

        # test 1: policy exist and matches for user

        mock_getPolicyActionValue.return_value = True
        mock_get_client_policy.return_value = dynamic_mobile_policy


        mobile = sms_token.get_mobile_number(fake_user)

        self.assertTrue(mobile == user_mobile)

        # ------------------------------------------------------------------ --

        # test 2: policy exist but does not matches for user

        mock_getPolicyActionValue.return_value = False
        mock_get_client_policy.return_value = dynamic_mobile_policy

        mobile = sms_token.get_mobile_number(fake_user)

        self.assertTrue(mobile == token_mobile)

        # ------------------------------------------------------------------ --

        # test 3: policy doest exist

        mock_get_client_policy.return_value = None

        mobile = sms_token.get_mobile_number(fake_user)

        self.assertTrue(mobile == token_mobile)

        # ------------------------------------------------------------------ --

        # test 4: no user exists

        mock_get_client_policy.return_value = None

        mobile = sms_token.get_mobile_number(None)

        self.assertTrue(mobile == token_mobile)

        return

# eof #

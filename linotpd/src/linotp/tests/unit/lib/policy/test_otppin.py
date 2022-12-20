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

""" unit test for complex policy comparisons """

import unittest

from mock import patch

from linotp.lib.user import User
from linotp.lib.auth.validate import check_pin

class FakeToken():
    type = 'test'
    
    def checkPin(self, passw, options=None):
        if passw == 'good':
            return True
        else:
            return False

class TestOtppinPolicy(unittest.TestCase):
    """
    unit test for check_pin and otppin policy
    """

    @patch('linotp.lib.auth.validate.get_pin_policies')
    def test_ignore_pin(self, mocked_get_pin_policies):
        """
        test that on otppin policy 3 the pin is ignored
        """

        userObj = User(login='max1', realm='mymixrealm')
        token = FakeToken()

        mocked_get_pin_policies.return_value = [3]

        res = check_pin(token, 'QUATSCH', userObj, options={})
        self.assertTrue(res)

        res = check_pin(token, '', userObj, options={})
        self.assertTrue(res)

        token.type = 'spass'
        res = check_pin(token, 'bad', userObj, options={})
        self.assertFalse(res)

        token.type = 'spass'
        res = check_pin(token, 'good', userObj, options={})
        self.assertTrue(res)

        return

# eof #

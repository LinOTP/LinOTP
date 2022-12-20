# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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

import unittest
from mock import patch

from linotp.tokens.vascotoken import VascoTokenClass

class VascoTokenClassTestCase(unittest.TestCase):

    @patch('linotp.tokens.vascotoken.VascoTokenClass._get_secret_object')
    @patch('linotp.tokens.vascotoken.vasco_otp_check')
    def do_check_otp(self, vasco_retvalue, expected_retvalue, mock_vasco_otpcheck, mock_secobj):
        class testToken(object):
            def setType(self, toktype):
                self.type = toktype

        vasco_token = VascoTokenClass(testToken())
        mock_vasco_otpcheck.return_value = (vasco_retvalue, None)

        ret = vasco_token.checkOtp("123456", None, None)
        self.assertEquals(ret, expected_retvalue, "Expecting return=%s for vasco return=%s")

    def test_check_otp_pass(self):
        self.do_check_otp(0, 0)

    def test_check_otp_fail(self):
        self.do_check_otp(1, -1)

if __name__ == '__main__':
    unittest.main()

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
' verfify that the userservice cookie is rfc6265 time format compliant'

import binascii
import datetime
from linotp.lib.userservice import create_auth_cookie

import unittest
from mock import patch


Secret = '012345678901234567890123456789012'
RFC6265_TIMEFORMAT = "%a, %d %b %Y %H:%M:%S GMT"
OLD_TIMEFORMAT = "%Y-%m-%d %H:%M:%S"

class TestCookieActivation(unittest.TestCase):

    @patch('linotp.lib.userservice.get_cookie_secret')
    @patch('linotp.lib.userservice.get_cookie_expiry')
    def test_tz_in_cookies(
            self, mock_get_cookie_expiry, mock_get_cookie_secret):
        """
        verify that the userservice cookie format is rfc6265 compliant
        """

        mock_get_cookie_secret.return_value = binascii.hexlify(Secret)
        mock_get_cookie_expiry.return_value = False

        ret = create_auth_cookie('hans', '127.0.0.1')
        _session, _expiration_dt, expiration_str = ret

        datetime.datetime.strptime(expiration_str, RFC6265_TIMEFORMAT)

        with self.assertRaises(ValueError) as exx:
            datetime.datetime.strptime(expiration_str, OLD_TIMEFORMAT)

        assert 'does not match format' in exx.exception.message

# eof
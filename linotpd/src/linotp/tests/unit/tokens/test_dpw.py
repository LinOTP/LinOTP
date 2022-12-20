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

from linotp.tokens.tagespassworttoken import dpwOtp


class TestDPWToken(unittest.TestCase):
    """
    Unit tests for tagespassword token algorithm
    """

    def test_tagepassword_algorithm(self):

        class mockSecObj(object):
            def getKey(self):
                return '1234567890123456789012345678901234567890'

        with dpwOtp(mockSecObj()) as dpw:
            day_otp = dpw.getOtp()
            res = dpw.checkOtp(anOtpVal=day_otp)

        self.assertTrue(res)

# eof #

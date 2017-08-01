# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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

import unittest

from linotp.lib.util import normalize_activation_code
from linotp.lib.crypto import createActivationCode


class TestOcraTokenActivationCode(unittest.TestCase):
    """
    Unit tests for OCRA activation code to be base32 compliant
    """

    def test_base32_activation_code(self):
        """
        verify that we can handle as well b32 char ambiguity errors
        like '1' instead of 'i' and '0' instead of 'o'
        """

        activationkey = createActivationCode(
                            acode=None, checksum=True).lower()

        a_code = "01" + activationkey[2:-2]
        ch_sum = "OI"

        activationcode = normalize_activation_code(a_code + ch_sum)

        a_code = activationcode[:-2]
        ch_sum = activationcode[-2:]

        self.assertTrue("1" not in a_code)
        self.assertTrue("0" not in a_code)

        self.assertTrue("I" not in ch_sum)
        self.assertTrue("O" not in ch_sum)

        return

    def test_non_base32_activation_code(self):
        """
        verify that we can not handle non b32 characters and non hex digits
        in checksum
        """

        activationkey = createActivationCode(
                            acode=None, checksum=True).lower()

        a_code = activationkey[:-2].replace('o', '0').replace('i', '1')
        ch_sum = activationkey[-2:].replace('0', 'o').replace('1', 'i')

        a_code = u'89ü' + a_code[3:]

        msg = "Not all characters are in base32 charset"

        with self.assertRaisesRegexp(Exception, msg):
            normalize_activation_code(a_code + ch_sum)

        activationkey = createActivationCode(
                            acode=None, checksum=True).lower()

        a_code = activationkey[:-2].replace('o', '0').replace('i', '1')
        ch_sum = activationkey[-2:].replace('0', 'o').replace('1', 'i')

        ch_sum = 'Z' + ch_sum[1:]

        msg = "Not all checksum characters are hex digits"

        with self.assertRaisesRegexp(Exception, msg):
            normalize_activation_code(a_code + ch_sum)

        return

# eof #

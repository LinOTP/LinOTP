# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

import logging

import sys
if sys.version_info < (2, 7):
    try:
        import unittest2 as unittest
    except ImportError as exc:
        print "You need to install unittest2 on Python 2.6. Unittest2 is a "\
              "backport of new unittest features."
        raise exc
else:
    import unittest

from mock import MagicMock, Mock


class U2FTokenClassTestCase(unittest.TestCase):

    """
    This class tests the U2FTokenClass in isolation by mocking out
    all dependencies on other classes. Therefore the tests can be run without
    requiring an installed server.
    """

    def setUp(self):
        from linotp.lib.tokens.u2ftoken import U2FTokenClass
        # Without this logging in the tested class fails
        logging.basicConfig()

        model_token = MagicMock(
            spec=[
                "getInfo",
                "setType",
            ]
        )  # linotp.model.Token
        model_token.getInfo.return_value = u'' + '{\n}'
        self.u2f_token = U2FTokenClass(model_token)
        model_token.setType.assert_called_once_with("u2f")

    def test_verify_counter_decrease_in_overflow_range(self):
        """
        Test decreased counter in overflow range
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 500)
        self.u2f_token.token.LinOtpIsactive = True
        with self.assertRaises(ValueError):
            self.u2f_token._verifyCounterValue((256 ** 4) - 1000)
        self.u2f_token.getFromTokenInfo.assert_called_once_with('counter', None)
        self.assertFalse(self.u2f_token.token.LinOtpIsactive)

    def test_verify_counter_equal_in_overflow_range(self):
        """
        Test equal counter in overflow range
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 500)
        self.u2f_token.token.LinOtpIsactive = True
        with self.assertRaises(ValueError):
            self.u2f_token._verifyCounterValue((256 ** 4) - 500)
        self.u2f_token.getFromTokenInfo.assert_called_once_with('counter', None)
        self.assertFalse(self.u2f_token.token.LinOtpIsactive)

    def test_verify_counter_increase_in_overflow_range(self):
        """
        Test increased counter in the overflow range
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 500)
        self.u2f_token.addToTokenInfo = Mock()
        self.u2f_token.token.LinOtpIsactive = True
        self.u2f_token._verifyCounterValue((256 ** 4) - 400)
        self.u2f_token.getFromTokenInfo.assert_called_once_with('counter', None)
        self.u2f_token.addToTokenInfo.assert_called_once_with('counter', (256 ** 4) - 400)
        self.assertTrue(self.u2f_token.token.LinOtpIsactive)

    def test_verify_counter_overflow_out_of_range1(self):
        """
        Test overflow out of the accepted range
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 500)
        self.u2f_token.token.LinOtpIsactive = True
        with self.assertRaises(ValueError):
            self.u2f_token._verifyCounterValue(1001)
        self.u2f_token.getFromTokenInfo.assert_called_once_with('counter', None)
        self.assertFalse(self.u2f_token.token.LinOtpIsactive)

    def test_verify_counter_overflow_out_of_range2(self):
        """
        Test overflow out of the accepted range #2
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 1001)
        self.u2f_token.token.LinOtpIsactive = True
        with self.assertRaises(ValueError):
            self.u2f_token._verifyCounterValue(0)
        self.u2f_token.getFromTokenInfo.assert_called_once_with('counter', None)
        self.assertFalse(self.u2f_token.token.LinOtpIsactive)

    def test_verify_counter_legal_overflow(self):
        """
        Test legal counter overflow
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 1000)
        self.u2f_token.addToTokenInfo = Mock()
        self.u2f_token.token.LinOtpIsactive = True
        self.u2f_token._verifyCounterValue(1000)
        self.u2f_token.getFromTokenInfo.assert_called_once_with('counter', None)
        self.u2f_token.addToTokenInfo.assert_called_once_with('counter', 1000)
        self.assertTrue(self.u2f_token.token.LinOtpIsactive)

    def test_verify_counter_decreased1(self):
        """
        Test decreased counter
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=500)
        self.u2f_token.token.LinOtpIsactive = True
        with self.assertRaises(ValueError):
            self.u2f_token._verifyCounterValue(499)
        self.u2f_token.getFromTokenInfo.assert_called_once_with('counter', None)
        self.assertFalse(self.u2f_token.token.LinOtpIsactive)

    def test_verify_counter_decreased2(self):
        """
        Test decreased counter #2
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=500)
        self.u2f_token.token.LinOtpIsactive = True
        with self.assertRaises(ValueError):
            self.u2f_token._verifyCounterValue(0)
        self.u2f_token.getFromTokenInfo.assert_called_once_with('counter', None)
        self.assertFalse(self.u2f_token.token.LinOtpIsactive)

    def test_verify_counter_equal(self):
        """
        Test equal counter
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=500)
        self.u2f_token.token.LinOtpIsactive = True
        with self.assertRaises(ValueError):
            self.u2f_token._verifyCounterValue(500)
        self.u2f_token.getFromTokenInfo.assert_called_once_with('counter', None)
        self.assertFalse(self.u2f_token.token.LinOtpIsactive)

    def test_verify_counter_increased1(self):
        """
        Test legal increased counter
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=500)
        self.u2f_token.addToTokenInfo = Mock()
        self.u2f_token.token.LinOtpIsactive = True
        self.u2f_token._verifyCounterValue(501)
        self.u2f_token.getFromTokenInfo.assert_called_once_with('counter', None)
        self.u2f_token.addToTokenInfo.assert_called_once_with('counter', 501)
        self.assertTrue(self.u2f_token.token.LinOtpIsactive)

    def test_verify_counter_increased2(self):
        """
        Test legal increased counter #2
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=500)
        self.u2f_token.addToTokenInfo = Mock()
        self.u2f_token.token.LinOtpIsactive = True
        self.u2f_token._verifyCounterValue(5000)
        self.u2f_token.getFromTokenInfo.assert_called_once_with('counter', None)
        self.u2f_token.addToTokenInfo.assert_called_once_with('counter', 5000)
        self.assertTrue(self.u2f_token.token.LinOtpIsactive)


if __name__ == '__main__':
    unittest.main()

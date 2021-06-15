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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

import logging

import sys
import unittest

from mock import MagicMock, Mock, patch
import pytest


class U2FTokenClassTestCase(unittest.TestCase):

    """
    This class tests the U2FTokenClass in isolation by mocking out
    all dependencies on other classes. Therefore the tests can be run without
    requiring an installed server.
    """

    def setUp(self):
        from linotp.tokens.u2ftoken.u2ftoken import U2FTokenClass

        # Without this logging in the tested class fails
        logging.basicConfig()

        model_token = MagicMock(
            spec=[
                "getInfo",
                "setType",
            ]
        )  # linotp.model.Token
        model_token.getInfo.return_value = "" + "{\n}"
        self.u2f_token = U2FTokenClass(model_token)
        model_token.setType.assert_called_once_with("u2f")

    #
    # Test the _verifyCounterValue function
    #

    def test_verify_counter_decrease_in_overflow_range(self):
        """
        Test decreased counter in overflow range
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 500)
        self.u2f_token.token.LinOtpIsactive = True
        with pytest.raises(ValueError):
            self.u2f_token._verifyCounterValue((256 ** 4) - 1000)
        self.u2f_token.getFromTokenInfo.assert_called_once_with(
            "counter", None
        )
        assert not self.u2f_token.token.LinOtpIsactive

    def test_verify_counter_equal_in_overflow_range(self):
        """
        Test equal counter in overflow range
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 500)
        self.u2f_token.token.LinOtpIsactive = True
        with pytest.raises(ValueError):
            self.u2f_token._verifyCounterValue((256 ** 4) - 500)
        self.u2f_token.getFromTokenInfo.assert_called_once_with(
            "counter", None
        )
        assert not self.u2f_token.token.LinOtpIsactive

    def test_verify_counter_increase_in_overflow_range(self):
        """
        Test increased counter in the overflow range
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 500)
        self.u2f_token.addToTokenInfo = Mock()
        self.u2f_token.token.LinOtpIsactive = True
        self.u2f_token._verifyCounterValue((256 ** 4) - 400)
        self.u2f_token.getFromTokenInfo.assert_called_once_with(
            "counter", None
        )
        self.u2f_token.addToTokenInfo.assert_called_once_with(
            "counter", (256 ** 4) - 400
        )
        assert self.u2f_token.token.LinOtpIsactive

    def test_verify_counter_overflow_out_of_range1(self):
        """
        Test overflow out of the accepted range
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 500)
        self.u2f_token.token.LinOtpIsactive = True
        with pytest.raises(ValueError):
            self.u2f_token._verifyCounterValue(1001)
        self.u2f_token.getFromTokenInfo.assert_called_once_with(
            "counter", None
        )
        assert not self.u2f_token.token.LinOtpIsactive

    def test_verify_counter_overflow_out_of_range2(self):
        """
        Test overflow out of the accepted range #2
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 1001)
        self.u2f_token.token.LinOtpIsactive = True
        with pytest.raises(ValueError):
            self.u2f_token._verifyCounterValue(0)
        self.u2f_token.getFromTokenInfo.assert_called_once_with(
            "counter", None
        )
        assert not self.u2f_token.token.LinOtpIsactive

    def test_verify_counter_legal_overflow(self):
        """
        Test legal counter overflow
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=(256 ** 4) - 1000)
        self.u2f_token.addToTokenInfo = Mock()
        self.u2f_token.token.LinOtpIsactive = True
        self.u2f_token._verifyCounterValue(1000)
        self.u2f_token.getFromTokenInfo.assert_called_once_with(
            "counter", None
        )
        self.u2f_token.addToTokenInfo.assert_called_once_with("counter", 1000)
        assert self.u2f_token.token.LinOtpIsactive

    def test_verify_counter_decreased1(self):
        """
        Test decreased counter
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=500)
        self.u2f_token.token.LinOtpIsactive = True
        with pytest.raises(ValueError):
            self.u2f_token._verifyCounterValue(499)
        self.u2f_token.getFromTokenInfo.assert_called_once_with(
            "counter", None
        )
        assert not self.u2f_token.token.LinOtpIsactive

    def test_verify_counter_decreased2(self):
        """
        Test decreased counter #2
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=500)
        self.u2f_token.token.LinOtpIsactive = True
        with pytest.raises(ValueError):
            self.u2f_token._verifyCounterValue(0)
        self.u2f_token.getFromTokenInfo.assert_called_once_with(
            "counter", None
        )
        assert not self.u2f_token.token.LinOtpIsactive

    def test_verify_counter_equal(self):
        """
        Test equal counter
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=500)
        self.u2f_token.token.LinOtpIsactive = True
        with pytest.raises(ValueError):
            self.u2f_token._verifyCounterValue(500)
        self.u2f_token.getFromTokenInfo.assert_called_once_with(
            "counter", None
        )
        assert not self.u2f_token.token.LinOtpIsactive

    def test_verify_counter_increased1(self):
        """
        Test legal increased counter
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=500)
        self.u2f_token.addToTokenInfo = Mock()
        self.u2f_token.token.LinOtpIsactive = True
        self.u2f_token._verifyCounterValue(501)
        self.u2f_token.getFromTokenInfo.assert_called_once_with(
            "counter", None
        )
        self.u2f_token.addToTokenInfo.assert_called_once_with("counter", 501)
        assert self.u2f_token.token.LinOtpIsactive

    def test_verify_counter_increased2(self):
        """
        Test legal increased counter #2
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=500)
        self.u2f_token.addToTokenInfo = Mock()
        self.u2f_token.token.LinOtpIsactive = True
        self.u2f_token._verifyCounterValue(5000)
        self.u2f_token.getFromTokenInfo.assert_called_once_with(
            "counter", None
        )
        self.u2f_token.addToTokenInfo.assert_called_once_with("counter", 5000)
        assert self.u2f_token.token.LinOtpIsactive

    #
    # Test the update function
    #

    def test_update_requested_phase_unknown_current_phase_None(self):
        """
        Test update function with an unknown requested_phase parameter and current_phase None
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=None)
        param = dict(description=None, phase="some_unknown_phase")
        with pytest.raises(Exception):
            self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)

    def test_update_requested_phase_unknown_current_phase_registration(self):
        """
        Test update function with an unknown requested_phase parameter and current_phase 'registration'
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value="registration")
        param = dict(description=None, phase="some_unknown_phase")
        with pytest.raises(Exception):
            self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)

    def test_update_requested_phase_unknown_current_phase_authentication(self):
        """
        Test update function with an unknown requested_phase parameter and current_phase 'authentication'
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value="authentication")
        param = dict(description=None, phase="some_unknown_phase")
        with pytest.raises(Exception):
            self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)

    def test_update_requested_phase_registration1_current_phase_None(self):
        """
        Test update function with requested_phase 'registration1' and current_phase None
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=None)
        self.u2f_token.addToTokenInfo = Mock()
        param = dict(description=None, phase="registration1")
        self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)
        self.u2f_token.addToTokenInfo.assert_called_once_with(
            "phase", "registration"
        )
        assert not self.u2f_token.token.LinOtpIsactive

    def test_update_requested_phase_registration1_current_phase_registration(
        self,
    ):
        """
        Test update function with requested_phase 'registration1' and current_phase 'registration'
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value="registration")
        param = dict(description=None, phase="registration1")
        with pytest.raises(Exception):
            self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)

    def test_update_requested_phase_registration1_current_phase_authentication(
        self,
    ):
        """
        Test update function with requested_phase 'registration1' and current_phase 'authentication'
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value="authentication")
        param = dict(description=None, phase="registration1")
        with pytest.raises(Exception):
            self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)

    def test_update_requested_phase_registration2_current_phase_None(self):
        """
        Test update function with requested_phase 'registration2' and current_phase None
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=None)
        param = dict(description=None, phase="registration2")
        with pytest.raises(Exception):
            self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)

    def test_update_requested_phase_registration2_current_phase_registration_correct_pin(
        self,
    ):
        """
        Test update function with requested_phase 'registration2' and current_phase registration
        and a correct pin
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value="registration")
        patcher = patch("linotp.tokens.u2ftoken.u2ftoken.check_pin", spec=True)
        check_pin_mock = patcher.start()
        check_pin_mock.return_value = True
        param = dict(description=None, phase="registration2", pin="test!pin")
        self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)
        check_pin_mock.assert_called_once_with(self.u2f_token, "test!pin")
        patcher.stop()

    def test_update_requested_phase_registration2_current_phase_registration_wrong_pin(
        self,
    ):
        """
        Test update function with requested_phase 'registration2' and current_phase registration
        and a wrong pin
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value="registration")
        patcher = patch("linotp.tokens.u2ftoken.u2ftoken.check_pin", spec=True)
        check_pin_mock = patcher.start()
        check_pin_mock.return_value = False
        param = dict(description=None, phase="registration2", pin="test!pin")
        with pytest.raises(ValueError):
            self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)
        check_pin_mock.assert_called_once_with(self.u2f_token, "test!pin")
        patcher.stop()

    def test_update_requested_phase_registration2_current_phase_authentication(
        self,
    ):
        """
        Test update function with requested_phase 'registration2' and current_phase 'authentication'
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value="authentication")
        param = dict(description=None, phase="registration2")
        with pytest.raises(Exception):
            self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)

    def test_update_requested_phase_None_current_phase_None(self):
        """
        Test update function with requested_phase None and current_phase None
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value=None)
        param = dict(description=None, phase=None)
        with pytest.raises(Exception):
            self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)

    def test_update_requested_phase_None_current_phase_registration(self):
        """
        Test update function with an requested_phase None and current_phase 'registration'
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value="registration")
        param = dict(description=None, phase=None)
        with pytest.raises(Exception):
            self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)

    def test_update_requested_phase_None_current_phase_authentication(self):
        """
        Test update function with requested_phase None and current_phase 'authentication'
        """
        self.u2f_token.getFromTokenInfo = Mock(return_value="authentication")
        param = dict(description=None, phase=None)
        with pytest.raises(Exception):
            self.u2f_token.update(param)
        self.u2f_token.getFromTokenInfo.assert_called_once_with("phase", None)


if __name__ == "__main__":
    unittest.main()

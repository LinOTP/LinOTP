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

import integration_data as data
import pytest

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.auth_ui import AuthUi


class TestAuth:
    """
    TestCase class that tests the auth/index forms
    """

    @pytest.fixture(autouse=True)
    def setUp(self, testcase):
        self.testcase = testcase
        self.realm_name = "se_test_auth"
        testcase.reset_resolvers_and_realms(
            data.sepasswd_resolver, self.realm_name
        )
        self.testcase.manage_ui.token_view.delete_all_tokens()
        self.manage_ui = self.testcase.manage_ui

    def test_auth_index(self):
        """
        Test /auth/index form by authenticating susi with a HMAC/HOTP Token
        """

        # Enroll HOTP token
        # Seed and OTP values: https://tools.ietf.org/html/rfc4226#appendix-D
        username = "susi"
        self.manage_ui.user_view.select_user(username)
        pin = "myauthpin"
        self.manage_ui.token_enroll.create_hotp_token(
            pin=pin, hmac_key="3132333435363738393031323334353637383930"
        )

        otp_list = ["755224", "287082", "359152", "969429", "338314", "254676"]

        auth = AuthUi(self.testcase)
        user = username + "@" + self.realm_name

        for otp in otp_list:
            assert auth.auth_using_index(user, pin, otp) == auth.AUTH_SUCCESS

        # wrong otp
        assert auth.auth_using_index(user, "bla!") == auth.AUTH_FAIL

        # test auth/index3
        otp_list = ["287922", "162583", "399871", "520489"]

        for otp in otp_list:
            assert auth.auth_using_index3(user, pin, otp) == auth.AUTH_SUCCESS

        # wrong otp
        assert (
            auth.auth_using_index(user, pin, "some invalid otp")
            == auth.AUTH_FAIL
        )

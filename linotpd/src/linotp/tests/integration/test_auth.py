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


import time

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.auth_ui import AuthUi
from linotp_selenium_helper.hotp_token import HotpToken
from linotp_selenium_helper.manage_ui import ManageUi
from linotp_selenium_helper.user_view import UserView
from linotp_selenium_helper.token_view import TokenView

import integration_data as data


class TestAuth(TestCase):
    """
    TestCase class that tests the auth/index forms
    """

    def setUp(self):
        TestCase.setUp(self)
        self.realm_name = "se_test_auth"
        self.reset_resolvers_and_realms(
            data.sepasswd_resolver, self.realm_name)
        self.manage = ManageUi(self)
        self.manage.token_view.delete_all_tokens()

    def test_auth_index(self):
        """
        Test /auth/index form by authenticating susi with a HMAC/HOTP Token
        """

        # Enroll HOTP token
        # Seed and OTP values: https://tools.ietf.org/html/rfc4226#appendix-D
        user_view = UserView(self.manage, self.realm_name)
        username = "susi"
        user_view.select_user(username)
        pin = "myauthpin"
        HotpToken(self.driver,
                  self.base_url,
                  pin=pin,
                  hmac_key="3132333435363738393031323334353637383930")

        otp_list = ["755224",
                    "287082",
                    "359152",
                    "969429",
                    "338314",
                    "254676"]

        auth = AuthUi(self)
        user = username + '@' + self.realm_name

        for otp in otp_list:
            assert auth.auth_using_index(user, pin, otp) == auth.AUTH_SUCCESS

        # wrong otp
        assert auth.auth_using_index(user, 'bla!') == auth.AUTH_FAIL

        # test auth/index3
        otp_list = ["287922",
                    "162583",
                    "399871",
                    "520489"]

        for otp in otp_list:
            assert auth.auth_using_index3(user, pin, otp) == auth.AUTH_SUCCESS

        # wrong otp
        assert auth.auth_using_index(
            user, pin, 'some invalid otp') == auth.AUTH_FAIL

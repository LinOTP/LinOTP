# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
Test token enrollment
"""

from linotp.tests import TestController

NOT_ALLOWED_ERROR = (
    "The policy settings do not allow you to issue this request!"
)


class TestUserserviceEnrollment(TestController):
    """
    Test the token initialization by end users via the userservice.
    """

    def setUp(self):
        TestController.setUp(self)
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        TestController.tearDown(self)

    def test_hotp_with_webprovisiongoogle(self):
        """
        Ensure that the webprovisionGOOGLE policy allows enrollment of a HOTP
        token via the 'enroll' endpoint, but not another token type.
        """
        params = {
            "name": "webprovisionHOTP",
            "scope": "selfservice",
            "action": "webprovisionGOOGLE",
            "user": "*",
            "realm": "*",
            "active": True,
        }

        response = self.make_system_request("setPolicy", params)
        assert "false" not in response, response

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
        }

        response = self.make_userselfservice_request(
            "enroll", params={"type": "hmac"}, auth_user=auth_user
        )
        assert ' "value": true' in response, response

        response = self.make_userselfservice_request(
            "enroll", params={"type": "totp"}, auth_user=auth_user
        )
        assert NOT_ALLOWED_ERROR in response, response

    def test_totp_with_webprovisiongoogletime(self):
        """
        Ensure that the webprovisionGOOGLEtime policy allows enrollment of a
        TOTP token via the 'enroll' endpoint, but not another token type.
        """
        params = {
            "name": "webprovisionTOTP",
            "scope": "selfservice",
            "action": "webprovisionGOOGLEtime",
            "user": "*",
            "realm": "*",
            "active": True,
        }

        response = self.make_system_request("setPolicy", params)
        assert "false" not in response, response

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
        }

        response = self.make_userselfservice_request(
            "enroll", params={"type": "totp"}, auth_user=auth_user
        )
        assert ' "value": true' in response, response

        response = self.make_userselfservice_request(
            "enroll", params={"type": "hmac"}, auth_user=auth_user
        )
        assert NOT_ALLOWED_ERROR in response, response

    def test_correct_pin_on_enrollment(self):
        """
        Ensure that the correct pin is set when enrolling a token.

        This test performs the following steps:
        1. Sets up a policy that allows token enrollment via self-service.
        2. Enrolls a token with a specific PIN.
        3. Validates that the token can be used with the correct PIN and OTP.
        """

        # Setup
        policy_params = {
            "name": "enroll",
            "scope": "selfservice",
            "action": "enrollPW",
            "user": "*",
            "realm": "*",
            "active": True,
        }

        response = self.make_system_request("setPolicy", policy_params)
        assert "false" not in response, response

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
        }
        token_params = {
            "type": "pw",
            "description": "Created via SelfService",
            "otpkey": "key",
            "pin": "pin",
        }
        response = self.make_userselfservice_request(
            "enroll", params=token_params, auth_user=auth_user
        )
        assert ' "value": true' in response, response

        # Test for correct PIN + OTP
        response = self.make_validate_request(
            "check",
            {
                "user": auth_user["login"],
                "pass": token_params["pin"] + token_params["otpkey"],
            },
        )
        resp_json = response.json
        assert resp_json["result"]["status"] == True
        assert resp_json["result"]["value"] == True

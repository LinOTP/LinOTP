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

from typing import Any, TypedDict

from linotp.tests import TestController

NOT_ALLOWED_ERROR = (
    "The policy settings do not allow you to issue this request!"
)


class EnrollmentTestParams(TypedDict):
    policies: list[dict[str, Any]]
    enroll_params: dict[str, Any]
    expected: bool


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
        Ensure that the correct pin is set when enrolling a token
        """

        # Setup
        params = {
            "name": "enroll",
            "scope": "selfservice",
            "action": "enrollPW, setOTPPIN",
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
        token_params = {
            "type": "pw",
            "description": "Created via SelfService",
            "otpkey": "key",
            "otppin": "pin",
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
                "pass": token_params["otppin"] + token_params["otpkey"],
            },
        )
        assert response.json["result"]["status"]
        assert response.json["result"]["value"]

    def _assert_enrollment(self, params: EnrollmentTestParams):
        self.setUp()

        for policy in params["policies"]:
            response = self.make_system_request("setPolicy", policy)
            assert "false" not in response, response

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
        }

        response = self.make_userselfservice_request(
            "enroll",
            params=params["enroll_params"],
            auth_user=auth_user,
        )
        result = response.json["result"]
        assert result.get("status") == params["expected"], (
            f"Assertion failed: Expected '{params['expected']}', but got '{result.get('status')}'.\n"
            f"Params: {params}\n"
            f"Full Response: {response.json}"
        )

    def test_pin_rule_enforcement_on_enrollment(self):
        """Tests for LINOTP-2255"""

        policy_enroll_totp_and_set_pin = {
            "name": "enroll_totp_and_set_pin",
            "scope": "selfservice",
            "action": "webprovisionGOOGLEtime,setOTPPIN",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        policy_otp_min_len_4 = {
            "name": "otp_min_length",
            "scope": "selfservice",
            "action": "otp_pin_minlength=4",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        policy_otp_max_len_8 = {
            "name": "otp_max_length",
            "scope": "selfservice",
            "action": "otp_pin_maxlength=8",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        policy_otp_pin_contents_c = {
            "name": "otp_pin_contents_c",
            "scope": "selfservice",
            "action": "otp_pin_contents=c",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        policy_otp_pin_contents_n = {
            "name": "otp_pin_contents_n",
            "scope": "selfservice",
            "action": "otp_pin_contents=n",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        policy_otp_pin_contents_s = {
            "name": "otp_pin_contents_s",
            "scope": "selfservice",
            "action": "otp_pin_contents=s",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        policy_otp_pin_contents_o = {
            "name": "otp_pin_contents_o",
            "scope": "selfservice",
            "action": "otp_pin_contents=o",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        policy_otp_pin_contents_plus_nc = {
            "name": "otp_pin_contents_plus_nc",
            "scope": "selfservice",
            "action": "otp_pin_contents=+nc",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        policy_otp_pin_contents_minus_nc = {
            "name": "otp_pin_contentsminus_nc",
            "scope": "selfservice",
            "action": "otp_pin_contents=-nc",
            "user": "*",
            "realm": "*",
            "active": True,
        }

        tests: list[EnrollmentTestParams] = [
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                ],
                "enroll_params": {"type": "totp", "otppin": ""},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                ],
                "enroll_params": {"type": "totp", "otppin": None},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                ],
                "enroll_params": {"type": "totp", "otppin": "123"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_min_len_4,
                ],
                "enroll_params": {"type": "totp", "otppin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_min_len_4,
                ],
                "enroll_params": {"type": "totp", "otppin": "123"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_min_len_4,
                ],
                "enroll_params": {"type": "totp", "otppin": "1234"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_max_len_8,
                ],
                "enroll_params": {"type": "totp", "otppin": "123456789"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_max_len_8,
                ],
                "enroll_params": {"type": "totp", "otppin": None},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_max_len_8,
                ],
                "enroll_params": {"type": "totp", "otppin": ""},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_max_len_8,
                ],
                "enroll_params": {"type": "totp", "otppin": "123"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_c,
                ],
                "enroll_params": {"type": "totp", "otppin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_c,
                ],
                "enroll_params": {"type": "totp", "otppin": None},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_c,
                ],
                "enroll_params": {"type": "totp", "otppin": "1!°"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_c,
                ],
                "enroll_params": {"type": "totp", "otppin": "a"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_n,
                ],
                "enroll_params": {"type": "totp", "otppin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_n,
                ],
                "enroll_params": {"type": "totp", "otppin": "a!°"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_n,
                ],
                "enroll_params": {"type": "totp", "otppin": "123"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_s,
                ],
                "enroll_params": {"type": "totp", "otppin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_s,
                ],
                "enroll_params": {"type": "totp", "otppin": "a1°"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_s,
                ],
                "enroll_params": {"type": "totp", "otppin": "!"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_o,
                ],
                "enroll_params": {"type": "totp", "otppin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_o,
                ],
                "enroll_params": {"type": "totp", "otppin": "a1!"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_o,
                ],
                "enroll_params": {"type": "totp", "otppin": "°"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_nc,
                ],
                "enroll_params": {"type": "totp", "otppin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_nc,
                ],
                "enroll_params": {"type": "totp", "otppin": "a1!"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_nc,
                ],
                "enroll_params": {"type": "totp", "otppin": "a"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_nc,
                ],
                "enroll_params": {"type": "totp", "otppin": "1"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_nc,
                ],
                "enroll_params": {"type": "totp", "otppin": "a1"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "otppin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "otppin": "a"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "otppin": "1"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "otppin": "a1!"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "otppin": "!"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "otppin": "a1"},
                "expected": True,
            },
        ]

        for params in tests:
            self._assert_enrollment(params)

    def test_setOTPPIN_on_enrollement(self):
        """Tests for LINOTP-2255"""
        policy_enroll_totp = {
            "name": "enroll_totp",
            "scope": "selfservice",
            "action": "webprovisionGOOGLEtime",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        policy_allow_set_pin = {
            "name": "allow_set_pin",
            "scope": "selfservice",
            "action": "setOTPPIN",
            "user": "*",
            "realm": "*",
            "active": True,
        }

        tests: list[EnrollmentTestParams] = [
            {
                "policies": [
                    policy_enroll_totp,
                ],
                "enroll_params": {"type": "totp"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp,
                ],
                "enroll_params": {"type": "totp", "otppin": "123"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp,
                    policy_allow_set_pin,
                ],
                "enroll_params": {"type": "totp", "otppin": "123"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp,
                    policy_allow_set_pin,
                ],
                "enroll_params": {"type": "totp"},
                "expected": False,
            },
        ]

        for params in tests:
            self._assert_enrollment(params)

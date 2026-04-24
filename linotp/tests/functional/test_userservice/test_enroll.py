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
from linotp.tests.functional.fido2_device import _AAGUID, SoftWebauthnDevice

NOT_ALLOWED_ERROR = "The policy settings do not allow you to issue this request!"


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
            "action": "enrollPW, setOTPPIN",
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
        assert resp_json["result"]["status"] is True
        assert resp_json["result"]["value"] is True

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
            "action": "enrollTOTP, setOTPPIN",
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
        policy_otp_pin_contents_plus_only = {
            "name": "otp_pin_contents_plus_only",
            "scope": "selfservice",
            "action": "otp_pin_contents=+",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        policy_otp_pin_contents_minus_only = {
            "name": "otp_pin_contentsminus_only",
            "scope": "selfservice",
            "action": "otp_pin_contents=-",
            "user": "*",
            "realm": "*",
            "active": True,
        }

        tests: list[EnrollmentTestParams] = [
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                ],
                "enroll_params": {"type": "totp", "pin": ""},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                ],
                "enroll_params": {"type": "totp", "pin": None},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                ],
                "enroll_params": {"type": "totp", "pin": "123"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_min_len_4,
                ],
                "enroll_params": {"type": "totp", "pin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_min_len_4,
                ],
                "enroll_params": {"type": "totp", "pin": "123"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_min_len_4,
                ],
                "enroll_params": {"type": "totp", "pin": "1234"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_max_len_8,
                ],
                "enroll_params": {"type": "totp", "pin": "123456789"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_max_len_8,
                ],
                "enroll_params": {"type": "totp", "pin": None},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_max_len_8,
                ],
                "enroll_params": {"type": "totp", "pin": ""},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_max_len_8,
                ],
                "enroll_params": {"type": "totp", "pin": "123"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_c,
                ],
                "enroll_params": {"type": "totp", "pin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_c,
                ],
                "enroll_params": {"type": "totp", "pin": None},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_c,
                ],
                "enroll_params": {"type": "totp", "pin": "1!°"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_c,
                ],
                "enroll_params": {"type": "totp", "pin": "a"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_n,
                ],
                "enroll_params": {"type": "totp", "pin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_n,
                ],
                "enroll_params": {"type": "totp", "pin": "a!°"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_n,
                ],
                "enroll_params": {"type": "totp", "pin": "123"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_s,
                ],
                "enroll_params": {"type": "totp", "pin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_s,
                ],
                "enroll_params": {"type": "totp", "pin": "a1°"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_s,
                ],
                "enroll_params": {"type": "totp", "pin": "!"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_o,
                ],
                "enroll_params": {"type": "totp", "pin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_o,
                ],
                "enroll_params": {"type": "totp", "pin": "a1!"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_o,
                ],
                "enroll_params": {"type": "totp", "pin": "°"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_nc,
                ],
                "enroll_params": {"type": "totp", "pin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_nc,
                ],
                "enroll_params": {"type": "totp", "pin": "a1!"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_nc,
                ],
                "enroll_params": {"type": "totp", "pin": "a"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_nc,
                ],
                "enroll_params": {"type": "totp", "pin": "1"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_nc,
                ],
                "enroll_params": {"type": "totp", "pin": "a1"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "pin": ""},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "pin": "a"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "pin": "1"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "pin": "a1!"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "pin": "!"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_nc,
                ],
                "enroll_params": {"type": "totp", "pin": "a1"},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_only,
                ],
                "enroll_params": {"type": "totp", "pin": None},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_only,
                ],
                "enroll_params": {"type": "totp", "pin": "1"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_plus_only,
                ],
                "enroll_params": {"type": "totp", "pin": ""},
                "expected": True,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_only,
                ],
                "enroll_params": {"type": "totp", "pin": None},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_only,
                ],
                "enroll_params": {"type": "totp", "pin": "1"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp_and_set_pin,
                    policy_otp_pin_contents_minus_only,
                ],
                "enroll_params": {"type": "totp", "pin": ""},
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
            "action": "enrollTOTP",
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
                "enroll_params": {"type": "totp", "pin": "123"},
                "expected": False,
            },
            {
                "policies": [
                    policy_enroll_totp,
                    policy_allow_set_pin,
                ],
                "enroll_params": {"type": "totp", "pin": "123"},
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

    def test_fido2_enrollment(self):
        """
        Test FIDO2 token enrollment (phase 1 and 2) via userservice.

        Uses a software FIDO2 authenticator (SoftWebauthnDevice) that
        generates real ES256 key pairs and produces valid attestation
        responses — no mocking or patching required.
        """
        self._create_fido2_policies()

        serial, registerreq, *_ = self.enroll_fido2_token(auth_user=self._auth_user())

        assert serial.startswith("FIDO2")
        assert registerreq["user"]["name"] == "passthru_user1"
        assert registerreq["user"]["displayName"] == "passthru_user1"

    def test_fido2_with_tokenlabel(self):
        """
        Test FIDO2 token with overridden user and displayName via tokenlabel.
        """
        self._create_fido2_policies(tokenlabel="<s><u>")

        serial, registerreq, *_ = self.enroll_fido2_token(auth_user=self._auth_user())

        expected = f"{serial}passthru_user1"
        assert registerreq["user"]["name"] == expected
        assert registerreq["user"]["displayName"] == expected

    def test_fido2_empty_tokenlabel(self):
        self._create_fido2_policies(tokenlabel="")

        _, registerreq, *_ = self.enroll_fido2_token(auth_user=self._auth_user())

        assert registerreq["user"]["name"] == "passthru_user1"
        assert registerreq["user"]["displayName"] == "passthru_user1"

    def _create_fido2_policies(self, tokenlabel=None):
        action = "fido2_rp_id=localhost"
        if tokenlabel is not None:
            action += f", tokenlabel={tokenlabel}"

        policies = [
            {
                "name": "enroll_fido2",
                "scope": "selfservice",
                "action": "enrollFIDO2",
                "user": "*",
                "realm": "*",
                "active": True,
            },
            {
                "name": "fido2_rpid",
                "scope": "enrollment",
                "action": action,
                "user": "*",
                "realm": "*",
                "active": True,
            },
        ]

        for p in policies:
            self.create_policy(p)

    def _auth_user(self):
        return {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
        }

    def test_fido2_enrollment_policies(self):
        """
        Verify that FIDO2 enrollment policies are reflected in the
        PublicKeyCredentialCreationOptions returned during phase 1.

        Sets fido2_attestation_conveyance, fido2_user_verification_requirement,
        fido2_resident_key_requirement and fido2_authenticator_types policies,
        then checks that the registration challenge contains the expected
        WebAuthn options.
        """

        policy_params = [
            {
                "name": "enroll_fido2",
                "scope": "selfservice",
                "action": "enrollFIDO2",
                "user": "*",
                "realm": "*",
                "active": True,
            },
            {
                "name": "fido2_rpid",
                "scope": "enrollment",
                "action": "fido2_rp_id=localhost",
                "user": "*",
                "realm": "*",
                "active": True,
            },
            {
                "name": "fido2_attestation",
                "scope": "enrollment",
                "action": "fido2_attestation_conveyance=direct",
                "user": "*",
                "realm": "*",
                "active": True,
            },
            {
                "name": "fido2_uv",
                "scope": "enrollment",
                "action": "fido2_user_verification_requirement=required",
                "user": "*",
                "realm": "*",
                "active": True,
            },
            {
                "name": "fido2_rk",
                "scope": "enrollment",
                "action": "fido2_resident_key_requirement=required",
                "user": "*",
                "realm": "*",
                "active": True,
            },
            {
                "name": "fido2_auth_types",
                "scope": "enrollment",
                "action": "fido2_authenticator_types=security-key",
                "user": "*",
                "realm": "*",
                "active": True,
            },
        ]
        for pp in policy_params:
            response = self.make_system_request("setPolicy", pp)
            assert "false" not in response, response

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
        }

        # Phase 1 — server generates a registration challenge
        response = self.make_userselfservice_request(
            "enroll",
            params={"type": "fido2"},
            auth_user=auth_user,
            new_auth_cookie=True,
        )
        assert response.json["result"]["status"] is True, response

        detail = response.json["detail"]
        register_request = detail["registerrequest"]

        # Check attestation conveyance preference
        assert register_request["attestation"] == "direct"

        auth_sel = register_request["authenticatorSelection"]
        assert auth_sel["userVerification"] == "required"
        assert auth_sel["residentKey"] == "required"

        # security-key only → attachment must be cross-platform and hint set
        assert auth_sel["authenticatorAttachment"] == "cross-platform"
        assert register_request["hints"] == ["security-key"]

    def test_fido2_allowed_authenticators_accepted(self):
        """FIDO2 enrollment succeeds when one of multiple whitelisted AAGUIDs matches."""
        self._create_fido2_policies()

        # Allow the SoftWebauthnDevice AAGUID among multiple space-separated values.
        self.create_policy(
            {
                "name": "fido2_allowed_auth",
                "scope": "enrollment",
                "action": (
                    "fido2_allowed_authenticators="
                    f"11111111-2222-3333-4444-555555555555 {_AAGUID} "
                    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                ),
                "user": "*",
                "realm": "*",
                "active": True,
            }
        )
        self.create_policy(
            {
                "name": "fido2_allowed_auth_2",
                "scope": "enrollment",
                "action": (
                    "fido2_allowed_authenticators="
                    "11111111-2222-3333-4444-555555555553"
                    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee1"
                ),
                "user": "*",
                "realm": "*",
                "active": True,
            }
        )
        serial, *_ = self.enroll_fido2_token(auth_user=self._auth_user())
        assert serial.startswith("FIDO2")

    def test_fido2_allowed_authenticators_rejected(self):
        """FIDO2 enrollment phase 2 fails when the device AAGUID is NOT in the whitelist."""
        self._create_fido2_policies()

        # Only allow a different AAGUID — the SoftWebauthnDevice will be rejected
        self.create_policy(
            {
                "name": "fido2_allowed_auth",
                "scope": "enrollment",
                "action": "fido2_allowed_authenticators=00000000-0000-0000-0000-000000000099",
                "user": "*",
                "realm": "*",
                "active": True,
            }
        )

        auth_user = self._auth_user()
        device = SoftWebauthnDevice()

        response = self.make_userselfservice_request(
            "enroll",
            params={"type": "fido2"},
            auth_user=auth_user,
            new_auth_cookie=True,
        )
        assert response.json["result"]["status"] is True, response
        detail = response.json["detail"]
        serial = detail["serial"]

        # Phase 2 — should fail because the AAGUID is not whitelisted
        attestation_response = device.create(
            detail["registerrequest"], origin="https://localhost"
        )
        response = self.make_userselfservice_request(
            "fido2_activate_finish",
            params={
                "serial": serial,
                "attestationResponse": attestation_response,
            },
            auth_user=auth_user,
            content_type="application/json",
        )
        assert response.json["result"]["status"] is False, response

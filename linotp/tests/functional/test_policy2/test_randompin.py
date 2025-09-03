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
Test the otp_pin_random policy
"""

import logging
from collections import deque
from copy import deepcopy

from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestRandompinController(TestController):
    """
    Test the otp_pin_random policy
    """

    # Don't mutate this data in test functions because it will be shared by all
    # tests. Instead copy it and then use it.
    tokens = [
        {
            "key": "3132333435363738393031323334353637383930",
            "type": "hmac",
            "serial": None,
            "otplen": 6,
            "pin": "123456",
            "otps": deque(
                [
                    "755224",
                    "287082",
                    "359152",
                    "969429",
                    "338314",
                    "254676",
                    "287922",
                    "162583",
                    "399871",
                    "520489",
                ]
            ),
        }
    ]
    test_realm = "myDefRealm"

    assign_policy = {
        "name": "enroll",
        "scope": "selfservice",
        "action": "assign",
        "realm": test_realm,
    }

    enroll_policy = {
        "name": "assign",
        "scope": "selfservice",
        "action": "enrollHMAC",
        "realm": test_realm,
    }

    randompin_policy = {
        "name": "randompin",
        "scope": "enrollment",
        "action": "otp_pin_random=12",
        "realm": test_realm,
    }

    setotppin_policy = {
        "name": "setotppin",
        "scope": "selfservice",
        "action": "setOTPPIN",
        "realm": test_realm,
    }
    autoassignment_policy = {
        "name": "autoassignment",
        "scope": "enrollment",
        "action": "autoassignment",
        "realm": test_realm,
    }

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def test_simple_enroll(self):
        """
        After normal enroll just OTP is enough. With otp_pin_random policy not.

        After a normal enroll you can authenticate successfully with only OTP
        (because no PIN is set). If otp_pin_random is set this is no longer the
        case (because PIN has been set to an unknown value).
        """
        # Enroll token
        user = "aἰσχύλος"  # realm myDefRealm  # noqa: RUF001
        token = deepcopy(self.tokens[0])
        self._enroll_token(token, user=user)

        # Login with only OTP succeeds
        self._validate(
            user,
            token["otps"].popleft(),
        )

        self.create_policy(self.randompin_policy)

        # Enroll new token
        token2 = deepcopy(self.tokens[0])
        self._enroll_token(token2, user=user)

        # Login with only OTP fails
        self._validate(user, token2["otps"].popleft(), expected="value-false")

    def test_simple_assign(self):
        """
        Same as 'test_simple_enroll' but with assign after enroll

        Verify the behaviour is the same if the token is first enrolled and
        then assigned to a user, instead of directly enrolling for the user
        as in test_simple_enroll.
        """
        # Enroll token
        user = "aἰσχύλος"  # realm myDefRealm  # noqa: RUF001
        token = deepcopy(self.tokens[0])
        self._enroll_token(token)

        # Login with only OTP succeeds
        self._validate_check_s(
            token["serial"],
            token["otps"].popleft(),
        )

        self._assign(token["serial"], user)

        # Login with only OTP succeeds
        self._validate(
            user,
            token["otps"].popleft(),
        )

        self.create_policy(self.randompin_policy)

        # Enroll token
        user = "aἰσχύλος"  # realm myDefRealm  # noqa: RUF001
        token2 = deepcopy(self.tokens[0])
        self._enroll_token(token2)

        # Login with only OTP fails (PIN unknown)
        self._validate_check_s(
            token2["serial"], token2["otps"].popleft(), expected="value-false"
        )

        self._assign(token2["serial"], user)

        # Login with only OTP fails (PIN unknown)
        self._validate(user, token2["otps"].popleft(), expected="value-false")

    def test_multi_assign(self):
        """
        Same as 'test_simple_assign' but with multiple tokens at once
        """
        # Enroll token
        user = "aἰσχύλος"  # realm myDefRealm  # noqa: RUF001
        token1 = deepcopy(self.tokens[0])
        token2 = deepcopy(self.tokens[0])

        self._enroll_token(token1)
        self._enroll_token(token2)

        # Login with only OTP succeeds
        self._validate_check_s(token1["serial"], token1["otps"].popleft())
        self._validate_check_s(token2["serial"], token2["otps"].popleft())

        self.create_policy(self.randompin_policy)

        self._assign([token1["serial"], token2["serial"]], user)

        # Login with only OTP fails (PIN unknown)
        self._validate_check_s(
            token1["serial"], token1["otps"].popleft(), expected="value-false"
        )
        self._validate_check_s(
            token2["serial"], token2["otps"].popleft(), expected="value-false"
        )

    def test_selfservice_set_pin_after_enroll(self):
        """
        Token is enrolled by admin, user logs into selfservice, sets PIN and authenticates successfully
        """
        self.create_policy(self.randompin_policy)
        self.create_policy(self.setotppin_policy)

        # Enroll token
        user = "aἰσχύλος"  # realm myDefRealm  # noqa: RUF001
        pwd = "Πέρσαι"
        token = deepcopy(self.tokens[0])
        self._enroll_token(token, user=user)

        # Login with only OTP fails (because PIN is unknown)
        self._validate(user, token["otps"].popleft(), expected="value-false")

        # User logs into selfservice and sets PIN
        pin = "mytokenpin"
        self._set_pin_in_selfservice(user, pwd, token["serial"], pin)

        # authenticate successfully with PIN+OTP
        self._validate(
            user,
            pin + token["otps"].popleft(),
        )

    def test_selfservice_enroll(self):
        """
        otp_pin_random sets a random pin when enrolling a token in selfservice
        """

        self.create_policy(self.enroll_policy)

        user = "aἰσχύλος"  # realm myDefRealm  # noqa: RUF001
        pwd = "Πέρσαι"
        token1 = deepcopy(self.tokens[0])
        token2 = deepcopy(self.tokens[0])

        # Enroll first token without otp_pin_random policy
        token1.pop("pin")
        self._enroll_token_in_selfservice(user, pwd, token1)
        # Login with only OTP succeeds
        self._validate_check_s(token1["serial"], token1["otps"].popleft())

        self.create_policy(self.randompin_policy)

        # Enroll second token with otp_pin_random policy without setotppin
        token2.pop("pin")
        self._enroll_token_in_selfservice(user, pwd, token2)
        # Login with OTP does not work (because PIN is random)
        self._validate_check_s(
            token2["serial"], token2["otps"].popleft(), expected="value-false"
        )

        self._create_setotppin_policy("myDefRealm")

        # Enroll second token with otp_pin_random policy with setotppin
        self._enroll_token_in_selfservice(user, pwd, token3)
        # Login with Pin and OTP works (because PIN is set)
        self._validate_check_s(
            token3["serial"], token3["pin"] + token3["otps"].popleft()
        )

    def test_selfservice_assign(self):
        """
        userservice/assign is not affected by otp_pin_random
        """

        user = "aἰσχύλος"  # realm myDefRealm  # noqa: RUF001
        pwd = "Πέρσαι"
        token = deepcopy(self.tokens[0])

        # Enroll token unassigned
        self._enroll_token(token)
        # authenticate successfully, no pin set yet
        self._validate_check_s(token["serial"], token["otps"].popleft())

        self.create_policy(self.setotppin_policy)
        self.create_policy(self.assign_policy)
        self.create_policy(self.randompin_policy)

        # Assign token to user in selfservice
        self._assign_in_selfservice(user, pwd, token["serial"])
        # Login with only OTP still works because userservice/assign is
        # not affected by otp_pin_random
        self._validate(user, token["otps"].popleft())

    def test_admin_setpin(self):
        """
        Admin can set the PIN, even after the user has set it in selfservice

        This test will fail with WebTest 1.2.1 (Debian Squeeze) because of a
        bug that caused cookies to be quoted twice. The bug is fixed in 1.2.2.
        https://github.com/Pylons/webtest/
                                commit/8471db1c2dc505c633bca2d39d5713dba0c51a42
        """
        self.create_policy(self.randompin_policy)
        self.create_policy(self.setotppin_policy)

        # Enroll token
        user = "aἰσχύλος"  # realm myDefRealm  # noqa: RUF001
        token = deepcopy(self.tokens[0])
        self._enroll_token(token, user=user)

        # Login with only OTP fails (because PIN is unknown)
        self._validate(user, token["otps"].popleft(), expected="value-false")

        # Admin sets PIN
        self._set_pin(token["serial"], "admin-set-pin")
        # authenticate successfully with PIN+OTP
        self._validate(
            user,
            "admin-set-pin" + token["otps"].popleft(),
        )

        # User logs into selfservice and sets PIN
        pwd = "Πέρσαι"
        pin = "mytokenpin"
        self._set_pin_in_selfservice(user, pwd, token["serial"], pin)
        # authenticate successfully with PIN+OTP
        self._validate(
            user,
            pin + token["otps"].popleft(),
        )

        # Admin sets PIN again
        self._set_pin(token["serial"], "second-admin-set-pin")
        # authenticate successfully with PIN+OTP
        self._validate(
            user,
            "second-admin-set-pin" + token["otps"].popleft(),
        )

    def test_assign_other_user(self):
        """
        Verify PIN is overwritten when assigning token to a different user

        Test both the case where the user is in the same realm (where the
        policy is defined) and in another realm without opt_pin_random policy.

        This test will fail with WebTest 1.2.1 (Debian Squeeze) because of a
        bug that caused cookies to be quoted twice. The bug is fixed in 1.2.2.
        https://github.com/Pylons/webtest/
                                commit/8471db1c2dc505c633bca2d39d5713dba0c51a42
        """
        self.create_policy(self.randompin_policy)
        self.create_policy(self.assign_policy)
        self.create_policy(self.setotppin_policy)

        # Enroll token
        user = "aἰσχύλος"  # realm myDefRealm  # noqa: RUF001
        token = deepcopy(self.tokens[0])
        self._enroll_token(token, user=user)

        # Login with only OTP fails (because PIN is unknown)
        self._validate(user, token["otps"].popleft(), expected="value-false")

        # User logs into selfservice and sets PIN
        pwd = "Πέρσαι"
        pin = "mytokenpin"
        self._set_pin_in_selfservice(user, pwd, token["serial"], pin)
        # authenticate successfully with PIN+OTP
        self._validate(
            user,
            pin + token["otps"].popleft(),
        )

        # Assign token to new user
        new_user = "beckett"
        self._assign(token["serial"], new_user)

        # authenticate fails because old PIN is no longer valid (i.e. was
        # overwritten with a random value during assignment)
        self._validate(
            new_user,
            pin + token["otps"].popleft(),
            expected="value-false",
        )

        # Admin sets the PIN
        self._set_pin(token["serial"], "admin-set-pin")

        # Now assign the token to a user in a realm without otp_pin_random
        # policy
        user3 = "shakespeare@mymixrealm"
        self._assign(token["serial"], user3)

        # authenticate succeeds because PIN is NOT overwritten (in a real
        # scenario it is assumed the new user does not know the PIN of the
        # previous one)
        self._validate(
            user3,
            "admin-set-pin" + token["otps"].popleft(),
        )

    def test_randompin_with_autoassignment(self):
        """
        Enroll with randompin and then autoassign token -> PIN is user password
        """
        self.create_policy(self.randompin_policy)

        token = deepcopy(self.tokens[0])
        self._enroll_token(token)

        # Login with only OTP fails (because PIN is unknown)
        self._validate_check_s(
            token["serial"], token["otps"].popleft(), expected="value-false"
        )

        # Create autoassignment policy
        self.create_policy(self.autoassignment_policy)
        # Set token realm for autoassignment to work
        self._set_token_realm(token["serial"], self.test_realm)

        # autoassign the token
        user = "aἰσχύλος"  # noqa: RUF001
        pwd = "Πέρσαι"
        self._validate(
            user,
            pwd + token["otps"].popleft(),
        )

        # The user password is set as PIN
        for _ in range(3):
            self._validate(
                user,
                pwd + token["otps"].popleft(),
            )

    # -------- Private helper methods ----- --
    def _enroll_token_in_selfservice(self, user, pwd, token):
        """
        Log into selfservice and enroll token

        :param user: username or username@realm
        :param pwd: user password for selfservice session
        :param token: A dictionary with token information. This dictionary is
            augmented with 'serial' after enrolling the token.
        """
        params = {
            "otpkey": token["key"],
            "type": token["type"],
            "otplen": token["otplen"],
        }
        if "pin" in token:
            params["pin"] = token["pin"]

        response = self.make_userservice_request(
            "enroll", params, auth_user=(user, pwd)
        )

        content = response.json
        assert content["result"]["status"], content
        assert content["result"]["value"], content
        token["serial"] = content["detail"]["serial"]

    def _enroll_token(self, token, user=None):
        """
        Enroll token for 'user'.

        :param token: A dictionary with token information. This dictionary is
            augmented with 'serial' after enrolling the token.
        :param user: The name of the user to assign the token to. If None then
            the token is not assigned.
        """
        # enroll token
        params = {
            "otpkey": token["key"],
            "type": token["type"],
            "otplen": token["otplen"],
        }
        if user:
            params["user"] = user.encode("utf-8")
        response = self.make_admin_request("init", params=params)
        content = response.json
        assert content["result"]["status"]
        assert content["result"]["value"]
        token["serial"] = content["detail"]["serial"]

    def _validate(self, user, pwd, expected="success", err_msg=None):
        """
        runs a validate/check request and verifies the response is as 'expected'

        :param user: Username or username@realm
        :param pwd: Password (e.g. PIN+OTP)
        :param expected: One of 'success', 'value-false', 'status-false' or
                        'both-false'
        :param err_msg: An error message to display if assert fails
        :return: The content (JSON object)
        """
        params = {"user": user.encode("utf-8"), "pass": pwd.encode("utf-8")}
        return self._validate_base(
            params,
            action="check",
            expected=expected,
            err_msg=err_msg,
        )

    def _validate_check_s(self, serial, pwd, expected="success", err_msg=None):
        """
        Makes a validate/check_s request and verifies the response is as
        'expected'

        :param serial: Token serial
        :param pwd: Password (e.g. PIN+OTP)
        :param expected: One of 'success', 'value-false', 'status-false' or
            'both-false'
        :param err_msg: An error message to display if assert fails
        :return: The content (JSON object)
        """
        params = {"serial": serial, "pass": pwd.encode("utf-8")}
        return self._validate_base(
            params,
            action="check_s",
            expected=expected,
            err_msg=err_msg,
        )

    def _validate_base(self, params, action="check", expected="success", err_msg=None):
        """
        Base method for /validate/<action> requests

        Don't call this method directly but use _validate() or
        _validate_check_s() instead.

        :param params: Request parameters
        :param expected: One of 'success', 'value-false', 'status-false' or
            'both-false'
        :param err_msg: An error message to display if the assert fails
        :return: The content (JSON object)
        """
        response = self.make_validate_request(action, params=params)
        content = response.json
        if not err_msg:
            err_msg = f"validate/{action} failed for {params!r}. Response: {content!r}"
        if expected == "success":
            assert content["result"]["status"], err_msg
            assert content["result"]["value"], err_msg
        elif expected == "value-false":
            assert content["result"]["status"], err_msg
            assert not content["result"]["value"], err_msg
        elif expected == "status-false":
            assert not content["result"]["status"], err_msg
            assert content["result"]["value"], err_msg
        elif expected == "both-false":
            assert not content["result"]["status"], err_msg
            assert not content["result"]["value"], err_msg
        else:
            self.fail(f"Unknown 'expected' {expected}")
        return content

    def _assign_in_selfservice(self, user, pwd, serial):
        """
        Log into selfservice and assign token

        :param user: username or username@realm
        :param pwd: user password for selfservice session
        :param serial: Token serial number
        :return: None
        """
        params = {"serial": serial}
        response = self.make_userservice_request(
            "assign", params, auth_user=(user, pwd)
        )
        content = response.json
        assert content["result"]["status"]
        expected = {"assign token": True}
        assert expected == content["result"]["value"]

    def _assign(self, serial, user):
        """
        Assign token defined by 'serial' to 'user'

        :param serial: Token serial number
        :param user: User (e.g. username@realm)
        :return: None
        """
        params = {
            "serial": serial,
            "user": user,
        }
        response = self.make_admin_request(
            "assign",
            params=params,
            content_type="application/json",  # json is necessary to assign multiple tokens at once
        )
        content = response.json
        assert content["result"]["status"]
        assert content["result"]["value"]

    def _set_pin_in_selfservice(self, user, pwd, serial, pin):
        """
        Log into selfservice and set PIN

        :param user: username or username@realm
        :param pwd: user password for selfservice session
        :param serial: Token serial
        :param pin: The PIN to be set
        """
        params = {
            "serial": serial,
            "userpin": pin,
        }

        response = self.make_userservice_request(
            "setpin", params, auth_user=(user, pwd)
        )

        content = response.json
        assert content["result"]["status"]
        expected = {"set userpin": 1}
        assert expected == content["result"]["value"]

    def _set_pin(self, serial, pin):
        """
        Set the token PIN 'pin' for the token identified by 'serial'
        """
        params = {
            "serial": serial,
            "pin": pin,
        }
        response = self.make_admin_request("set", params=params)
        content = response.json
        assert content["result"]["status"]
        assert content["result"]["value"]

    def _set_token_realm(self, serial, realm):
        """
        Set the token realm 'realm' for the token identified by 'serial'
        """
        assert serial and realm, "Both 'serial' and 'realm' required"
        params = {
            "serial": serial,
            "realms": realm,
        }
        response = self.make_admin_request("tokenrealm", params=params)
        content = response.json
        assert content["result"]["status"]
        assert content["result"]["value"] == 1

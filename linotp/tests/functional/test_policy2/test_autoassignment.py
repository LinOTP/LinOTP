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
Test the autoassignment Policy.
"""
import json
from copy import deepcopy

import pytest
from mock import patch

from flask import g

from linotp.tests import TestController


class TestAutoassignmentController(TestController):
    """
    Test the autoassignment Policy.
    """

    # Define a list of 5 token with known OTP values. The 'serial' is set
    # during enrollment to the value chosen by LinOTP
    token_list = [
        {
            "key": "4132333435363738393031323334353637383930",
            "type": "hmac",
            "serial": None,
            "otplen": 6,
            "otps": ["297991", "212756", "338869"],
        },
        {
            "key": "5132333435363738393031323334353637383930",
            "type": "hmac",
            "serial": None,
            "otplen": 6,
            "otps": ["841650", "850446", "352919"],
        },
        {
            "key": "my_secret_password",
            "type": "pw",
            "serial": None,
            "otplen": len("my_secret_password"),
            "otps": [
                "my_secret_password",
                "my_secret_password",
                "my_secret_password",
            ],
        },
        {
            "key": "9163508031b20d2fbb1868954e041729",
            "type": "yubikey",
            "serial": None,
            "otplen": 48,
            "otps": [
                "ecebeeejedecebeg" + "fcniufvgvjturjgvinhebbbertjnihit",
                "ecebeeejedecebeg" + "tbkfkdhnfjbjnkcbtbcckklhvgkljifu",
                "ecebeeejedecebeg" + "ktvkekfgufndgbfvctgfrrkinergbtdj",
            ],
        },
        {
            "key": "3132333435363738393031323334353637383930",
            "type": "hmac",
            "serial": None,
            "otplen": 6,
            "otps": ["755224", "287082", "359152"],
        },
    ]
    # set up in setUp
    policies_for_deletion = None
    token_for_deletion = None

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()
        self.token_for_deletion = set()
        self.policies_for_deletion = set()
        self._enroll_token(self.token_list)

    def tearDown(self):
        # Delete policies
        for policy in self.policies_for_deletion:
            self.delete_policy(policy)
        # Delete token
        for token in self.token_for_deletion:
            self.delete_token(token)
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def test_autoassign_mixed_token(self):
        """
        Autoassignment with 4 HMAC and 1 Yubikey token to 5 different users

        5 Token (4 HMAC + 1 Yubikey) are enrolled and put together in the same
        token realm.  An autoenrollment policy for that realm is created.  5
        different users from that realm autoassign themselves one token each by
        authenticating with their user-store password and an OTP value
        corresponding to that token.
        """

        token_list = deepcopy(self.token_list)

        self._create_autoassignment_policy(
            "my_autoassign_policy", "mydefrealm"
        )
        self._set_token_realm(token_list, "mydefrealm")

        # 5 (user, password) pairs from myDefRealm
        users = [
            ("molière", "molière"),
            ("shakespeare", "shakespeare1"),
            ("lorca", "lorca1"),
            ("aἰσχύλος", "Πέρσαι"),
            ("beckett", "beckett1"),
        ]

        # autoassign token to users
        for i in range(5):
            user_name, user_pwd = users[i]
            token = token_list[i]
            self._validate(
                user_name,
                user_pwd + token["otps"][0],
            )

        for i in range(5):
            # Assert the token was assigned to the correct user
            user_name, user_pwd = users[i]
            token = token_list[i]
            response = self.make_admin_request(
                "getTokenOwner", {"serial": token["serial"]}
            )
            content = response.json
            assert content["result"]["status"]
            assert user_name == content["result"]["value"]["username"]

            # Validate the remaining OTP values
            for j in range(1, 3):
                self._validate(
                    user_name,
                    user_pwd + token["otps"][j],
                )

    def test_cant_autoassign_assigned_token(self):
        """
        It is not possible to autoassign a token that has already been assigned.
        """
        # Only one token required for this test
        token_list = deepcopy(self.token_list[0:1])

        # Put all token in the same realm
        self._create_autoassignment_policy(
            "my_autoassign_policy", "mydefrealm"
        )
        self._set_token_realm(token_list, "mydefrealm")

        # (user, password) pairs from myDefRealm
        users = [
            ("molière", "molière"),
            ("shakespeare", "shakespeare1"),
        ]

        # Assign token[0] to users[0]
        user_name, user_pwd = users[0]
        token = token_list[0]
        params = {
            "user": user_name.encode("utf-8"),
            "serial": token["serial"],
        }
        response = self.make_admin_request("assign", params=params)
        content = response.json
        assert content["result"]["status"]
        assert 1 == content["result"]["value"]

        # Try to autoassign token[0] to users[1] -> should fail because it is
        # already assigned to users[0]
        user_name, user_pwd = users[1]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token["otps"][0],
            expected="value-false",
        )

        # molière can authenticate...
        user_name, user_pwd = users[0]
        token = token_list[0]
        # No PIN was set
        self._validate(
            user_name,
            token["otps"][1],
        )
        # ... and shakespeare can't
        user_name, user_pwd = users[1]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token["otps"][2],
            expected="value-false",
        )

    def test_only_autoassign_with_no_other_token(self):
        """
        A user can only autoassign himself a token if he has no token.
        """
        self._create_autoassignment_policy(
            "my_autoassign_policy", "mydefrealm"
        )
        # Only two token required for this test
        token_list = deepcopy(self.token_list[0:2])

        # Put all token in the same realm
        self._set_token_realm(token_list, "mydefrealm")

        # (user, password) pairs from myDefRealm
        users = [
            ("molière", "molière"),
        ]

        # Assign token[0] to users[0]
        user_name, user_pwd = users[0]
        token = token_list[0]
        params = {
            "user": user_name.encode("utf-8"),
            "serial": token["serial"],
        }
        response = self.make_admin_request("assign", params=params)
        content = response.json
        assert content["result"]["status"]
        assert 1 == content["result"]["value"]

        # Try to autoassign token[1] to users[0] -> should fail because the
        # user already has a token
        user_name, user_pwd = users[0]
        token = token_list[1]
        self._validate(
            user_name,
            user_pwd + token["otps"][0],
            expected="value-false",
        )

        # molière can only authenticate with token_list[0] ...
        user_name, user_pwd = users[0]
        token = token_list[0]
        # No PIN was set
        self._validate(
            user_name,
            token["otps"][1],
        )
        # ... not token_list[1]
        user_name, user_pwd = users[0]
        token = token_list[1]
        self._validate(
            user_name,
            user_pwd + token["otps"][2],
            expected="value-false",
        )

    def test_no_policy_no_autoassign(self):
        """
        Without the autoassign policy autoassignment does not work.
        """
        # Only one token required for this test
        token_list = deepcopy(self.token_list[0:1])

        # (user, password) pairs from myDefRealm
        users = [
            ("molière", "molière"),
        ]

        self._set_token_realm(token_list, "mydefrealm")

        user_name, user_pwd = users[0]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token["otps"][0],
            expected="value-false",
        )

    def test_policy_int_action(self):
        """
        If autoassigment=<int> the policy will work.

        This is due to backwards compatibility because once upon a time that
        value was used to determine the token length of the token. In order not
        to break older system on upgrade we still support this syntax. The
        'value' of the <int> is ignored (unless it is -1, see
        test_policy_negative_action).
        """
        # Only one token required for this test
        token_list = deepcopy(self.token_list[0:1])

        # (user, password) pairs from myDefRealm
        users = [
            ("molière", "molière"),
        ]

        # Policy with <int> action
        params = {
            "name": "int_autoassignment",
            "scope": "enrollment",
            "action": "autoassignment=99",
            "user": "*",
            "realm": "mydefrealm",
        }
        self.create_policy(params)
        self.policies_for_deletion.add("int_autoassignment")

        self._set_token_realm(token_list, "mydefrealm")

        user_name, user_pwd = users[0]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token["otps"][0],
        )

    def test_policy_negative_action(self):
        """
        If autoassigment=-1 the policy will not be active.

        This is due to backwards compatibility.
        """
        # Only one token required for this test
        token_list = deepcopy(self.token_list[0:1])

        # (user, password) pairs from myDefRealm
        users = [
            ("molière", "molière"),
        ]

        # Policy with action -1
        params = {
            "name": "negative_autoassignment",
            "scope": "enrollment",
            "action": "autoassignment=-1",
            "user": "*",
            "realm": "mydefrealm",
        }
        self.create_policy(params)
        self.policies_for_deletion.add("negative_autoassignment")

        self._set_token_realm(token_list, "mydefrealm")

        user_name, user_pwd = users[0]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token["otps"][0],
            expected="value-false",
        )

    def test_duplicate_otp(self):
        """
        If the OTP value matches for several token autoassignment fails
        """
        token_list = deepcopy(self.token_list[1:2])
        token = deepcopy(token_list[0])
        token["serial"] = token["serial"] + "copy"

        # Enroll new token with duplicate first OTP

        params = {
            "otpkey": token["key"],
            "type": token["type"],
            "otplen": token["otplen"],
            "serial": token["serial"],
        }
        response = self.make_admin_request("init", params=params)
        content = response.json
        assert content["result"]["status"]
        assert content["result"]["value"]
        token["serial"] = content["detail"]["serial"]

        self.token_for_deletion.add(token["serial"])
        token_list.append(token)

        # (user, password) pairs from myDefRealm
        users = [
            ("molière", "molière"),
            ("shakespeare", "shakespeare1"),
        ]

        self._create_autoassignment_policy(
            "my_autoassign_policy", "mydefrealm"
        )
        self._set_token_realm(token_list, "mydefrealm")

        # autoassign token_list[0] to users[0] -> should fail because the OTP
        # value is valid for several token and therefore it can't be
        # determined which one to use
        user_name, user_pwd = users[0]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token["otps"][0],
            expected="value-false",
        )

        # This only happens if several unassigned token have a common OTP
        # value. To verify this we assign one of the token, then the other
        # one can be assigned with autoassigment.

        # Assign token_list[0] to users[0]
        user_name, user_pwd = users[0]
        token = token_list[0]
        params = {
            "user": user_name.encode("utf-8"),
            "serial": token["serial"],
        }
        response = self.make_admin_request("assign", params=params)
        content = response.json
        assert content["result"]["status"]
        assert 1 == content["result"]["value"]
        # No PIN was set
        self._validate(
            user_name,
            token["otps"][1],
        )

        # autoassign token_list[1] to users[1]
        user_name, user_pwd = users[1]
        token = token_list[1]
        self._validate(
            user_name,
            user_pwd + token["otps"][1],
        )

    def test_with_ignore_autoassignment_pin(self):
        """
        Test PIN is empty when ignore_autoassignment_pin policy is set
        """
        token_list = deepcopy(self.token_list[0:1])

        self._create_autoassignment_policy(
            "my_autoassign_policy", "mydefrealm"
        )
        self._set_token_realm(token_list, "mydefrealm")

        # (user, password) pairs from myDefRealm
        users = [
            ("molière", "molière"),
        ]

        self._create_ignore_autoassignment_pin_policy("mydefrealm")

        # autoassign token to users
        user_name, user_pwd = users[0]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token["otps"][0],
        )

        # Assert the token was assigned to the correct user
        response = self.make_admin_request(
            "getTokenOwner", {"serial": token["serial"]}
        )
        content = response.json
        assert content["result"]["status"]
        assert user_name == content["result"]["value"]["username"]

        # Validate the remaining OTP values (note PIN is empty)
        for j in range(1, 3):
            self._validate(
                user_name,
                token["otps"][j],
            )

    # -------- Private helper methods ----- --

    def _enroll_token(self, token_list):
        """
        Enroll all token in token_list. Update the list with the serial number
        returned by LinOTP.

        Adds the token to self.token_for deletion so it is cleaned up on
        tearDown.
        """
        for token in token_list:
            params = {
                "otpkey": token["key"],
                "type": token["type"],
                "otplen": token["otplen"],
            }
            response = self.make_admin_request("init", params=params)
            content = response.json
            assert content["result"]["status"]
            assert content["result"]["value"]
            token["serial"] = content["detail"]["serial"]
            self.token_for_deletion.add(token["serial"])

    def _set_token_realm(self, token_list, realm_name):
        """
        Set the token realm 'realm_name' for all token in 'token_list'.
        """
        for token in token_list:
            assert token["serial"] is not None
            params = {"serial": token["serial"], "realms": realm_name}
            response = self.make_admin_request("tokenrealm", params=params)
            content = response.json
            assert content["result"]["status"]
            assert 1 == content["result"]["value"]

    def _create_autoassignment_policy(
        self, name, realm, action="autoassignment"
    ):
        """
        Create an autoassignment policy with name 'name' for realm 'realm'.

        Adds the policy to self.policies_for deletion so it is cleaned up on
        tearDown.
        """
        params = {
            "name": name,
            "scope": "enrollment",
            "action": action,
            "user": "*",
            "realm": realm,
        }
        self.create_policy(params)
        self.policies_for_deletion.add(name)

    def _create_ignore_autoassignment_pin_policy(self, realm):
        """
        Create an ignore_autoassignment_pin policy for realm 'realm'.

        Adds the policy to self.policies_for deletion so it is cleaned up on
        tearDown.
        """
        params = {
            "name": "ignore_autoassignment_pin",
            "scope": "enrollment",
            "action": "ignore_autoassignment_pin",
            "realm": realm,
        }
        self.create_policy(params)
        self.policies_for_deletion.add("ignore_autoassignment_pin")

    def _validate(self, user, pwd, expected="success", err_msg=None):
        """
        Makes a validate/check requests and verifies the response is as 'expected'
        :param user: Username or username@realm
        :param pwd: Password (e.g. PIN+OTP)
        :param expected: One of 'success', 'value-false', 'status-false' or 'both-false'
        :param err_msg: An error message to display if assert fails
        :return: The content (JSON object)
        """
        params = {"user": user.encode("utf-8"), "pass": pwd.encode("utf-8")}
        response = self.make_validate_request("check", params=params)
        content = response.json
        if not err_msg:
            err_msg = "validate/check failed for %r. Response: %r" % (
                user,
                content,
            )
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
            self.fail("Unknown 'expected' %s" % expected)
        return content

    def test_autoassign_mixed_token_wo_password(self):
        """
        Autoassignment wo password with 4 HMAC + 1 Yubikey to 5 different users

        - 5 Token (4 HMAC + 1 Yubikey) are enrolled and put together in
          the same token realm.

        - An autoenrollment policy for that realm is created.

        - 5 different users from that realm autoassign themselves one token
          each by authenticating with the OTP value corresponding to
          that token.

        """

        # 5 users from myDefRealm
        users = ["molière", "shakespeare", "lorca", "aἰσχύλος", "beckett"]

        # 5 token descriptions
        token_list = deepcopy(self.token_list)

        # ----------------------------------------------------------------- --

        # create the policies for autoassigment without pin

        self._create_autoassignment_policy(
            name="my_autoassign_policy_wo_pass",
            realm="mydefrealm",
            action="autoassignment_without_password",
        )

        self._set_token_realm(token_list, "mydefrealm")

        # ----------------------------------------------------------------- --

        # validate/check with otp only to autoassign token to users

        for i in range(5):
            user_name = users[i]
            token = token_list[i]

            params = {
                "user": user_name.encode("UTF-8"),
                "pass": token["otps"][0],
            }

            response = self.make_validate_request("check", params=params)

            msg = "Error 65537 while instatiating the CBC mode"
            assert msg not in g.audit["info"]

            assert '"value": true' in response

        # ----------------------------------------------------------------- --

        # verify the correct assignment of the token to the user

        for i in range(5):
            user_name = users[i]
            token = token_list[i]
            params = {"serial": token["serial"]}

            response = self.make_admin_request("getTokenOwner", params=params)
            content = json.loads(response.body)

            assert content["result"]["status"]
            assert user_name == content["result"]["value"]["username"]

            # -------------------------------------------------------------- --

            # verify the correct working of the token by validate/check with
            # the remaining OTP values

            for j in range(1, 3):
                params = {
                    "user": user_name.encode("UTF-8"),
                    "pass": token["otps"][j],
                }

                response = self.make_validate_request("check", params=params)
                assert '"value": true' in response

        return


# eof #

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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

"""unit test for policy query with actions"""

import copy
import datetime
import unittest
from collections import namedtuple

import pytest
from mock import patch

from linotp.lib.policy import (
    PolicyException,
    get_auto_enrollment,
    get_autoassignment,
    get_tokenissuer,
)
from linotp.lib.policy.maxtoken import (
    check_maxtoken_for_user,
    check_maxtoken_for_user_by_type,
)
from linotp.lib.token import TokenHandler
from linotp.lib.user import User as LinotpUser

Token = namedtuple("Token", ["type"])

fake_context = {
    "Client": "128.0.0.1",
}

PolicySet = {
    "hans": {
        "realm": "*",
        "active": "True",
        "client": "*",
        "user": "hans",
        "time": "* * * * * *;",
        "action": "dummy=2",
        "scope": "enrollment",
    },
    "fake_user": {
        "realm": "*",
        "active": "True",
        "client": "*",
        "user": "fake_user",
        "time": "* * * * * *;",
        "action": "dummy1",
        "scope": "enrollment",
    },
    "general": {
        "realm": "*",
        "active": "True",
        "client": "*",
        "user": "*",
        "time": "* * * * * *;",
        "action": "action",
        "scope": "enrollment",
    },
}


@pytest.mark.usefixtures("app")
class PolicyActionTest(unittest.TestCase):
    """Verify that policy actions are correctly identified for a given user and in general.

    the policy action has to be part of the policy selection step and not only
    during the get_action_value processing. Otherwise there will only
    policies be found for a user where the action might not be part of and the
    general policies with "user:'*'" which might contain the action wont be
    selected.

    this test verifies this behaviour for various policy evaluation helper
    functions that had been fixed as there are:

    * check_maxtoken_for_user: action=maxtoken
    * check_maxtoken_for_user_by_type: action=maxtokenHMAC (eg)
    * get_tokenissuer: action=tokenissuer
    * get_autoassignment: actio=autoassignment
    * get_auto_enrollment: action=autoenrollment
    * lib.token::losttoken:
        lostTokenPWLen, lostTokenValid, lostTokenPWContents

    """

    @patch("linotp.lib.policy.util.context", new=fake_context)
    @patch("linotp.lib.context.request_context", new=fake_context)
    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.policy.maxtoken._getUserRealms")
    @patch("linotp.lib.policy.maxtoken._get_client")
    @patch("linotp.lib.token.get_tokens")
    def test_maxtoken_evaluation(
        self,
        mocked_get_tokens,
        mocked__get_client,
        mocked__getUserRealms,
        mocked__get_policies,
        mocked_get_policy_definitions,
    ):
        """check if maxtoken policy works correctly."""

        fake_user = LinotpUser(login="fake_user", realm="defaultrealm")

        mocked_get_tokens.return_value = [Token("hmac")]
        mocked__get_client.return_value = "127.0.0.1"
        mocked__getUserRealms.return_value = ["defaultrealm", "otherrealm"]

        mocked_get_policy_definitions.return_value = {
            "enrollment": {"maxtoken": {"type": "int"}}
        }

        policy_set = copy.deepcopy(PolicySet)

        # ----------------------------------------------------------------- --

        # verify that general policy is honored

        policy_set["general"]["action"] = "maxtoken=2"
        mocked__get_policies.return_value = policy_set

        try:
            check_maxtoken_for_user(user=fake_user)
        except PolicyException:
            assert not True, (
                "_checkTokenAssigned: Exception raised, but "
                "token count was still in boundaries"
            )

        # ----------------------------------------------------------------- --

        # verify that user specific policy is honored

        policy_set["fake_user"]["action"] = 'maxtoken="1 ", '
        mocked__get_policies.return_value = policy_set

        try:
            check_maxtoken_for_user(user=fake_user)
        except PolicyException:
            assert True, (
                "_checkTokenAssigned: Exception raised, but "
                "token count was still in boundaries"
            )

    @patch("linotp.lib.policy.util.context", new=fake_context)
    @patch("linotp.lib.context.request_context", new=fake_context)
    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.policy.maxtoken._getUserRealms")
    @patch("linotp.lib.policy.maxtoken._get_client")
    @patch("linotp.lib.token.get_tokens")
    def test_maxtoken_type_evaluation2(
        self,
        mocked_get_tokens,
        mocked__get_client,
        mocked__getUserRealms,
        mocked__get_policies,
        mocked_get_policy_definitions,
    ):
        """Check if maxtoken type policy works correctly."""

        fake_user = LinotpUser(login="fake_user", realm="defaultrealm")

        mocked_get_tokens.return_value = [Token("hmac")]
        mocked__get_client.return_value = "127.0.0.1"
        mocked__getUserRealms.return_value = ["defaultrealm", "otherrealm"]
        mocked_get_policy_definitions.return_value = {
            "enrollment": {
                "maxtoken": {"type": "int"},
                "maxtokenHMAC": {"type": "int"},
                "maxtokenPUSH": {"type": "int"},
            }
        }

        policy_set = copy.deepcopy(PolicySet)

        # ----------------------------------------------------------------- --

        # verify that general policy is honored

        policy_set["general"]["action"] = "maxtokenHMAC=2, maxtokenPUSH=2,"
        mocked__get_policies.return_value = policy_set

        try:
            check_maxtoken_for_user_by_type(fake_user, "hmac")
        except PolicyException:
            assert not True, (
                "_checkTokenAssigned: Exception raised, but "
                "token count was still in boundaries"
            )

        # ----------------------------------------------------------------- --

        # verify that if set, the  user specific  policy is honored

        policy_set["fake_user"]["action"] = "maxtokenHMAC=1"
        mocked__get_policies.return_value = policy_set

        try:
            check_maxtoken_for_user_by_type(fake_user, "hmac")
        except PolicyException:
            assert True, (
                "_checkTokenAssigned: Exception raised, but "
                "token count was not in boundaries"
            )

    @patch("linotp.lib.policy.util.context", new=fake_context)
    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.policy._get_client")
    def test_tokenissuer(
        self,
        mocked__get_client,
        mocked__get_policies,
        mocked_get_policy_definitions,
    ):
        """Verify that the tokenissuer is evaluated from general."""

        mocked__get_client.return_value = "127.0.0.1"
        mocked_get_policy_definitions.return_value = {
            "enrollment": {
                "tokenissuer": {
                    "type": "str",
                    "desc": "the issuer label for the google authenticator.",
                },
            }
        }

        policy_set = copy.deepcopy(PolicySet)

        # ----------------------------------------------------------------- --

        # verify that general policy is honored

        policy_set["general"]["action"] = "tokenissuer=<s>:<u>@<r>"
        mocked__get_policies.return_value = policy_set

        issuer = get_tokenissuer(
            user="fake_user", realm="defaultrealm", serial="mySerial"
        )
        assert issuer == "mySerial:fake_user@defaultrealm"

        # ----------------------------------------------------------------- --

        # verify that if set, user specific policy is honored

        policy_set["fake_user"]["action"] = "dummy, tokenissuer=<u>@<r>"
        mocked__get_policies.return_value = policy_set

        issuer = get_tokenissuer(
            user="fake_user", realm="defaultrealm", serial="mySerial"
        )
        assert issuer == "fake_user@defaultrealm"

    @patch("linotp.lib.policy.util.context", new=fake_context)
    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.policy._get_client")
    def test_autoassignment(
        self,
        mocked__get_client,
        mocked__get_policies,
        mocked_get_policy_definitions,
    ):
        """Verify that the autoassignment is evaluated from general."""

        mocked__get_client.return_value = "127.0.0.1"

        policy_set = copy.deepcopy(PolicySet)

        # ----------------------------------------------------------------- --

        # verify that general policy is honored

        policy_set["general"]["action"] = "autoassignment"
        mocked__get_policies.return_value = policy_set
        mocked_get_policy_definitions.return_value = {
            "enrollment": {
                "autoassignment": {
                    "type": "bool",
                    "desc": "users can assign a token just by using the "
                    "unassigned token to authenticate.",
                },
            }
        }

        fake_user = LinotpUser(login="fake_user", realm="defaultrealm")
        assert get_autoassignment(fake_user), "autoassigment should be set!"

        # ----------------------------------------------------------------- --

        # verify that if set, user specific policy is honored

        policy_set["fake_user"]["action"] = "tokenissuer=<u>, autoassignment"
        mocked__get_policies.return_value = policy_set

        issuer = get_tokenissuer(
            user="fake_user", realm="defaultrealm", serial="mySerial"
        )
        assert issuer == "fake_user"

    @patch("linotp.lib.policy.util.context", new=fake_context)
    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.policy._get_client")
    def test_autoenrollment(
        self,
        mocked__get_client,
        mocked__get_policies,
        mocked_get_policy_definitions,
    ):
        """Verify that the autoenrollment is evaluated from general."""

        mocked__get_client.return_value = "127.0.0.1"

        policy_set = copy.deepcopy(PolicySet)

        mocked_get_policy_definitions.return_value = {
            "enrollment": {
                "autoenrollment": {
                    "type": "str",
                    "desc": "users can enroll a token just by using the "
                    "pin to authenticate and will an otp for authentication",
                },
            }
        }
        # ----------------------------------------------------------------- --

        # verify that general policy is honored

        policy_set["general"]["action"] = "autoenrollment=email"
        mocked__get_policies.return_value = policy_set

        fake_user = LinotpUser(login="fake_user", realm="defaultrealm")
        is_enabled, token_type = get_auto_enrollment(fake_user)

        assert is_enabled, "autoenrollment should be defined!"
        assert token_type == ["email"]

        # ----------------------------------------------------------------- --

        # verify that if set, user specific policy is honored

        policy_set["fake_user"]["action"] = "autoenrollment=sms"
        mocked__get_policies.return_value = policy_set

        fake_user = LinotpUser(login="fake_user", realm="defaultrealm")
        is_enabled, token_type = get_auto_enrollment(fake_user)

        assert is_enabled, "autoenrollment should be defined!"
        assert token_type == ["sms"]

    @patch("linotp.lib.token.context", new=fake_context)
    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.token.TokenHandler.getTokenOwner")
    @patch("linotp.lib.token.TokenHandler.copyTokenUser")
    @patch("linotp.lib.token.TokenHandler.copyTokenPin")
    def test_losttoken(
        self,
        mocked_copyTokenPin,
        mocked_copyTokenUser,
        mocked_getTokenOwner,
        mocked__get_policies,
        mocked_get_policy_definitions,
    ):
        """Verify the policy evaluation in losttoken honores general actions."""

        fake_user = LinotpUser(login="fake_user", realm="defaultrealm")
        mocked_getTokenOwner.return_value = fake_user

        mocked_copyTokenUser.return_value = 1
        mocked_copyTokenPin.return_value = 1

        policy_set = copy.deepcopy(PolicySet)

        mocked_get_policy_definitions.return_value = {
            "enrollment": {
                "lostTokenPWLen": {
                    "type": "int",
                    "desc": "The length of the password in case of temporary token.",
                },
                "lostTokenPWContents": {
                    "type": "str",
                    "desc": "The contents of the temporary password, "
                    "described by the characters C, c, n, s.",
                },
                "lostTokenValid": {
                    "type": "set",
                    "value": ["int", "duration"],
                    "desc": "The length of the validity for the temporary "
                    'token as days or duration with "d"-days, "h"-hours,'
                    ' "m"-minutes, "s"-seconds.',
                },
            }
        }
        # ----------------------------------------------------------------- --

        # verify that general policy is honored

        policy_set["general"]["action"] = (
            "lostTokenPWLen=5, lostTokenPWContents=n, lostTokenValid=2"
        )

        mocked__get_policies.return_value = policy_set

        end_date = (datetime.date.today() + datetime.timedelta(days=2)).strftime(
            "%d/%m/%y"
        )
        end_date = "%s 23:59" % end_date

        th = TokenHandler()
        res = th.losttoken("mySerial", "mySerial_new")

        assert res["password"].isdigit()
        assert len(res["password"]) == 5
        assert res["end_date"] == end_date

        # ----------------------------------------------------------------- --

        # verify that user specific policy is honored

        policy_set["fake_user"]["action"] = (
            "lostTokenPWLen=3, lostTokenPWContents=c, lostTokenValid=1"
        )

        mocked__get_policies.return_value = policy_set

        end_date = (datetime.date.today() + datetime.timedelta(days=1)).strftime(
            "%d/%m/%y"
        )
        end_date = "%s 23:59" % end_date

        th = TokenHandler()
        res = th.losttoken(serial="mySerial", new_serial="mySerial_new")

        assert not res["password"].isdigit()
        assert len(res["password"]) == 3
        assert res["end_date"] == end_date

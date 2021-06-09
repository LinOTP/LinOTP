# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2020 arxes-tolina
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

""" unit test for policy query selfservice actions """

from collections import namedtuple

import copy
import unittest

from linotp.lib.policy.action import (
    get_selfservice_actions,
    get_selfservice_action_value,
)
from linotp.lib.user import User as LinotpUser

from mock import patch
import pytest


Token = namedtuple("Token", ["type"])
fake_context = {
    "translate": lambda x: x,
    "Client": "128.0.0.1",
}

PolicySet = {
    "hans": {
        "realm": "*",
        "active": "True",
        "client": "*",
        "user": "hans",
        "time": "* * * * * *;",
        "action": "enable",
        "scope": "selfservice",
    },
    "simple_user": {
        "realm": "*",
        "active": "True",
        "client": "*",
        "user": "simple_user",
        "time": "* * * * * *;",
        "action": "disable",
        "scope": "selfservice",
    },
    "general": {
        "realm": "*",
        "active": "True",
        "client": "*",
        "user": "*",
        "time": "* * * * * *;",
        "action": "",
        "scope": "selfservice",
    },
}


@pytest.mark.usefixtures("app")
class SelfserviceActionTest(unittest.TestCase):
    """Verify the helper function get_selfservice_actions"""

    @patch("linotp.lib.token.context", new=fake_context)
    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.policy.action._get_client")
    def test_get_selfservice_actions(
        self,
        mocked__get_client,
        mocked__get_policies,
        mocked_get_policy_definitions,
    ):
        """Verify the policy evaluation via helper get_selfservice_actions"""

        mocked__get_client.return_value = "127.0.0.1"

        simple_user = LinotpUser(login="simple_user", realm="defaultrealm")
        anonym_user = LinotpUser(login="anonym_user", realm="defaultrealm")

        policy_set = copy.deepcopy(PolicySet)

        mocked_get_policy_definitions.return_value = {
            "selfservice": {
                "setDescription": {"type": "bool"},
                "enrollHMAC": {"type": "bool"},
                "reset": {"type": "bool"},
            }
        }

        # ----------------------------------------------------------------- --

        # verify that general policy is honored

        policy_set["general"]["action"] = "setDescription, enrollHMAC, reset"

        mocked__get_policies.return_value = policy_set

        res = get_selfservice_actions(simple_user, "setDescription")

        assert "setDescription" in res
        assert res["setDescription"]

        res = get_selfservice_actions(simple_user)

        assert "setDescription" not in res
        assert "disable" in res

        assert get_selfservice_actions(simple_user, "setDescription")

        assert not get_selfservice_actions(anonym_user, "disable")

        # ----------------------------------------------------------------- --

        # verify that user specific policy is honored

        policy_set["simple_user"]["action"] = "setDescription, disable"

        mocked__get_policies.return_value = policy_set

        res = get_selfservice_actions(simple_user)

        assert "setDescription" in res
        assert "disable" in res
        assert "reset" not in res

    @patch("linotp.lib.token.context", new=fake_context)
    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.policy.action._get_client")
    def test_get_selfservice_actions2(
        self,
        mocked__get_client,
        mocked__get_policies,
        mocked_get_policy_definitions,
    ):
        """Verify the policy evaluation via helper get_selfservice_actions"""

        mocked__get_client.return_value = "127.0.0.1"

        simple_user = LinotpUser(login="simple_user", realm="defaultrealm")
        anonym_user = LinotpUser(login="anonym_user", realm="defaultrealm")

        policy_set = copy.deepcopy(PolicySet)

        # ----------------------------------------------------------------- --
        mocked_get_policy_definitions.return_value = {
            "selfservice": {
                "otp_pin_maxlength": {"type": "int"},
                "enrollHMAC": {"type": "bool"},
                "reset": {"type": "bool"},
            }
        }
        # verify that general policy is honored

        policy_set["general"][
            "action"
        ] = "otp_pin_maxlength=4, enrollHMAC, reset"

        mocked__get_policies.return_value = policy_set

        res = get_selfservice_actions(simple_user, "otp_pin_maxlength")

        assert "otp_pin_maxlength" in res
        assert res["otp_pin_maxlength"] == 4

        # ----------------------------------------------------------------- --

        # verify that user specific policy is honored

        policy_set["simple_user"][
            "action"
        ] = "otp_pin_maxlength=6, delete, reset"

        mocked__get_policies.return_value = policy_set

        res = get_selfservice_actions(simple_user, "otp_pin_maxlength")

        assert "otp_pin_maxlength" in res
        assert res["otp_pin_maxlength"] == 6

        # ----------------------------------------------------------------- --

        # verify that user specific policy is honored but only for the user

        res = get_selfservice_actions(anonym_user, "otp_pin_maxlength")

        assert "otp_pin_maxlength" in res
        assert res["otp_pin_maxlength"] == 4

    @patch("linotp.lib.token.context", new=fake_context)
    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.policy.action._get_client")
    def test_get_selfservice_action_value(
        self,
        mocked__get_client,
        mocked__get_policies,
        mocked_get_policy_definitions,
    ):
        """Verify the policy evaluation via helper get_selfservice_action_value"""

        mocked__get_client.return_value = "127.0.0.1"

        simple_user = LinotpUser(login="simple_user", realm="defaultrealm")
        anonym_user = LinotpUser(login="anonym_user", realm="defaultrealm")

        policy_set = copy.deepcopy(PolicySet)

        # ----------------------------------------------------------------- --
        mocked_get_policy_definitions.return_value = {
            "selfservice": {
                "otp_pin_maxlength": {"type": "int"},
                "enrollHMAC": {"type": "bool"},
                "reset": {"type": "bool"},
            }
        }
        # verify that general policy is honored

        policy_set["general"][
            "action"
        ] = "otp_pin_maxlength=4, enrollHMAC, reset"

        mocked__get_policies.return_value = policy_set

        res = get_selfservice_action_value(
            "otp_pin_maxlength", user=simple_user
        )

        assert res == 4

        # ----------------------------------------------------------------- --

        # verify that user specific policy is honored

        policy_set["simple_user"][
            "action"
        ] = "otp_pin_maxlength=6, delete, reset"

        mocked__get_policies.return_value = policy_set

        res = get_selfservice_action_value(
            "otp_pin_maxlength", user=simple_user
        )

        assert res == 6

        # ----------------------------------------------------------------- --

        # verify that user specific policy is honored but only for the user

        res = get_selfservice_action_value(
            "otp_pin_maxlength", user=anonym_user
        )

        assert res == 4

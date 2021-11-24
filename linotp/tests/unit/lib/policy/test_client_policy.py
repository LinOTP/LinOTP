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

""" unit test for policy query honoring client"""

import unittest

import pytest
from mock import patch

from linotp.lib.policy import get_partition, getOTPPINEncrypt, supports_offline
from linotp.lib.user import User as LinotpUser


class Token:
    def __init__(self, toke_type):
        self.type = toke_type

    def getType(self):
        return self.type


fake_context = {
    "Client": "128.0.0.1",
}


@pytest.mark.usefixtures("app")
class ClientPolicyTest(unittest.TestCase):
    """Verify the replacement of getPolicy with get_client_policy.

    the relacement was made in the following places:

    * getOTPPINEncrypt(serial=None, user=None): action=otp_pin_encrypt
    * supports_offline(realms, token): action=support_offline
    * get_partition(realms, user): action=partition

    """

    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.token.context", new=fake_context)
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.policy._get_client")
    def test_supports_offline(
        self,
        mocked__get_client,
        mocked__get_policies,
        mocked_get_policy_definitions,
    ):
        """verify that client in the policy is honored for supports_offline"""

        m_policy = {
            "general": {
                "realm": "*",
                "active": "True",
                "client": "*",
                "user": "*",
                "time": "* * * * * *;",
                "action": "support_offline=qr",
                "scope": "authentication",
            }
        }
        mocked_get_policy_definitions.return_value = {
            "authentication": {
                "support_offline": {
                    "type": "set",
                    "value": ["qr", "u2f"],  # TODO: currently hardcoded
                    "desc": "The token types that should support offline "
                    "authentication",
                },
            }
        }

        mocked__get_policies.return_value = m_policy

        qr_token = Token("qr")

        mocked__get_client.return_value = "127.0.0.1"
        assert supports_offline(realms=["defaultrealm"], token=qr_token)

        mocked__get_client.return_value = "128.0.0.1"
        assert supports_offline(realms=["defaultrealm"], token=qr_token)

        m_policy["general"]["client"] = "127.0.0.1/24"

        mocked__get_client.return_value = "127.0.0.1"
        assert supports_offline(realms=["defaultrealm"], token=qr_token)

        mocked__get_client.return_value = "128.0.0.1"
        assert not supports_offline(realms=["defaultrealm"], token=qr_token)

    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.token.context", new=fake_context)
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.policy._get_client")
    def test_get_partition(
        self,
        mocked__get_client,
        mocked__get_policies,
        mocked_get_policy_definitions,
    ):
        """verify that client in the policy is honored for get_partition"""

        m_policy = {
            "general": {
                "realm": "*",
                "active": "True",
                "client": "127.0.0.1/24",
                "user": "*",
                "time": "* * * * * *;",
                "action": "partition=2",
                "scope": "enrollment",
            }
        }
        mocked_get_policy_definitions.return_value = {
            "enrollment": {
                "partition": {"type": "int", "desc": "partition"},
            }
        }
        mocked__get_policies.return_value = m_policy

        user = LinotpUser(login="user", realm="defaultrealm")

        mocked__get_client.return_value = "127.0.0.1"
        assert get_partition(["defaultrealm"], user=user) == 2

        mocked__get_client.return_value = "128.0.0.1"
        assert get_partition(["defaultrealm"], user=user) == 0

    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.token.context", new=fake_context)
    @patch("linotp.lib.policy._getUserRealms")
    @patch("linotp.lib.policy.processing.get_policies")
    @patch("linotp.lib.policy._get_client")
    def test_getOTPPINEncrypt(
        self,
        mocked__get_client,
        mocked__get_policies,
        mocked__get_realms,
        mocked_get_policy_definitions,
    ):
        """verify that client in the policy is honored for getOTPPINEncrypt"""

        m_policy = {
            "general": {
                "realm": "*",
                "active": "True",
                "client": "127.0.0.1/24",
                "user": "*",
                "time": "* * * * * *;",
                "action": "otp_pin_encrypt",
                "scope": "enrollment",
            }
        }

        mocked__get_policies.return_value = m_policy
        mocked__get_realms.return_value = ["defaultrealm"]
        mocked_get_policy_definitions.return_value = {
            "enrollment": {
                "otp_pin_encrypt": {"type": "int", "value": [0, 1]},
            }
        }

        user = LinotpUser(login="user", realm="defaultrealm")

        mocked__get_client.return_value = "127.0.0.1"
        assert getOTPPINEncrypt(user=user) == 1

        mocked__get_client.return_value = "128.0.0.1"
        assert getOTPPINEncrypt(user=user) == 0

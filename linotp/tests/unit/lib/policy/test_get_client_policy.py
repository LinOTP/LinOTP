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


"""
Test the passthrough Policy in combination with the passOnNoToken
"""

import unittest

from mock import patch

import linotp.lib.policy
from linotp.lib.policy import get_single_auth_policy


def m_get_client_match():
    return "192.168.13.14"


def m_get_client_no_match():
    return "172.111.1.14"


def m_get_policies():
    policies = {
        "qrtoken_local": {
            "name": "qrtoken_local",
            "realm": "*",
            "active": "True",
            "client": "*",
            "user": "*",
            "time": "*",
            "action": "qrtoken_pairing_callback_url=http://local",
            "scope": "authentication",
        },
        "qrtoken_client": {
            "name": "qrtoken_client",
            "realm": "*",
            "active": "True",
            "client": "192.168.0.0/16,",
            "user": "*",
            "time": "*",
            "action": "qrtoken_pairing_callback_url=http://client",
            "scope": "authentication",
        },
    }
    return policies.copy()


class TestGetClientPolicy(unittest.TestCase):

    """
    Policy test
    """

    @patch("linotp.lib.policy.action.get_policy_definitions")
    def test_get_single_auth_policy_pe(self, mock_get_policy_definitions):
        """
        verify that (more specific) policy which refers to a client is selected

        this is the first one of a series to test that policy evaluation
        supports the filtering by client, now focusing on the function
              get_single_auth_policy
        which is used by the QRToken and the PushToken to retrieve the pairing
        and callback urls from the policy defintions

        """

        mock_get_policy_definitions.return_value = {
            "authentication": {"qrtoken_pairing_callback_url": {"type": "str"}}
        }
        with patch.object(
            linotp.lib.policy, "_get_client", autospec=True
        ) as mock_get_client:

            # ------------------------------------------------------------------ --

            # call the get_policies function which must be mocked

            with patch.object(
                linotp.lib.policy.processing, "get_policies", autospec=True
            ) as mock_get_policies:

                # ---------------------------------------------------------- --

                # setup the to be called  mocked functions

                mock_get_policies.side_effect = m_get_policies
                mock_get_client.side_effect = m_get_client_match

                action_value = get_single_auth_policy(
                    "qrtoken_pairing_callback_url", realms=["*"]
                )

                assert "client" in action_value

                mock_get_client.side_effect = m_get_client_no_match
                action_value = get_single_auth_policy(
                    "qrtoken_pairing_callback_url", realms=["*"]
                )

                assert "client" not in action_value


# eof #

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

import unittest

from mock import patch

from linotp.lib.user import User
from linotp.provider import get_provider_from_policy

mocked_context = {"Client": "123.123.123.123"}


class TestProviderFromPolicy(unittest.TestCase):
    """
    unit test to identify provider  from policy
    """

    @patch("linotp.provider.request_context", new=mocked_context)
    def test_get_default_provider(self):
        """
        get the default providers if no policy
        """
        with patch("linotp.lib.policy.get_client_policy") as mock_policy:
            with patch("linotp.provider._get_default_provider_name") as mock_default:
                mock_policy.return_value = {}
                mock_default.return_value = "default"

                provider = get_provider_from_policy("sms", user=User("login", "realm"))

                assert provider == ["default"]

    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.provider.request_context", new=mocked_context)
    def test_get_policy_provider(self, mocked_get_policy_definitions):
        """
        get the providers from the policy
        """

        with patch("linotp.lib.policy.get_client_policy") as mocked_policy:
            mocked_policy.return_value = {
                "one": {
                    "name": "one",
                    "scope": "authentication",
                    "active": True,
                    "action": "sms_provider=  one   two ,  ",
                    "realm": "*",
                    "user": "*",
                }
            }
            mocked_get_policy_definitions.return_value = {
                "authentication": {
                    "sms_provider": {"type": "str"},
                }
            }

            provider = get_provider_from_policy("sms", user=User("login", "realm"))

            assert provider == ["one", "two"]


# eof #

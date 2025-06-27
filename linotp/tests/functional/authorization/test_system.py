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
Test user authorisation for actions in the "system" scope.
"""

from linotp.tests import TestController


class TestSystemPolicy(TestController):
    """
    Test the system read/write policies.
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

    def test_active_system_policies(self):
        """verify that only active system policies are evaluated

        1. verify that anybody can read the system information if no system
           policy is defined at all
        2. define a system policy and verify that this admin is able to read
           the system information
        3. verify that nobody else is able to read the system (getRealms)
        4. verify that nobody else is able to read the system (getRealms)
           as disabling a policy has the same effect as deleting it
        5. verify that any admin with read permission is able to read the
           system information.
        6. when all policies are disabled, no access restrictions are set
        7. if a policy of a different scope is set this has no impact on the
           current scope - no restriction will be given
        """

        # 1. verify, that anybody is allowed to read the realms if no system
        #    policy is defined:

        response = self.make_system_request("getRealms", auth_user="hans")
        assert response.json["result"]["status"]

        # 2. define a system policy and verify that this admin is able to read
        #    the system information

        params = {
            "name": "super_admin",
            "scope": "system",
            "action": "read, write",
            "active": True,
            "user": "admin",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        response = self.make_system_request("getRealms", auth_user="admin")
        assert response.json["result"]["status"]

        # 3. verify that nobody else is able to read the system (getRealms)

        response = self.make_system_request("getRealms", auth_user="hans")
        assert not response.json["result"]["status"]

        # 4. verify that nobody else is able to read the system (getRealms)
        #    as disabling a policy has the same effect as deleting it

        params = {
            "name": "no_full_admin",
            "scope": "system",
            "action": "read",
            "active": False,
            "user": "hans",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        response = self.make_system_request("getRealms", auth_user="hans")
        assert not response.json["result"]["status"]

        # 5. verify that any admin with read permission is able to read the
        #    system information.

        params = {
            "name": "no_full_admin",
            "scope": "system",
            "action": "read",
            "active": True,
            "user": "hans",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        response = self.make_system_request("getRealms", auth_user="hans")
        assert response.json["result"]["status"]

        # 6. when all policies are disabled, no access restrictions are set
        params = {
            "name": "no_full_admin",
            "scope": "system",
            "action": "read",
            "active": False,
            "user": "hans",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        params = {
            "name": "super_admin",
            "scope": "system",
            "action": "read, write",
            "active": False,
            "user": "admin",
            "realm": "*",
        }
        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        response = self.make_system_request("getRealms", auth_user="hans")
        assert response.json["result"]["status"]

        response = self.make_system_request("getRealms", auth_user="admin")
        assert response.json["result"]["status"]

        # 7. if a policy of a different scope is set this has no impact on the
        #    current scope - no restriction will be given

        params = {
            "name": "super_admin",
            "scope": "audit",
            "action": "view",
            "active": True,
            "user": "admin",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        response = self.make_system_request("getRealms", auth_user="hans")
        assert response.json["result"]["status"]


# eof #

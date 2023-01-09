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
Test user authorisation for actions in the "tools" scope.
"""
import io
import os

from linotp.tests import TestController


class TestToolsAuthorisation(TestController):
    """
    Test the tools access policies.
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

    def import_users(
        self,
        file_name="4users.csv",
        resolver_name=None,
        dryrun=True,
        auth_user="admin",
    ):
        # ------------------------------------------------------------------ --

        if not resolver_name:
            resolver_name = file_name.strip(".csv")

        # open the csv data and import the users

        user_file = os.path.join(self.fixture_path, file_name)

        with io.open(user_file, "r", encoding="utf-8") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]
        params = {
            "resolver": resolver_name,
            "dryrun": dryrun,
            "format": "csv",
        }

        return self.make_tools_request(
            action="import_users",
            params=params,
            upload_files=upload_files,
            auth_user=auth_user,
        )

    def test_active_tools_policies(self):
        """verify that only active tools policies are evaluated

        1. verify that anybody can import users (tools/import_users)) if no
           tools policy is defined at all
        2. define a tools policy and verify that this admin is able to import
           users
        3. verify that other users are not able to import users
        4. verify that other users are not able to import users
           as disabling a policy has the same effect as deleting it
        5. verify that other users are able to import users if the policy
           becomes active.
        6. when all policies are disabled, no access restrictions are set
        7. if a policy of a different scope is set this has no impact on the
           current scope - no restriction will be given

        """

        # 1. verify that anybody can import users (tools/import_users)) if no
        #    tools policy is defined at all
        response = self.import_users(file_name="4users.csv", auth_user="hans")
        assert response.json["result"]["status"]

        # 2. define a tools policy and verify that this admin is able to
        # import users

        params = {
            "name": "super_admin",
            "scope": "tools",
            "action": "import_users",
            "active": True,
            "user": "admin",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        response = self.import_users(file_name="4users.csv", auth_user="admin")
        assert response.json["result"]["status"]

        # 3. verify that other users are not able to import users

        response = self.import_users(file_name="4users.csv", auth_user="hans")
        assert not response.json["result"]["status"]

        # 4. verify that other users are not able to import users even as
        #    disabling a policy has the same effect as deleting it

        params = {
            "name": "no_full_admin",
            "scope": "tools",
            "action": "import_users",
            "active": False,
            "user": "hans",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        response = self.import_users(file_name="4users.csv", auth_user="hans")
        assert not response.json["result"]["status"]

        # 5. verify that other users are able to import users if the policy
        #    becomes active.

        params = {
            "name": "no_full_admin",
            "scope": "tools",
            "action": "import_users",
            "active": True,
            "user": "hans",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        response = self.import_users(file_name="4users.csv", auth_user="hans")
        assert response.json["result"]["status"]

        # 6. when all policies are disabled, no access restrictions are set

        params = {
            "name": "no_full_admin",
            "scope": "tools",
            "action": "import_users",
            "active": False,
            "user": "hans",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        params = {
            "name": "super_admin",
            "scope": "tools",
            "action": "import_users",
            "active": False,
            "user": "admin",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        response = self.import_users(file_name="4users.csv", auth_user="hans")
        assert response.json["result"]["status"]

        response = self.import_users(file_name="4users.csv", auth_user="admin")
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

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


""" """

from linotp.tests import TestController


class TestRealms(TestController):
    """
    test for the api endpoing /api/v2/realms
    """

    def setUp(self):
        """setup the test controller"""
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        """clean up after the tests"""
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def test_realms_controller_access(self):
        """verify that authentication is required for the realms controller

        * first we run an authenticated request via 'make_api_v2_request'
        * then we run an unauthenticated request via the standard client
          which will fail with status 401
        """

        # ---------------------------------------------------------------- --
        # access the realms api via the authenticated testing api

        response = self.make_api_v2_request("/realms/")

        assert response.json["result"]["status"]
        assert isinstance(response.json["result"]["value"], list)

        # ---------------------------------------------------------------- --
        # access the tokens api with the unauthenticated testing client

        response = self.client.get("/api/v2/realms/")

        assert response.status_code == 401

    def test_realms_controller_permissions(self):
        """verify that system read permission is required to read realms"""
        # --------------------------------------------------------------- --
        # create a restriction to the 'admin' to only see myDefRealm tokens

        admin_read_write_realms = {
            "name": "admin_read_write_realms",
            "active": True,
            "action": "read, write",
            "user": "admin",
            "scope": "system",
            "realm": "myDefRealm",
            "time": None,
        }

        response = self.make_system_request(
            "setPolicy",
            params=admin_read_write_realms,
            auth_user="admin",
        )

        assert response.json["result"]["status"]

        # --------------------------------------------------------------- --
        # admin2 has only read permissions

        admin2_read_realms = {
            "name": "admin2_read_realms",
            "active": True,
            "action": "read",
            "user": "admin2",
            "scope": "system",
            "realm": "myDefRealm",
            "time": None,
        }

        response = self.make_system_request(
            "setPolicy",
            params=admin2_read_realms,
            auth_user="admin",
        )

        assert response.json["result"]["status"]

        # --------------------------------------------------------------- --
        # admin3 has only write permissions

        assert response.json["result"]["status"]

        admin3_write_realms = {
            "name": "admin3_write_realms",
            "active": True,
            "action": "write",
            "user": "admin3",
            "scope": "system",
            "realm": "myDefRealm",
            "time": None,
        }

        response = self.make_system_request(
            "setPolicy",
            params=admin3_write_realms,
            auth_user="admin",
        )

        assert response.json["result"]["status"]

        # --------------------------------------------------------------- --
        # admin2 is only allowed to write to and to read from system

        response = self.make_api_v2_request("/realms/", auth_user="admin")

        assert len(response.json["result"]["value"]) == 4

        # --------------------------------------------------------------- --
        # admin2 is only allowed to read from system

        response = self.make_api_v2_request("/realms/", auth_user="admin2")

        assert len(response.json["result"]["value"]) == 4

        # --------------------------------------------------------------- --
        # admin3 is only allowed to write to system

        response = self.make_api_v2_request("/realms/", auth_user="admin3")

        assert response.status_code == 403

        # --------------------------------------------------------------- --
        # we delete the policies in the correct order, otherwise this might
        # fail

        self.delete_policy(name="admin3_write_realms", auth_user="admin")
        self.delete_policy(name="admin2_read_realms", auth_user="admin")
        self.delete_policy(name="admin_read_write_realms", auth_user="admin")

    def test_get_users(self):
        realm_name = "myDefRealm"
        response = self.make_api_v2_request(
            f"/realms/{realm_name}/users", auth_user="admin"
        )
        result = response.json
        # myDefRealm has 27 users
        assert len(result["result"]["value"]) == 27

        response = self.make_api_v2_request(
            f"/realms/{realm_name}/users",
            params={"username": "*passt*"},
            auth_user="admin",
        )
        result = response.json
        # 2 passthru_user in myDefRealm
        assert len(result["result"]["value"]) == 2

        response = self.make_api_v2_request(
            f"/realms/{realm_name}/users",
            params={"rp": "3", "page": 0},
            auth_user="admin",
        )
        result = response.json
        assert len(result["result"]["value"]) == 3

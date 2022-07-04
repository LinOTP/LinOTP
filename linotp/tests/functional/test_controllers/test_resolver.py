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


from linotp.tests import TestController


class TestResolver(TestController):
    """
    Tests for the endpoints under /api/v2/resolver
    """

    def setUp(self):
        """
        Set up the test controller.

        Apart from the default admin realm and resolver it creates a resolver
        called myDefRes contained in mydefrealm and mymixrealm, and a resolver
        called myOtherRes contained in myotherrealm and mymixrealm.
        """
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
        return

    def test_resolver_result(self):
        """verify that the response of resolvers e contains realms

        get the list of resolvers and verify that they contain the pointer
        to the list of realms
        """

        response = self.make_api_v2_request("/resolvers/")

        assert response.json["result"]["status"]
        assert isinstance(response.json["result"]["value"], list)

        for resolver in response.json["result"]["value"]:
            assert "realms" in resolver

    def test_resolver_controller_access(self):
        """verify that authentication is required for the resolvers controller

        * first we run an authenticated request via 'make_api_v2_request'
        * then we run an unauthenticated request via the standard client
          which will fail with status 401
        """

        # ---------------------------------------------------------------- --
        # access the resolvers api via the authenticated testing api

        response = self.make_api_v2_request("/resolvers/")

        assert response.json["result"]["status"]
        assert isinstance(response.json["result"]["value"], list)

        # ---------------------------------------------------------------- --
        # access the resolvers api with the unauthenticated testing client

        response = self.client.get("/api/v2/resolvers/")

        assert response.status_code == 401

    def test_resolvers_controller_permissions(self):
        """verify that system read permission is required to read resolvers"""
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
        # admin is only allowed to write to and to read from system

        response = self.make_api_v2_request("/resolvers/", auth_user="admin")

        assert len(response.json["result"]["value"]) == 3

        # --------------------------------------------------------------- --
        # admin2 is only allowed to read from system

        response = self.make_api_v2_request("/resolvers/", auth_user="admin2")

        assert len(response.json["result"]["value"]) == 3

        # --------------------------------------------------------------- --
        # admin3 is only allowed to write to system

        response = self.make_api_v2_request("/resolvers/", auth_user="admin3")

        assert response.status_code == 403

        # --------------------------------------------------------------- --
        # we delete the policies in the correct order, otherwise this might
        # fail

        self.delete_policy(name="admin3_write_realms", auth_user="admin")
        self.delete_policy(name="admin2_read_realms", auth_user="admin")
        self.delete_policy(name="admin_read_write_realms", auth_user="admin")

    def test_resolver_users_pagination(self):
        """
        Request the users from a resolver and ensure that the result contains a
        paginated list of users.
        """

        response = self.make_api_v2_request("/resolvers/myDefRes/users")

        assert response.json["result"]["status"]
        value = response.json["result"]["value"]
        assert isinstance(value, dict)

        assert "page" in value
        assert "pageSize" in value
        assert "totalPages" in value
        assert "pageRecords" in value

        records = value["pageRecords"]
        assert isinstance(records, list)

    def test_resolver_users_access(self):
        """verify that authentication is required for the get_users endpoint

        * first we run an authenticated request via 'make_api_v2_request'
        * then we run an unauthenticated request via the standard client
          which will fail with status 401
        """

        # ---------------------------------------------------------------- --
        # access the resolvers api via the authenticated testing api

        response = self.make_api_v2_request("/resolvers/myDefRes/users")

        assert response.json["result"]["status"]
        assert isinstance(response.json["result"]["value"], dict)

        # ---------------------------------------------------------------- --
        # access the resolvers api with the unauthenticated testing client

        response = self.client.get("/api/v2/resolvers/myDefRes/users")

        assert response.status_code == 401

    def test_resolver_users_permissions(self):
        """verify that admin/userlist permission is required to read resolvers"""

        # 'admin' has permissions to list users in all resolvers

        admin_read_write_system = {
            "name": "admin_read_write_system",
            "active": True,
            "action": "userlist",
            "user": "admin",
            "scope": "admin",
            "realm": "*",
            "time": None,
        }

        response = self.make_system_request(
            "setPolicy",
            params=admin_read_write_system,
            auth_user="admin",
        )
        assert response.json["result"]["status"]

        # create a restriction to the 'admin2' to only see myDefRealm users
        admin2_read_myDefRealm = {
            "name": "admin2_read_myDefRealm",
            "active": True,
            "action": "userlist",
            "user": "admin2",
            "scope": "admin",
            "realm": "myDefRealm",
            "time": None,
        }
        response = self.make_system_request(
            "setPolicy",
            params=admin2_read_myDefRealm,
            auth_user="admin",
        )
        assert response.json["result"]["status"]

        # create a restriction to the 'admin3' to only see myOtherRealm users
        admin3_read_myOtherRealm = {
            "name": "admin3_read_myOtherRealm",
            "active": True,
            "action": "userlist",
            "user": "admin3",
            "scope": "admin",
            "realm": "myOtherRealm",
            "time": None,
        }
        response = self.make_system_request(
            "setPolicy",
            params=admin3_read_myOtherRealm,
            auth_user="admin",
        )
        assert response.json["result"]["status"]

        # admin can list users from both resolvers
        response = self.make_api_v2_request(
            "/resolvers/myDefRes/users", auth_user="admin"
        )
        myDefUsers = response.json["result"]["value"]["pageRecords"]
        assert len(myDefUsers) == 27

        response = self.make_api_v2_request(
            "/resolvers/myOtherRes/users", auth_user="admin"
        )
        myOtherUsers = response.json["result"]["value"]["pageRecords"]
        assert len(myOtherUsers) == 8

        # --------------------------------------------------------------- --
        # admin2 is only allowed to list users from myDefRes

        response = self.make_api_v2_request(
            "/resolvers/myDefRes/users", auth_user="admin2"
        )
        myDefUsers = response.json["result"]["value"]["pageRecords"]
        assert len(myDefUsers) == 27

        response = self.make_api_v2_request(
            "/resolvers/myOtherRes/users", auth_user="admin2"
        )

        assert not response.json["result"]["status"]
        assert response.status_code == 403

        # --------------------------------------------------------------- --
        # admin3 is only allowed to list users from myOtherRes

        response = self.make_api_v2_request(
            "/resolvers/myDefRes/users", auth_user="admin3"
        )
        assert not response.json["result"]["status"]
        assert response.status_code == 403

        response = self.make_api_v2_request(
            "/resolvers/myOtherRes/users", auth_user="admin3"
        )
        myOtherUsers = response.json["result"]["value"]["pageRecords"]
        assert len(myOtherUsers) == 8

        # --------------------------------------------------------------- --
        # we delete the policies in the correct order, otherwise this might
        # fail

        self.delete_policy(name="admin3_read_myOtherRealm", auth_user="admin")
        self.delete_policy(name="admin2_read_myDefRealm", auth_user="admin")
        self.delete_policy(name="admin_read_write_system", auth_user="admin")

    def test_users_of_resolver_not_in_realm(self):
        """
        Verify that an admin can check the users within a resolver that is not
        in a realm, as long as they have userlist permissions implicitly due to
        no admin policy being specified, or explicit permissions to list users
        in all realms.
        """
        # set only myOtherRes as the resolver of both myDefRealm and myMixRealm,
        # so that myDefResolver is not in any realm.
        response = self.make_system_request(
            "setRealm",
            params={
                "realm": "myDefRealm",
                "resolvers": "useridresolver.PasswdIdResolver.IdResolver.myOtherRes",
            },
            auth_user="admin",
        )
        assert response.json["result"]["status"]
        response = self.make_system_request(
            "setRealm",
            params={
                "realm": "myMixRealm",
                "resolvers": "useridresolver.PasswdIdResolver.IdResolver.myOtherRes",
            },
            auth_user="admin",
        )
        assert response.json["result"]["status"]

        # admin can list users from all resolvers implicitly, as no policy has
        # been set in the admin scope
        response = self.make_api_v2_request(
            "/resolvers/myDefRes/users", auth_user="admin"
        )
        myDefUsers = response.json["result"]["value"]["pageRecords"]
        assert len(myDefUsers) == 27

        # 'admin' has explicit permissions to list users in all resolvers

        admin_read_write_system = {
            "name": "admin_read_write_system",
            "active": True,
            "action": "userlist",
            "user": "admin",
            "scope": "admin",
            "realm": "*",
            "time": None,
        }

        response = self.make_system_request(
            "setPolicy",
            params=admin_read_write_system,
            auth_user="admin",
        )
        assert response.json["result"]["status"]

        # admin can list users from both resolvers
        response = self.make_api_v2_request(
            "/resolvers/myDefRes/users", auth_user="admin"
        )
        myDefUsers = response.json["result"]["value"]["pageRecords"]
        assert len(myDefUsers) == 27

        # --------------------------------------------------------------- --
        # we delete the policies in the correct order, otherwise this might
        # fail

        self.delete_policy(name="admin_read_write_system", auth_user="admin")

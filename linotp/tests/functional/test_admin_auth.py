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
Test the support for resolver definitions in system or admin policy user entry
"""

import base64
import logging
import os

import pytest

from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestAdminAuthController(TestController):
    def setUp(self):
        TestController.setUp(self)
        # clean setup
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        # create the common resolvers and realm
        self.create_common_resolvers()
        self.create_common_realms()
        self.create_extra_resolver()

    def tearDown(self):
        TestController.tearDown(self)
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

    def create_extra_resolver(self):
        resolver_params = {
            "adminResolver": {
                "name": "adminResolver",
                "fileName": os.path.join(self.fixture_path, "admin-passwd"),
                "type": "passwdresolver",
            },
        }
        self.resolvers = {
            "adminResolver": (
                "useridresolver.PasswdIdResolver.IdResolver.adminResolver"
            ),
        }
        params = resolver_params["adminResolver"]
        response = self.create_resolver(name="adminResolver", params=params)
        assert response.json["result"]["status"] == True, response

    def createPolicy(self, param=None):
        policy = {
            "name": "admin01",
            "scope": "admin",
        }

        # overwrite the default defintion
        policy.update(param)

        resp_dict = "setPolicy %s" % policy["name"]

        response = self.make_system_request("setPolicy", params=policy)
        assert response.json["result"]["status"] == True, response
        assert isinstance(
            response.json["result"]["value"][resp_dict], dict
        ), "expected policy to have been set and details returned."

    def test_admin_show(self):
        """
        Ensure that admin policy show can be limited to
        1-specific users,
        2-users of specific resolvers,
        3-or matched by regular expression
        """
        self.createPolicy(
            {
                "realm": "myOtherRealm",
                "action": "userlist, show",
                "user": "admin, adminResolver:, *@virtRealm",
            }
        )

        action = "show"

        # simple match - backward compatible
        response = self.make_admin_request(action, auth_user="admin")
        assert response.json["result"]["status"] == True, response

        # pattern match for domain
        response = self.make_admin_request(action, auth_user="root@virtRealm")
        assert response.json["result"]["status"] == True, response

        # existent user in resolver
        response = self.make_admin_request(action, auth_user="root@adomain")
        assert response.json["result"]["status"] == True, response

        # non existent user in resolver
        response = self.make_admin_request(action, auth_user="toor@adomain")
        assert response.json["result"]["status"] == False, response

    def test_admin_resolver_and_domain(self):
        """
        This test sets the policy for action:userlist and verifies it against users with
        1-exact match
        2-domain match (pattern match)
        3- a user from an allowed resolver can use it. (note: an allowed resolver is
        presented in the user field of policy with semicolon after the name of the resolver)
        4- It also checks that a user who does not exist in the resolver, can
        not access the functionality.
        """
        self.createPolicy(
            {
                "realm": "*",
                "action": "userlist, ",
                "user": "admin, adminResolver:, *@virtRealm",
            }
        )

        action = "userlist"

        # simple match - backward compatible
        response = self.make_admin_request(action, auth_user="admin")
        assert response.json["result"]["status"] == True, response

        # pattern match for domain
        response = self.make_admin_request(action, auth_user="root@virtRealm")
        assert response.json["result"]["status"] == True, response

        # existent user in resolver 'adminResolver'
        response = self.make_admin_request(action, auth_user="root@adomain")
        assert response.json["result"]["status"] == True, response

        # non existent user in resolver
        response = self.make_admin_request(action, auth_user="toor@adomain")
        assert response.json["result"]["status"] == False, response

    def test_admin_username_regex_and_domain(self):
        """
        TODO: add test description:
        """
        self.createPolicy(
            {
                "realm": "*",
                "action": "userlist, ",
                "user": "admin, adminResolver:,.*oo.*@virtRealm",
            }
        )

        action = "userlist"

        # simple match - backward compatible
        response = self.make_admin_request(action, auth_user="admin")
        assert response.json["result"]["status"] == True, response

        # pattern match for domain
        response = self.make_admin_request(action, auth_user="root@virtRealm")
        assert response.json["result"]["status"] == True, response

        # existance test in resolver
        response = self.make_admin_request(action, auth_user="rotot@virtRealm")
        assert response.json["result"]["status"] == False, response

        # non existance test in resolver
        response = self.make_admin_request(action, auth_user="toor@virtRealm")
        assert response.json["result"]["status"] == True, response

    def test_admin_action_wildcard(self):
        """
        TODO: add test description
        """
        userview_parameters = {
            "page": "1",
            "rp": "15",
            "sortname": "username",
            "sortorder": "asc",
            "query": "",
            "qtype": "username",
            "realm": "myDefRealm",
        }
        userlist_parameters = {
            "username": "*",
            "realm": "myDefRealm",
        }

        # Test 1: TODO: What is tested here?

        self.createPolicy(
            {
                "realm": "*",
                "action": "userlist, ",
                "user": "admin, adminResolver:, *@virtRealm",
            }
        )

        response = self.make_manage_request(
            "userview_flexi", params=userview_parameters, auth_user="admin"
        )
        assert response.json["result"]["value"]["page"] == 1, response
        assert isinstance(response.json["result"]["value"]["rows"], list)

        # Test 2: TODO: What is tested here?

        self.createPolicy(
            {
                "realm": "myDefRealm",
                "action": "show, *, userlist",
                "user": "admin, adminResolver:, *@virtRealm",
            }
        )

        response = self.make_admin_request(
            "userlist", params=userlist_parameters, auth_user="admin"
        )
        assert response.json["result"]["status"] == True, response

        response = self.make_manage_request(
            "userview_flexi", params=userview_parameters, auth_user="admin"
        )
        assert response.json["result"]["value"]["page"] == 1, response
        assert isinstance(response.json["result"]["value"]["rows"], list)

        # Test 3: TODO: What is tested here?

        self.createPolicy(
            {
                "realm": "myDefRealm",
                "action": "userlist, *",
                "user": "admin, adminResolver:, *@virtRealm",
            }
        )

        response = self.make_admin_request(
            "userlist", params=userlist_parameters, auth_user="admin"
        )
        assert response.json["result"]["status"] == True, response

        response = self.make_manage_request(
            "userview_flexi", params=userview_parameters, auth_user="admin"
        )
        assert response.json["result"]["value"]["page"] == 1, response
        assert isinstance(response.json["result"]["value"]["rows"], list)

    def test_system_auth_policy_match(self):
        """
        System Authorization: check if correct policies are matched if multiple policies exist
        """
        self.createPolicy(
            {
                "name": "sys_super",
                "scope": "system",
                "realm": "*",
                "action": "read, write",
                "user": "superadmin, adminResolver:, *@virtRealm",
            }
        )

        self.createPolicy(
            {
                "name": "sys_auth",
                "scope": "system",
                "realm": "*",
                "action": "read",
                "user": "seconduser",
            }
        )

        # ALl users that are matched with policy 'sys_super'
        # should be allowed to write system config

        params = {"testKey": "testVal"}
        response = self.make_system_request(
            "setConfig", params=params, auth_user="root@virtRealm"
        )
        assert response.json["result"]["status"] == True, response

        params = {"testKey": "testVal"}
        response = self.make_system_request(
            "setConfig", params=params, auth_user="root@adomain"
        )
        assert response.json["result"]["status"] == True, response

        # now do the test on setConfig
        params = {"testKey": "testVal"}
        response = self.make_system_request(
            "setConfig", params=params, auth_user="superadmin"
        )
        assert response.json["result"]["status"] == True, response

        # The user 'seconduser' should only be matched by the policy 'sys_auth'
        # and therefore is not allowed to write system config

        params = {"testKey": "testVal"}
        response = self.make_system_request(
            "setConfig", params=params, auth_user="seconduser"
        )
        assert (
            "Policy check failed. You are not "
            "allowed to write system config."
            in response.json["result"]["error"]["message"]
        ), response

    @pytest.mark.skip(reason="in developement")
    def test_system_auth_inheritance(self):
        """
        System Authorization: check if admin@example.com is matched with the regex or direct match
        """
        self.createPolicy(
            {
                "name": "sys_super",
                "scope": "system",
                "realm": "*",
                "action": "read, write",
                "user": "superadmin, adminResolver:, *@virtRealm, *@example",
            }
        )

        self.createPolicy(
            {
                "name": "sys_auth",
                "scope": "system",
                "realm": "*",
                "action": "read",
                "user": "admin@example",
            }
        )

        # Users of the example.com domain that are not admin@example.com
        # are allowed to write system config

        params = {"testKey": "testVal"}
        response = self.make_system_request(
            "setConfig", params=params, auth_user="foo@example.com"
        )
        assert response.json["result"]["status"] == True, response

        # Users that are not part of the example.com domain are not
        # allowed to write system config

        params = {"testKey": "testVal"}
        response = self.make_system_request(
            "setConfig", params=params, auth_user="foo@whatever"
        )
        assert (
            "Policy check failed. You are not "
            "allowed to write system config."
            in response.json["result"]["error"]["message"]
        ), response

        # The user admin@example.com is matching both policies, but because
        # the action 'write' is only part of the policy 'sys_super', the
        # 'direct user match' of policy 'sys_auth' is not revoking the 'write'
        # action of the policy 'sys_super' that is only a 'regex user match'.
        # This is according to the policy priority evaluation in 'lib/policy/evaluate.py'.

        params = {"testKey": "testVal"}
        response = self.make_system_request(
            "setConfig", params=params, auth_user="admin@example.com"
        )
        assert response.json["result"]["status"] == True, response

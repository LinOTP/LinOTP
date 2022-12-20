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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

from linotp.tests import TestController


class TestUserserviceDescriptionTest(TestController):
    """
    support userservice api to set token description
    """

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

    def tearDown(self):
        TestController.tearDown(self)

    def test_set_description(self):
        """
        verify userservice set description api

        0. setup policies
        1. enroll hmac token
        2a. user cannot set description
        2b. user cannot set empty description
        3. extend policies to allow setDescription
        4. user can set description of this token
        5. verify that description is set

        """
        # common setting

        user = "passthru_user1@myDefRealm"

        auth_user = {"login": user, "password": "geheim1"}

        # ------------------------------------------------------------------ --

        # 0. setup policies

        policy = {
            "name": "T1",
            "action": "enrollHMAC, ",
            "user": " passthru.*.myDefRes:",
            "realm": "*",
            "scope": "selfservice",
        }
        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        # ------------------------------------------------------------------ --

        # 1. enroll hmac token

        params = {"type": "hmac", "genkey": 1}

        response = self.make_userselfservice_request(
            "enroll", params, auth_user=auth_user, new_auth_cookie=True
        )

        assert "detail" in response, response
        serial = response.json["detail"]["serial"]

        # ------------------------------------------------------------------ --

        # 2a. user cannot set description for this token -
        #     no description setting policy is defined

        params = {"serial": serial, "description": "this is my token"}

        response = self.make_userselfservice_request(
            "setdescription",
            params=params,
            auth_user=auth_user,
            new_auth_cookie=True,
        )
        assert "The policy settings do not allow you to" in response, response

        # ------------------------------------------------------------------ --

        # 2b. user cannot set empty description for this token -
        #     no description setting policy is defined

        params = {"serial": serial, "description": ""}

        response = self.make_userselfservice_request(
            "setdescription",
            params=params,
            auth_user=auth_user,
            new_auth_cookie=True,
        )
        assert "The policy settings do not allow you to" in response, response

        # ------------------------------------------------------------------ --

        # 3. extend policies to allow setDescription

        policy = {
            "name": "T1",
            "action": "enrollHMAC, setDescription",
            "user": " passthru.*.myDefRes:",
            "realm": "*",
            "scope": "selfservice",
        }
        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        # ------------------------------------------------------------------ --

        # 4. user can set description of this token

        params = {"serial": serial, "description": "this is my token"}

        response = self.make_userselfservice_request(
            "setdescription",
            params=params,
            auth_user=auth_user,
            new_auth_cookie=True,
        )

        assert "false" not in response, response

        # ------------------------------------------------------------------ --

        # 5. verify that description is set

        params = {"serial": serial}

        response = self.make_admin_request("show", params)
        assert "this is my token" in response, response

    def test_assign_with_description(self):
        """
        verify token assignment including description

        0. setup policies
        1. admin enroll token
        2. assign token with description
        3. verify that descrption is set

        """

        # ------------------------------------------------------------------ --

        # common settings

        user = "passthru_user1@myDefRealm"

        auth_user = {"login": user, "password": "geheim1"}

        # ------------------------------------------------------------------ --

        # 0. setup policies

        policy = {
            "name": "T1",
            "action": "enrollHMAC, assign",
            "user": " passthru.*.myDefRes:",
            "realm": "*",
            "scope": "selfservice",
        }
        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        # ------------------------------------------------------------------ --

        # 1. enroll hmac token

        serial = "myHmac"

        params = {"serial": serial, "genkey": 1}

        response = self.make_admin_request("init", params)
        assert "detail" in response, response

        # ------------------------------------------------------------------ --

        # 2. user can assign this token, setting description is allowed
        # implicit

        params = {"serial": serial, "description": "this is my token"}

        response = self.make_userselfservice_request(
            "assign", params=params, auth_user=auth_user, new_auth_cookie=True
        )
        assert "false" not in response, response

        # ------------------------------------------------------------------ --

        # 3. verify that description is set

        params = {"serial": serial}

        response = self.make_admin_request("show", params)
        assert "this is my token" in response, response

    def test_webprovision_with_description(self):
        """
        verify token webprovision including description

        0. setup policies
        1. webprovision token with token
        2. verify that description is set

        """

        # ------------------------------------------------------------------ --

        # common settings

        user = "passthru_user1@myDefRealm"

        auth_user = {"login": user, "password": "geheim1"}

        # ------------------------------------------------------------------ --

        # 0. setup policies

        policy = {
            "name": "T1",
            "action": "webprovisionOATH, webprovisionGOOGLEtime, webprovisionGOOGLE",
            "user": " passthru.*.myDefRes:",
            "realm": "*",
            "scope": "selfservice",
        }
        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        # ------------------------------------------------------------------ --

        token_types = [
            "oathtoken",
            "googleauthenticator_time",
            "googleauthenticator",
        ]

        for token_type in token_types:

            # 1. enroll oathtoken token

            description = "my %s" % token_type

            params = {"type": token_type, "description": description}

            response = self.make_userselfservice_request(
                "webprovision",
                params=params,
                auth_user=auth_user,
                new_auth_cookie=True,
            )

            assert "oathtoken" in response, response
            serial = response.json["result"]["value"]["oathtoken"]["serial"]

            # ------------------------------------------------------------------ --

            # 2. verify that description is set

            params = {"serial": serial}

            response = self.make_admin_request("show", params)
            assert description in response, response


# eof

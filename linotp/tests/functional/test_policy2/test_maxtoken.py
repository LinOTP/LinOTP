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
Test the maxtoken Policy.
"""


from linotp.tests import TestController


class TestPolicyMaxtoken(TestController):
    """
    Test the admin show Policy.
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

    def enroll_token(self, token_params=None):
        parameters = {
            "serial": "003e808e",
            "otpkey": "e56eb2bcbafb2eea9bce9463f550f86d587d6c71",
            "description": "myToken",
        }
        if token_params:
            parameters.update(token_params)

        response = self.make_admin_request("init", params=parameters)
        return response

    def test_maxtoken_assign(self):
        """
        test maxtoken check for multiple same user in realm and user wildcard

        the maxtoken could happen in two cases - during init and during assign

        """
        policy = {
            "name": "maxtoken",
            "realm": "*",
            "active": "True",
            "client": "",
            "user": "*",
            "time": "",
            "action": "maxtoken=2, ",
            "scope": "enrollment",
        }

        self.create_policy(policy)

        for i in range(1, 4):
            token_params = {
                "serial": "#TCOUNT%d" % i,
            }
            response = self.enroll_token(token_params)
            assert "#TCOUNT%d" % i in response

        for i in range(1, 3):
            params = {"serial": "#TCOUNT%d" % i, "user": "def"}
            response = self.make_admin_request("assign", params=params)
            assert '"value": true' in response, response

        i = 3
        params = {"serial": "#TCOUNT%d" % i, "user": "def"}
        response = self.make_admin_request("assign", params=params)
        message = "ERR411: The maximum number of allowed tokens"
        assert message in response, response

        return

    def test_maxtoken_enroll(self):
        """
        test maxtoken check for multiple same user in realm and user wildcard

        the maxtoken could happen in two cases - during init and during assign

        """
        policy = {
            "name": "maxtoken",
            "realm": "*",
            "active": "True",
            "client": "",
            "user": "*",
            "time": "",
            "action": "maxtoken=2, ",
            "scope": "enrollment",
        }

        response = self.create_policy(policy)

        for i in range(1, 3):
            token_params = {"serial": "#TCOUNT%d" % i, "user": "def"}
            response = self.enroll_token(token_params)
            assert "#TCOUNT%d" % i in response

        i = 3
        token_params = {"serial": "#TCOUNT%d" % i, "user": "def"}
        response = self.enroll_token(token_params)
        message = (
            "ERR411: The maximum number of allowed tokens per user "
            "is exceeded"
        )
        assert message in response, response

        return

    def test_maxtoken_selfservice(self):
        """
        verify the maxtoken policy in the selfservice scope

        policies: overall allowed is 4, max email is 2, max hmac is 1

        enrollment tests:

        1. enroll email - ok
        2. enroll hmac - ok
        3. enroll hmac - fail, only one hmac allowed
        4. enroll email - ok
        5. enroll email - no more email token allowed
        6. enroll sms - ok, the 4th token
        7. enroll sms - fail, more than 4 token

        assignment tests

        8. admin creates hmac token
        9. assign - fail, due to total token limit
        10. admin removes one sms token
        11. assign - fail, due to hmac token limit
        12. admin removes old hmac token
        13. assign - ok

        """

        policy = {
            "name": "maxtoken",
            "realm": "*",
            "active": "True",
            "client": "",
            "user": "*",
            "time": "",
            "action": "maxtoken=4, maxtokenEMAIL=2, maxtokenHMAC=1 ",
            "scope": "enrollment",
        }

        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response

        policy = {
            "name": "T1",
            "action": (
                "enrollEMAIL, enrollSMS, assign, "
                "webprovisionGOOGLE, webprovisionGOOGLEtime, "
            ),
            "user": " passthru.*.myDefRes:",
            "realm": "*",
            "scope": "selfservice",
        }
        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        # 1. enroll email - ok

        user = "passthru_user1@myDefRealm"
        pin = "123"

        auth_user = {"login": user, "password": "geheim1"}

        params = {
            "type": "email",
            "email_address": "test@example.net",
            "pin": pin,
        }
        response = self.make_userselfservice_request(
            "enroll", params=params, auth_user=auth_user, new_auth_cookie=True
        )

        assert "detail" in response, response

        # 2. enroll hmac - ok

        params = {"type": "googleauthenticator", "serial": "myGoo"}
        response = self.make_userselfservice_request(
            "webprovision",
            params=params,
            auth_user=auth_user,
            new_auth_cookie=True,
        )

        assert "oathtoken" in response, response

        # 3. enroll hmac - fail, only one hmac allowed

        params = {
            "type": "googleauthenticator",
        }
        response = self.make_userselfservice_request(
            "webprovision",
            params=params,
            auth_user=auth_user,
            new_auth_cookie=True,
        )

        assert "The maximum number of allowed tokens" in response, response

        # 4. enroll email - ok

        params = {
            "type": "email",
            "email_address": "test@example.net",
            "pin": pin,
        }
        response = self.make_userselfservice_request(
            "enroll", params=params, auth_user=auth_user, new_auth_cookie=True
        )

        assert "detail" in response, response

        # 5. enroll email - no more email token allowed

        params = {
            "type": "email",
            "email_address": "test@example.net",
            "pin": pin,
        }
        response = self.make_userselfservice_request(
            "enroll", params=params, auth_user=auth_user, new_auth_cookie=True
        )

        assert "allowed tokens of type email" in response, response

        # 6. enroll sms - ok, the 4th token

        params = {
            "type": "sms",
            "phone": "1234456",
            "pin": pin,
            "serial": "mysms",
        }
        response = self.make_userselfservice_request(
            "enroll", params=params, auth_user=auth_user, new_auth_cookie=True
        )

        assert "detail" in response, response

        # 7. enroll sms - fail, more than 4 token

        params = {"type": "sms", "phone": "1234456", "pin": pin}
        response = self.make_userselfservice_request(
            "enroll", params=params, auth_user=auth_user, new_auth_cookie=True
        )

        assert "The maximum number of allowed tokens" in response, response

        # ------------------------------------------------------------------ --

        # assignment tests

        # 8. admin creates hmac token

        params = {"genkey": 1, "serial": "myHmac"}
        response = self.make_admin_request("init", params=params)

        assert "false" not in response

        # 9. assign - fail, due to total token limit

        params = {
            "serial": "myHmac",
        }
        response = self.make_userselfservice_request(
            "assign", params=params, auth_user=auth_user, new_auth_cookie=True
        )

        assert "The maximum number of allowed tokens" in response, response

        # 10. admin removes one sms token

        params = {"serial": "mysms"}
        response = self.make_admin_request("remove", params=params)

        assert "false" not in response

        # 11. assign - fail, due to hmac token limit

        params = {
            "serial": "myHmac",
        }
        response = self.make_userselfservice_request(
            "assign", params=params, auth_user=auth_user, new_auth_cookie=True
        )

        assert "allowed tokens of type hmac per user" in response, response

        # 12. admin removes old hmac token

        params = {"serial": "myGoo"}
        response = self.make_admin_request("remove", params=params)

        assert "false" not in response

        # 13. assign - ok

        params = {
            "serial": "myHmac",
        }
        response = self.make_userselfservice_request(
            "assign", params=params, auth_user=auth_user, new_auth_cookie=True
        )

        assert "false" not in response, response


class TestMaxtokenSelfService(TestController):
    """
    Test the maxtoken info in context of selfservice
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

    def enroll_token(self, token_params=None):
        parameters = {
            "otpkey": "e56eb2bcbafb2eea9bce9463f550f86d587d6c71",
            "description": "myToken",
        }
        if token_params:
            parameters.update(token_params)

        response = self.make_admin_request("init", params=parameters)
        return response

    def test_all_token_limits_set(self):
        policy = {
            "name": "maxtoken",
            "realm": "*",
            "active": "True",
            "client": "",
            "user": "*",
            "time": "",
            "action": "maxtoken=4, ",
            "scope": "enrollment",
        }

        self.create_policy(policy)

        for i in range(1, 4):
            token_params = {
                "serial": "#TCOUNT%d" % i,
                "user": "passthru_user1@myDefRealm",
            }
            self.enroll_token(token_params)

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
        }

        response = self.make_userselfservice_request(
            "context", auth_user=auth_user
        )

        all_token_limits = response.json["detail"]["settings"]["token_limits"][
            "all_token"
        ]
        assert all_token_limits == 4

    def test_all_token_limits_not_set(self):
        for i in range(1, 4):
            token_params = {
                "serial": "#TCOUNT%d" % i,
                "user": "passthru_user1@myDefRealm",
            }
            self.enroll_token(token_params)

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
        }

        response = self.make_userselfservice_request(
            "context", auth_user=auth_user
        )

        all_token_limits = response.json["detail"]["settings"]["token_limits"][
            "all_token"
        ]
        assert all_token_limits is None

    def test_token_limit_pro_type(self):
        policy = {
            "name": "maxtoken_for_type",
            "realm": "*",
            "active": "True",
            "client": "",
            "user": "*",
            "time": "",
            "action": "maxtoken=5, maxtokenPW=3",
            "scope": "enrollment",
        }

        self.create_policy(policy)

        for i in range(1, 4):
            token_params = {
                "serial": "#TCOUNT%d" % i,
                "type": "pw",
                "user": "passthru_user1@myDefRealm",
            }
            self.enroll_token(token_params)

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
        }

        response = self.make_userselfservice_request(
            "context", auth_user=auth_user
        )

        token_limit_res = response.json["detail"]["settings"]["token_limits"][
            "token_types"
        ]
        assert len(token_limit_res) == 1
        token_limit = token_limit_res[0]
        assert token_limit["max_token"] == 3
        assert token_limit["token_type"] == "pw"

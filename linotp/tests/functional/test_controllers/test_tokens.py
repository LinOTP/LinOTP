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


class TestTokens(TestController):
    """
    test the search on a token list
    """

    serials = []
    policies = []

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
        return

    def _create_pw_tokens(
        self, username="horst", realm="mydefrealm", amount_of_users=1
    ):
        for i in range(amount_of_users):
            serial = f"PWToken-{username}-{realm}-{i}"
            params = {
                "type": "pw",
                "otpkey": "geheim1",
                "user": username,
                "realm": realm,
                "serial": serial,
            }
            response = self.make_admin_request("init", params=params)
            result = response.json["result"]
            assert result["status"]
            assert result["value"]

            self.serials.append(serial)

    def test_tokens_controller_access(self):
        """verify that authentication is required for the tokens controller

        * first we run an authenticated request via 'make_api_v2_request'
        * then we run an unauthenticated request via the standard client
          which will fail with status 401
        """

        # ---------------------------------------------------------------- --
        # access the tokens api via the authenticated testing api

        response = self.make_api_v2_request("/tokens/")

        assert response.json["result"]["status"]
        assert isinstance(response.json["result"]["value"]["pageRecords"], list)

        # ---------------------------------------------------------------- --
        # access the tokens api with the unauthenticated testing client

        response = self.client.get("/api/v2/tokens/")

        assert response.status_code == 401

    def test_tokens_controller_permissions(self):
        """admin can see only the tokens which he is allowed to see

        * first create 2 tokens for two users which belong to different realms
        * establish the policy which allows our standard 'admin' user to
          view only tokens of the 'mydefrealm' realm
        * verify that in the result list only tokens are included which the
          user 'admin' is allowed to see
        """

        # --------------------------------------------------------------- --
        # create some tokens belonging to different realms

        users = [("horst", "mydefrealm"), ("other_user", "myotherrealm")]
        for user, realm in users:
            self._create_pw_tokens(username=f"{user}", realm=realm)

        # --------------------------------------------------------------- --
        # create a restriction to the 'admin' to only see myDefRealm tokens

        admin_policy = {
            "name": "amin_read_tokens",
            "active": True,
            "action": "show",
            "user": "admin",
            "scope": "admin",
            "realm": "myDefRealm",
            "time": None,
        }

        response = self.make_system_request(
            "setPolicy",
            params=admin_policy,
            auth_user="admin",
        )

        assert response.json["result"]["status"]

        # --------------------------------------------------------------- --
        # verify that the access to tokens is restricet to
        # the policy defined realm

        response = self.make_api_v2_request("/tokens/")

        assert len(response.json["result"]["value"]["pageRecords"]) == 1
        token = response.json["result"]["value"]["pageRecords"][0]
        assert token["serial"] == "PWToken-horst-mydefrealm-0"

        # test realm filtering
        params = {"realm": "mymixrealm"}
        response = self.make_api_v2_request("/tokens/", params=params)
        assert response.status_code == 403

        params = {"realm": "NON_EXISTING_REALM"}
        response = self.make_api_v2_request("/tokens/", params=params)
        assert response.status_code == 403

        params = {"realm": "mydefrealm"}
        response = self.make_api_v2_request("/tokens/", params=params)
        assert len(response.json["result"]["value"]["pageRecords"]) == 1

    def test_tokens_controller_no_permissions(self):
        """'admin' is not allowed to view any token

        * establish the policy which allows our standard 'admin' user to
          not see any token
        * verify that in the result list only tokens are included which the
          user 'admin' is allowed to see
        """

        # --------------------------------------------------------------- --
        # create a restriction to the 'admin' to not see any tokens

        admin_policy = {
            "name": "amin_not_allowed_to_read_tokens",
            "active": True,
            "action": "initHMAC",
            "user": "admin",
            "scope": "admin",
            "realm": "myDefRealm",
            "time": None,
        }

        response = self.make_system_request(
            "setPolicy",
            params=admin_policy,
            auth_user="admin",
        )

        assert response.json["result"]["status"]

        # --------------------------------------------------------------- --
        # verify that the access to tokens is restriced by the admin/show
        # policy - if not allowed we get an 403 - forbidden

        response = self.make_api_v2_request("/tokens/", auth_user="nimda")
        assert response.status_code == 403

    def test_tokens_controller_pagination(self):
        """verify /api/v2/tokens response is paginated

        we create a set of 40 users which should be paginated.
        we verify that the pagination starts with 0 and that we can
        step through the pages

        TODO:
        sortOrder does not work by now - might be a problem
        of the old code in the TokenIterator
        """
        self._create_pw_tokens(amount_of_users=40)

        response = self.make_api_v2_request("/tokens/")

        assert response.json["result"]["status"]
        assert isinstance(response.json["result"]["value"]["pageRecords"], list)
        assert response.json["result"]["value"]["page"] == 0
        assert response.json["result"]["value"]["pageSize"] == 50
        assert response.json["result"]["value"]["totalPages"] == 1
        assert response.json["result"]["value"]["totalRecords"] == 40

        params = {"page": "3", "pageSize": "10", "sortOrder": "desc"}
        response = self.make_api_v2_request("/tokens/", params=params)

        assert response.json["result"]["status"]
        assert response.json["result"]["value"]["page"] == 3
        assert response.json["result"]["value"]["pageSize"] == 10
        assert response.json["result"]["value"]["totalPages"] == 4
        assert response.json["result"]["value"]["totalRecords"] == 40

    def test_tokens_controller_default_pagination(self):
        """verify /api/v2/tokens response is paginated

        We create a set of 60 users which should be paginated. Then we request
        the users without setting page and and pageSize. The system's default
        (50) number of tokens should be returned.

        Then we send a request with pageSize set to zero. All tokens should be
        returned.

        """
        self._create_pw_tokens(amount_of_users=60)

        response = self.make_api_v2_request("/tokens/")

        assert response.json["result"]["status"]
        assert response.json["result"]["value"]["page"] == 0
        assert response.json["result"]["value"]["pageSize"] == 50
        assert response.json["result"]["value"]["totalPages"] == 2
        assert response.json["result"]["value"]["totalRecords"] == 60
        assert len(response.json["result"]["value"]["pageRecords"]) == 50

        params = {"pageSize": "0"}
        response = self.make_api_v2_request("/tokens/", params=params)

        assert response.json["result"]["status"]
        assert response.json["result"]["value"]["page"] == 0
        assert response.json["result"]["value"]["pageSize"] == 60
        assert response.json["result"]["value"]["totalPages"] == 1
        assert response.json["result"]["value"]["totalRecords"] == 60
        assert len(response.json["result"]["value"]["pageRecords"]) == 60

    def test_get_token_by_serial_authentication(self):
        """access by serial to a not existing token"""

        # ---------------------------------------------------------------- --
        # access the tokens api via the authenticated testing api -
        # accessin an non existing token

        response = self.make_api_v2_request("/tokens/1234")

        assert response.json["result"]["status"]
        assert isinstance(response.json["result"]["value"], dict)

        # ---------------------------------------------------------------- --
        # access the tokens api with the unauthenticated testing client

        response = self.client.get("/api/v2/tokens/")

        assert response.status_code == 401

    def test_get_token_by_serial_authorisation(self):
        """verify that the user must be authorized to view the token"""

        # --------------------------------------------------------------- --
        # create some tokens belonging to different realms

        users = [("horst", "mydefrealm"), ("other_user", "myotherrealm")]
        for user, realm in users:
            self._create_pw_tokens(username=user, realm=realm)

        # --------------------------------------------------------------- --
        # create a restriction to the 'admin' to only see myDefRealm tokens

        admin_policy = {
            "name": "amin_read_tokens",
            "active": True,
            "action": "show",
            "user": "admin",
            "scope": "admin",
            "realm": "myDefRealm",
            "time": None,
        }

        response = self.make_system_request(
            "setPolicy",
            params=admin_policy,
            auth_user="admin",
        )

        assert response.json["result"]["status"]

        # --------------------------------------------------------------- --
        # verify that the access to tokens is restricet to
        # the policy defined realm

        serial = f"PWToken-{users[0][0]}-{users[0][1]}-0"

        response = self.make_api_v2_request(f"/tokens/{serial}")

        assert response.json["result"]["status"]
        assert response.json["result"]["value"]["serial"] == serial

        serial = f"PWToken-{users[1][0]}-{users[1][1]}-0"

        response = self.make_api_v2_request(f"/tokens/{serial}")

        assert response.json["result"]["status"]
        assert "serial" not in response.json["result"]["value"]

    def test_tokens_controller_filter_realm(self):
        """verify /api/v2/tokens can be filtered by user"""

        users = [("horst", "mydefrealm"), ("beckett", "mymixrealm")]
        for user, realm in users:
            self._create_pw_tokens(username=user, realm=realm)

        # exact search
        params = {"realm": "mydefrealm"}
        response = self.make_api_v2_request("/tokens/", params=params)
        result = response.json["result"]
        assert result["value"]["totalRecords"] == 1

        # wildcard search
        params = {"realm": "mymix*"}
        response = self.make_api_v2_request("/tokens/", params=params)
        result = response.json["result"]
        assert result["value"]["totalRecords"] == 1

        params = {"realm": "my*realm"}
        response = self.make_api_v2_request("/tokens/", params=params)
        result = response.json["result"]
        assert result["value"]["totalRecords"] == 2

        params = {"realm": "NON_EXISTING_REALM"}
        response = self.make_api_v2_request("/tokens/", params=params)
        result = response.json["result"]
        assert result["value"]["totalRecords"] == 0

    def test_tokens_controller_filter_user(self):
        """verify /api/v2/tokens can be filtered by user"""

        users_and_amount = [("horst", 5), ("beckett", 7)]
        for user, amount in users_and_amount:
            self._create_pw_tokens(username=user, amount_of_users=amount)

        # exact search
        params = {"username": "horst"}
        response = self.make_api_v2_request("/tokens/", params=params)
        result = response.json["result"]
        assert result["value"]["totalRecords"] == users_and_amount[0][1]

        # wildcard search
        params = {"username": "beck*"}
        response = self.make_api_v2_request("/tokens/", params=params)
        result = response.json["result"]
        assert result["value"]["totalRecords"] == users_and_amount[1][1]

        params = {"username": "*t"}
        response = self.make_api_v2_request("/tokens/", params=params)
        result = response.json["result"]
        assert (
            result["value"]["totalRecords"]
            == users_and_amount[0][1] + users_and_amount[1][1]
        )

        # filter user with realm
        params = {"username": "horst", "realm": "mydefrealm"}
        response = self.make_api_v2_request("/tokens/", params=params)
        result = response.json["result"]
        assert result["value"]["totalRecords"] == users_and_amount[0][1]

        params = {"username": "horst", "realm": "NON_EXISTING_REALM"}
        response = self.make_api_v2_request("/tokens/", params=params)
        result = response.json["result"]
        assert result["value"]["totalRecords"] == 0


# eof #

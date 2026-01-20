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
Test the tokencount Policy.
"""

from linotp.tests import TestController


class TestPolicyTokencount(TestController):
    """
    Test the admin show Policy.
    """

    tokencount = 4
    auth_user = ("passthru_user1@mydefrealm", "geheim1")

    new_token_params = {
        "serial": f"#SETUP{tokencount + 1}",
        "type": "pw",
        "otpkey": f"setupkey{tokencount + 1}",
        "user": auth_user[0],
    }
    unassigned_token_params = {
        "serial": "#UNASSIGNED",
        "type": "pw",
        "otpkey": "UNASSIGNED",
    }
    new_userservice_token_params = {
        "type": "pw",
        "otpkey": "newkey",
        "pin": "newpin",
    }

    def setUp(self):
        TestController.setUp(self)
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.create_common_resolvers()
        self.create_common_realms()

        # enroll tokens up to the tokencount limit
        for i in range(1, self.tokencount + 1):
            token_params = {
                "serial": f"#SETUP{i}",
                "type": "pw",
                "otpkey": f"setupkey{i}",
                "user": self.auth_user[0],
            }
            _serial = self.enroll_token(token_params=token_params)

        # set up selfservice policy
        selfservice_policy = {
            "name": "selfservice_enroll",
            "scope": "selfservice",
            "action": "enrollPW, setOTPPIN, enable, assign",
            "user": "*",
            "realm": "mydefrealm",
        }
        self.create_policy(selfservice_policy)

        # set up tokencount policy
        tokencount_policy = {
            "name": "token_count_policy",
            "scope": "enrollment",
            "action": f"tokencount={self.tokencount}, ",
            "user": "*",
            "realm": "mydefrealm",
        }
        self.create_policy(tokencount_policy)

    def tearDown(self):
        TestController.tearDown(self)

    def assert_admin_blocked(self, response):
        """Assert admin operation was blocked by tokencount policy"""
        resp_json = response.json
        assert resp_json["result"]["status"] is False, resp_json
        assert "value" not in resp_json["result"], resp_json
        msg = "The maximum allowed number of tokens for the realm 'mydefrealm'"
        assert msg in resp_json["result"]["error"]["message"], resp_json

    def assert_userservice_blocked(self, response):
        """Assert userservice operation was blocked by tokencount policy"""
        resp_json = response.json
        assert resp_json["result"]["status"] is False, resp_json
        assert "value" not in resp_json["result"], resp_json
        msg_fragments = [
            "You may not enroll any more tokens",
            "You may not enable any more tokens",
            "The maximum allowed number of tokens",
        ]
        assert any(
            msg in resp_json["result"]["error"]["message"] for msg in msg_fragments
        ), resp_json

    def test_tokencount_blocks_enroll_when_at_limit(self):
        """Enrolling a token fails when tokencount limit is reached"""
        response = self.make_admin_request("init", params=self.new_token_params)
        self.assert_admin_blocked(response)

    def test_tokencount_blocks_enroll_when_at_limit_with_unassigned(self):
        """Unassigned tokens in realm still count toward tokencount limit"""
        self.unassign_token("#SETUP1")

        response = self.make_admin_request("init", params=self.new_token_params)
        self.assert_admin_blocked(response)

    def test_tokencount_allows_enroll_when_token_disabled(self):
        """Enrolling a token succeeds when another token is disabled"""
        self.disable_token("#SETUP1")

        response = self.make_admin_request("init", params=self.new_token_params)
        resp_json = response.json

        assert resp_json["result"]["status"] is True, resp_json
        assert resp_json["result"]["value"] is True, resp_json

    def test_tokencount_blocks_enable_when_at_limit(self):
        """Enabling a token fails when tokencount limit is reached"""
        # Reduce tokencount to create a limit scenario
        self.create_policy(
            {
                "name": "token_count_policy",
                "scope": "enrollment",
                "action": f"tokencount={self.tokencount - 1}, ",
                "user": "*",
                "realm": "mydefrealm",
            }
        )
        self.disable_token("#SETUP1")

        response = self.make_admin_request("enable", params={"serial": "#SETUP1"})
        assert '"value": 1' not in response, response
        assert "You may not enable any more tokens" in response, response

    def test_tokencount_allows_enable_when_token_disabled(self):
        """Enabling a token succeeds when another token is disabled"""
        self.disable_token("#SETUP1")

        response = self.make_admin_request("enable", params={"serial": "#SETUP1"})
        resp_json = response.json

        assert resp_json["result"]["status"] is True, resp_json
        assert resp_json["result"]["value"] == 1, resp_json

    def test_tokencount_allows_reenable_of_same_token(self):
        """Re-enabling an already enabled token succeeds"""
        response = self.make_admin_request("enable", params={"serial": "#SETUP1"})
        resp_json = response.json

        assert resp_json["result"]["status"] is True, resp_json
        assert resp_json["result"]["value"] == 1, resp_json

    def test_tokencount_blocks_assign_when_at_limit(self):
        """Assigning a token fails when tokencount limit is reached"""
        unassigned_serial = self.enroll_token(self.unassigned_token_params)

        response = self.make_admin_request(
            "assign", params={"serial": unassigned_serial, "user": self.auth_user[0]}
        )
        self.assert_admin_blocked(response)

    def test_tokencount_blocks_assign_when_at_limit_with_unassigned(self):
        """Unassigning a token doesn't free up space for assigning a different token"""
        self.unassign_token("#SETUP1")
        unassigned_serial = self.enroll_token(self.unassigned_token_params)

        response = self.make_admin_request(
            "assign", params={"serial": unassigned_serial, "user": self.auth_user[0]}
        )
        self.assert_admin_blocked(response)

    def test_tokencount_allows_reassign_of_same_token(self):
        """Reassigning an already assigned token succeeds"""
        response = self.make_admin_request(
            "assign", params={"serial": "#SETUP1", "user": self.auth_user[0]}
        )
        resp_json = response.json

        assert resp_json["result"]["status"] is True, resp_json
        assert resp_json["result"]["value"] is True, resp_json

    def test_tokencount_allows_assign_when_token_disabled(self):
        """Assigning a new token succeeds when another token is disabled"""
        self.disable_token("#SETUP1")
        unassigned_serial = self.enroll_token(self.unassigned_token_params)

        response = self.make_admin_request(
            "assign", params={"serial": unassigned_serial, "user": self.auth_user[0]}
        )
        resp_json = response.json

        assert resp_json["result"]["status"] is True, resp_json
        assert resp_json["result"]["value"] is True, resp_json

    def test_tokencount_blocks_userservice_enroll_when_at_limit(self):
        """Enrolling via userservice fails when tokencount limit is reached"""
        response = self.make_userservice_request(
            "enroll", params=self.new_userservice_token_params, auth_user=self.auth_user
        )
        self.assert_userservice_blocked(response)

    def test_tokencount_blocks_userservice_enroll_when_at_limit_with_unassigned(self):
        """Unassigned tokens in realm still count toward tokencount limit"""
        self.unassign_token("#SETUP1")

        response = self.make_userservice_request(
            "enroll", params=self.new_userservice_token_params, auth_user=self.auth_user
        )
        self.assert_userservice_blocked(response)

    def test_tokencount_allows_userservice_enroll_when_token_disabled(self):
        """Enrolling a token via userservice succeeds when another token is disabled"""
        self.disable_token("#SETUP1")

        response = self.make_userservice_request(
            "enroll", params=self.new_userservice_token_params, auth_user=self.auth_user
        )
        resp_json = response.json
        assert resp_json["result"]["status"] is True, resp_json
        assert resp_json["result"]["value"] is True, resp_json

    def test_tokencount_blocks_userservice_enable_when_at_limit(self):
        """Enabling via userservice fails when tokencount limit is reached"""
        # Reduce tokencount to create a limit scenario
        self.create_policy(
            {
                "name": "token_count_policy",
                "scope": "enrollment",
                "action": f"tokencount={self.tokencount - 1}, ",
                "user": "*",
                "realm": "mydefrealm",
            }
        )
        self.disable_token("#SETUP1")

        response = self.make_userservice_request(
            "enable", params={"serial": "#SETUP1"}, auth_user=self.auth_user
        )
        self.assert_userservice_blocked(response)

    def test_tokencount_allows_userservice_enable_when_token_disabled(self):
        """Enabling a token via userservice succeeds when another token is disabled"""
        self.disable_token("#SETUP1")

        response = self.make_userservice_request(
            "enable", params={"serial": "#SETUP1"}, auth_user=self.auth_user
        )
        resp_json = response.json
        assert resp_json["result"]["status"] is True, resp_json
        assert resp_json["result"]["value"]["enable token"] == 1, resp_json

    def test_tokencount_allows_userservice_reenable_of_same_token(self):
        """Re-enabling an already enabled token via userservice succeeds"""
        response = self.make_userservice_request(
            "enable", params={"serial": "#SETUP1"}, auth_user=self.auth_user
        )
        resp_json = response.json
        assert resp_json["result"]["status"] is True, resp_json
        assert resp_json["result"]["value"]["enable token"] == 1, resp_json

    def test_tokencount_blocks_userservice_assign_when_at_limit(self):
        """Assigning a token via userservice fails when tokencount limit is reached"""
        unassigned_serial = self.enroll_token(self.unassigned_token_params)

        response = self.make_userservice_request(
            "assign", params={"serial": unassigned_serial}, auth_user=self.auth_user
        )
        self.assert_userservice_blocked(response)

    def test_tokencount_blocks_userservice_assign_when_at_limit_with_unassigned(self):
        """Unassigning a token doesn't free up space for assigning a different token via userservice"""
        self.unassign_token("#SETUP1")
        unassigned_serial = self.enroll_token(self.unassigned_token_params)

        response = self.make_userservice_request(
            "assign", params={"serial": unassigned_serial}, auth_user=self.auth_user
        )
        self.assert_userservice_blocked(response)

    def test_tokencount_allows_userservice_assign_when_token_disabled(self):
        """Assigning a new token via userservice succeeds when another token is disabled"""
        self.disable_token("#SETUP1")
        unassigned_serial = self.enroll_token(self.unassigned_token_params)

        response = self.make_userservice_request(
            "assign", params={"serial": unassigned_serial}, auth_user=self.auth_user
        )
        resp_json = response.json
        assert resp_json["result"]["status"] is True, resp_json
        assert resp_json["result"]["value"] == {"assign token": True}, resp_json

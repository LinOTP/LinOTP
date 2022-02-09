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
Test the onetime token for the selfservice login
"""
import json
from typing import List

import pytest

from linotp.tests import TestController


class TestRolloutToken(TestController):
    """
    Test the one time login token
    """

    def setUp(self):
        TestController.setUp(self)
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.create_common_resolvers()
        self.create_common_realms()

        self._setup_mfa_login_policy()

    def tearDown(self):
        TestController.tearDown(self)

    def _setup_mfa_login_policy(self):
        params = {
            "name": "mfa",
            "scope": "selfservice",
            "action": "mfa_login, mfa_3_fields",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        response = self.make_system_request("setPolicy", params)
        assert isinstance(
            response.json["result"]["value"]["setPolicy mfa"], dict
        ), "expected mfa policy details to be returned from request"

    def _setup_purge_policy(self):
        params = {
            "name": "purge",
            "scope": "enrollment",
            "action": "purge_rollout_token",
            "user": "*",
            "realm": "*",
            "active": True,
        }
        response = self.make_system_request("setPolicy", params)
        assert isinstance(
            response.json["result"]["value"]["setPolicy purge"], dict
        ), "expected purge policy details to be returned from request"

    def init_rollout_token(
        self,
        user: str,
        pw: str,
        pin: str,
        serial: str = "KIPW0815",
        scopes: List[str] = None,
        rollout: bool = None,
    ):
        params = {
            "otpkey": pw,
            "user": user,
            "pin": pin,
            "type": "pw",
            "serial": serial,
            "description": "Test rollout token",
        }

        assert (
            scopes is not None or rollout is not None
        ), "You should be setting scopes or rollout params for initializing rollout tokens"

        if rollout is not None:
            params["rollout"] = "True"
        if scopes is not None:
            params["scope"] = json.dumps({"path": scopes})

        response = self.make_admin_request("init", params=params)
        assert response.json["result"]["value"] == True, response

    def init_token(
        self,
        user: str,
        pw: str,
        pin: str,
        serial: str = "KIPWOTHER",
    ):
        params = {
            "otpkey": pw,
            "user": user,
            "pin": pin,
            "type": "pw",
            "serial": serial,
            "description": "Production token - not rollout",
        }
        response = self.make_admin_request("init", params=params)
        assert response.json["result"]["value"] == True, response

    def validate_check(self, user, pin, password):
        params = {"user": user, "pass": pin + password}
        response = self.make_validate_request("check", params=params)

        return response

    # ---------------------------------------------------------------------- --

    def test_scope_both(self):
        """
        test token with both scopes defined
        """
        user = "passthru_user1@myDefRealm"
        password = "geheim1"
        otp = "verry_verry_secret"
        pin = "1234567890"

        self.init_rollout_token(
            user, otp, pin, scopes=["validate", "userservice"]
        )

        response = self.validate_check(user, pin, otp)
        assert response.json["result"]["value"] == True, response

        response, _ = self._user_service_login(user, password, otp)
        assert response.json["result"]["value"] == True, response

    def test_scope_selfservice(self):
        """
        test token with both scopes defined
        """
        user = "passthru_user1@myDefRealm"
        password = "geheim1"
        otp = "verry_verry_secret"
        pin = "1234567890"

        self.init_rollout_token(user, otp, pin, scopes=["userservice"])

        response = self.validate_check(user, pin, otp)
        assert response.json["result"]["value"] == False, response

        response, _ = self._user_service_login(user, password, otp)
        assert response.json["result"]["value"] == True, response

    def test_scope_selfservice_alias(self):
        """
        test token with both scopes defined
        """
        user = "passthru_user1@myDefRealm"
        password = "geheim1"
        otp = "verry_verry_secret"
        pin = "1234567890"

        self.init_rollout_token(user, otp, pin, rollout=True)

        response = self.validate_check(user, pin, otp)
        assert response.json["result"]["value"] == False, response

        response, _ = self._user_service_login(user, password, otp)
        assert response.json["result"]["value"] == True, response

    def test_scope_validate(self):
        """
        test token with both scopes defined
        """
        user = "passthru_user1@myDefRealm"
        password = "geheim1"
        otp = "verry_verry_secret"
        pin = "1234567890"

        self.init_rollout_token(user, otp, pin, scopes=["validate"])

        response = self.validate_check(user, pin, otp)
        assert response.json["result"]["value"] == True, response

        response, _ = self._user_service_login(user, password, otp)
        assert response.json["result"]["value"] == False, response

    @pytest.mark.exclude_sqlite
    def test_enrollment_janitor(self):
        """
        test janitor - remove rollout token via validate/check
        """
        self._setup_purge_policy()

        user = "passthru_user1@myDefRealm"
        password = "geheim1"
        otp = "verry_verry_secret"
        pin = "1234567890"

        self.init_rollout_token(user, otp, pin, scopes=["userservice"])
        self.init_token(user, "second", "Test123!")

        # ------------------------------------------------------------------ --

        # ensure the rollout is only valid in scope userservice

        response = self.validate_check(user, pin, otp)
        assert response.json["result"]["value"] == False, response

        response, _ = self._user_service_login(user, password, otp)
        assert response.json["result"]["value"] == True, response

        response = self.make_admin_request("show", params=params)
        assert "KIPW0815" in response, response

        # ------------------------------------------------------------------ --

        # verify that the default description of the token is 'rollout token'

        tokens = (
            json.loads(response.body)
            .get("result", {})
            .get("value", {})
            .get("data", [])
        )

        assert len(tokens) > 1

        for token in tokens:
            if token["LinOtp.TokenSerialnumber"] == "KIPW0815":
                assert token["LinOtp.TokenDesc"] == "rollout token"
                break

        # ------------------------------------------------------------------ --

        # after the valid authentication with the second token
        # the rollout token should have disappeared

        response = self.validate_check(user, pin="Test123!", password="second")
        assert response.json["result"]["value"] == True, response

        response = self.make_admin_request("show", params=params)
        assert "KIPW0815" not in response, response

        # ------------------------------------------------------------------ --

        # verify that the audit log reflects the purge of the rollout tokens

        found_in_audit_log = False

        params = {
            "rp": 20,
            "page": 1,
            "sortorder": "desc",
            "sortname": "number",
            "qtype": "action",
            "query": "validate/check",
        }

        response = self.make_audit_request("search", params=params)

        entries = json.loads(response.body).get("rows", [])
        for entry in entries:
            data = entry["cell"]
            if "purged rollout tokens:KIPW0815" in data[12]:
                found_in_audit_log = True
                break

        assert found_in_audit_log, entries

    def test_enrollment_janitor2(self):
        """
        test janitor - remove rollout token via selfservice login
        """
        self._setup_purge_policy()

        user = "passthru_user1@myDefRealm"
        password = "geheim1"
        otp = "verry_verry_secret"
        pin = "1234567890"

        self.init_rollout_token(user, otp, pin, scopes=["userservice"])
        self.init_token(user, "second", "Test123!")

        # ------------------------------------------------------------------ --
        # ensure that login with rollout token is only
        # possible in the selfservice

        response = self.validate_check(user, pin, otp)
        assert response.json["result"]["value"] == False, response

        response, _ = self._user_service_login(user, password, otp)
        assert response.json["result"]["value"] == True, response

        # ------------------------------------------------------------------ --

        # the valid authentication with the rollout token
        # should make the rollout token not disappeared

        response = self.make_admin_request("show", params=params)
        assert "KIPW0815" in response, response

        # ------------------------------------------------------------------ --

        # after the valid authentication with the second token
        # the rollout token should have disappeared

        response, _ = self._user_service_login(user, password, otp="second")
        assert response.json["result"]["value"] == True, response

        response = self.make_admin_request("show", params=params)
        assert "KIPW0815" not in response, response

    def test_enrollment_janitor3(self):
        """
        test janitor - do not remove rollout token via selfservice login
        """
        user = "passthru_user1@myDefRealm"
        password = "geheim1"
        otp = "verry_verry_secret"
        pin = "1234567890"

        self.init_rollout_token(user, otp, pin, scopes=["userservice"])
        self.init_token(user, "second", "Test123!")

        # ------------------------------------------------------------------ --
        # ensure that login with rollout token is only
        # possible in the selfservice

        response = self.validate_check(user, pin, otp)
        assert response.json["result"]["value"] == False, response

        response, _ = self._user_service_login(user, password, otp)
        assert response.json["result"]["value"] == True, response

        # ------------------------------------------------------------------ --

        # the valid authentication with the rollout token
        # should make the rollout token not disappeared

        response = self.make_admin_request("show", params=params)
        assert "KIPW0815" in response, response

        # ------------------------------------------------------------------ --

        # after the valid authentication with the second token
        # the rollout token should not disappeared as the policy is not set

        response, _ = self._user_service_login(user, password, otp="second")
        assert response.json["result"]["value"] == True, response

        response = self.make_admin_request("show", params=params)
        assert "KIPW0815" in response, response

    def do_enroll_token_purge_scope_validate(self, scope):
        """
        test janitor - do purge rollout tokens that have scope
        userservice AND validate
        """
        self._setup_purge_policy()

        user = "passthru_user1@myDefRealm"
        password = "geheim1"
        otp = "verry_verry_secret"
        pin = "1234567890"

        self.init_rollout_token(user, otp, pin, scopes=scope)
        self.init_token(user, "second", "Test123!")

        # ------------------------------------------------------------------ --
        # ensure that login with rollout token is possible
        # via scopes

        response = self.validate_check(user, pin, otp)
        if "validate" in scope:
            assert response.json["result"]["value"] == True, response
        else:
            assert response.json["result"]["value"] == False, response

        # Login via selfservice
        response, _ = self._user_service_login(user, password, otp)
        if "userservice" in scope:
            assert response.json["result"]["value"] == True, response
        else:
            assert response.json["result"]["value"] == False, response

        # ------------------------------------------------------------------ --

        # the valid authentication with the rollout token
        # should not have purged the rollout token

        response = self.make_admin_request("show")
        token_info = response.json["result"]["value"]["data"][1]
        self.assertEquals(
            token_info["LinOtp.TokenSerialnumber"], "KIPW0815", response
        )
        self.assertEquals(
            token_info["LinOtp.TokenDesc"], "Test rollout token", response
        )

        # ------------------------------------------------------------------ --

        # after the valid authentication with the second token the
        # rollout token should have been purged as the policy is set

        response, _ = self._user_service_login(user, password, otp="second")
        assert response.json["result"]["value"] == True, response

        response = self.make_admin_request("show")
        assert "KIPW0815" not in response, response

    def test_enroll_token_purge_scope_validate(self):
        """
        test janitor - do purge rollout tokens that have scope
        validate
        """
        self.do_enroll_token_purge_scope_validate(["validate"])

    def test_enroll_token_purge_scope_validate_and_selfservice(self):
        """
        test janitor - do purge rollout tokens that have scope
        userservice AND validate
        """
        self.do_enroll_token_purge_scope_validate(["validate", "userservice"])

    def test_not_purge_non_enroll_token(self):
        """
        test janitor - do not purge non-rollout tokens
        """

        self._setup_purge_policy()

        user = "passthru_user1@myDefRealm"
        otpkey = "secret"
        pin1 = "pin1"
        pin2 = "pin2"

        self.init_token(user, otpkey, pin1, serial="KIPW01")
        self.init_token(user, otpkey, pin2, serial="KIPW02")

        # ------------------------------------------------------------------ --
        # do a login with both tokens

        response = self.validate_check(user, pin1, otpkey)
        assert response.json["result"]["value"] == True, response

        response = self.validate_check(user, pin2, otpkey)
        assert response.json["result"]["value"] == True, response

        # ------------------------------------------------------------------ --

        # after the valid authentications with both tokens, both tokens
        # should not have been purged

        response = self.make_admin_request("show")
        assert "KIPW01" in response, response
        assert "KIPW02" in response, response

    def test_selfservice_usertokenlist(self):
        """
        test token with both scopes defined
        """
        user = "passthru_user1@myDefRealm"
        password = "geheim1"
        otp = "verry_verry_secret"
        pin = "1234567890"

        self.init_rollout_token(user, otp, pin, rollout=True)
        self.init_token(user, "second", "Test123!")

        # ----------------------------------------------------------------- --

        # now login into selfservice and query the users token list

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": "geheim1",
            "otp": otp,
        }

        response = self.make_userselfservice_request(
            "usertokenlist", auth_user=auth_user
        )

        # verify that the rollout token is not in the list

        assert "KIPW0815" in response, response
        assert "LinOtp.TokenSerialnumber" in response, response

        response = self.make_selfservice_request(
            "usertokenlist", None, auth_user=auth_user
        )
        assert "KIPW0815" not in response.body, response

        return


# eof

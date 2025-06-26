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
Test the onetime token for the selfservice login
"""

import json
from typing import List

from linotp.tests import TestController


class TestRolloutToken(TestController):
    """
    Test the one time login token
    """

    # test fixtures
    user = "passthru_user1@myDefRealm"
    pw = "geheim1"
    otp1 = "verry_verry_secret"
    pin1 = "1234567890"
    otp2 = "second"
    pin2 = "Test123!"
    ROLLOUT_TOKEN_SERIAL = "KIPW0815"
    ROLLOUT_TOKEN_DESC = "Test rollout token"

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
        assert isinstance(response.json["result"]["value"]["setPolicy mfa"], dict), (
            "expected mfa policy details to be returned from request"
        )

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
        assert isinstance(response.json["result"]["value"]["setPolicy purge"], dict), (
            "expected purge policy details to be returned from request"
        )

    def init_rollout_token(
        self,
        user: str,
        pw: str,
        pin: str,
        serial: str = ROLLOUT_TOKEN_SERIAL,
        scopes: List[str] = None,
        rollout: bool = None,
    ):
        params = {
            "otpkey": pw,
            "user": user,
            "pin": pin,
            "type": "pw",
            "serial": serial,
            "description": self.ROLLOUT_TOKEN_DESC,
        }

        assert scopes is not None or rollout is not None, (
            "You should be setting scopes or rollout params for initializing rollout tokens"
        )

        if rollout is not None:
            params["rollout"] = "True"
        if scopes is not None:
            params["scope"] = json.dumps({"path": scopes})

        response = self.make_admin_request("init", params=params)
        assert response.json["result"]["value"] is True, response

    def init_token(self, user: str, pw: str, pin: str, serial: str = "KIPWOTHER"):
        params = {
            "otpkey": pw,
            "user": user,
            "pin": pin,
            "type": "pw",
            "serial": serial,
            "description": "Production token - not rollout",
        }
        response = self.make_admin_request("init", params=params)
        assert response.json["result"]["value"] is True, response

    def validate_check(self, user, pin, password):
        params = {"user": user, "pass": pin + password}
        return self.make_validate_request("check", params=params)

    # ---------------------------------------------------------------------- --

    def do_check_scopes(
        self,
        exp_validate: bool,  # should a validate request work with this token?
        exp_userservice: bool,  # should a selfservice login work with this token?
        scopes: List[str] = None,
        rollout: bool = None,
    ):
        self.init_rollout_token(
            self.user, self.otp1, self.pin1, scopes=scopes, rollout=rollout
        )

        response = self.validate_check(self.user, self.pin1, self.otp1)
        assert response.json["result"]["value"] == exp_validate, response

        response, _ = self._user_service_login(self.user, self.pw, self.otp1)
        assert response.json["result"]["value"] == exp_userservice, response

    def test_scope_both(self):
        """
        test 'rollout token' feature with rollout scopes 'selfservice'
        and 'validate'.
        """
        self.do_check_scopes(True, True, scopes=["validate", "userservice"])

    def test_scope_selfservice(self):
        """
        test 'rollout token' feature with rollout scope 'selfservice'.
        """
        self.do_check_scopes(False, True, scopes=["userservice"])

    def test_scope_validate(self):
        """
        test 'rollout token' feature with rollout scope 'validate'.
        """
        self.do_check_scopes(True, False, scopes=["validate"])

    def test_scope_selfservice_alias(self):
        """
        test 'rollout token' feature with alias param 'rollout=True'.

        LinOTP should treat this the same as `scopes=["userservice"]`.
        """
        self.do_check_scopes(False, True, rollout=True)

    def test_scope_and_rollout(self):
        """
        test 'rollout token' feature with scope AND rollout alias.

        LinOTP should ignore the alias and only recognize the scopes list.
        """
        self.do_check_scopes(True, False, scopes=["validate"], rollout=True)

    def test_empty_scope(self):
        r"""
        test 'rollout token' feature with empty scope.

        LinOTP should ignore any rollout feature because no explicit scope
        is defined. Please don't ask me why ¯\_(ツ)_/¯.
        """
        self.do_check_scopes(True, True, scopes=[])

    def test_enrollment_janitor(self):
        """
        test janitor - remove rollout token via validate/check
        """
        self._setup_purge_policy()

        self.init_rollout_token(self.user, self.otp1, self.pin1, scopes=["userservice"])
        self.init_token(self.user, self.otp2, self.pin2)

        # ------------------------------------------------------------------ --

        # ensure the rollout is only valid in scope userservice

        response = self.validate_check(self.user, self.pin1, self.otp1)
        assert response.json["result"]["value"] is False, response

        response, _ = self._user_service_login(self.user, self.pw, self.otp1)
        assert response.json["result"]["value"] is True, response

        # ------------------------------------------------------------------ --

        # Verify that the token is still there
        # by checking for the token's description and serial

        response = self.make_admin_request("show")
        tokens = response.json["result"]["value"]["data"]

        assert len(tokens) == 2
        assert any(
            token["LinOtp.TokenSerialnumber"] == self.ROLLOUT_TOKEN_SERIAL
            and token["LinOtp.TokenDesc"] == self.ROLLOUT_TOKEN_DESC
            for token in tokens
        ), response

        # ------------------------------------------------------------------ --

        # after the valid authentication with the second token
        # the rollout token should have disappeared

        response = self.validate_check(self.user, self.pin2, self.otp2)
        assert response.json["result"]["value"] is True, response

        response = self.make_admin_request("show")
        assert self.ROLLOUT_TOKEN_SERIAL not in response, response

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

        self.init_rollout_token(self.user, self.otp1, self.pin1, scopes=["userservice"])
        self.init_token(self.user, self.otp2, self.pin2)

        # ------------------------------------------------------------------ --
        # ensure that login with rollout token is only
        # possible in the selfservice

        response = self.validate_check(self.user, self.pin1, self.otp1)
        assert response.json["result"]["value"] is False, response

        response, _ = self._user_service_login(self.user, self.pw, self.otp1)
        assert response.json["result"]["value"] is True, response

        # ------------------------------------------------------------------ --

        # the valid authentication with the rollout token
        # should make the rollout token not disappeared

        response = self.make_admin_request("show")
        assert self.ROLLOUT_TOKEN_SERIAL in response, response

        # ------------------------------------------------------------------ --

        # after the valid authentication with the second token
        # the rollout token should have disappeared

        response, _ = self._user_service_login(self.user, self.pw, self.otp2)
        assert response.json["result"]["value"] is True, response

        response = self.make_admin_request("show")
        assert self.ROLLOUT_TOKEN_SERIAL not in response, response

    def test_enrollment_janitor3(self):
        """
        test janitor - do not remove rollout token via selfservice login
        """

        self.init_rollout_token(self.user, self.otp1, self.pin1, scopes=["userservice"])
        self.init_token(self.user, self.otp2, self.pin2)

        # ------------------------------------------------------------------ --
        # ensure that login with rollout token is only
        # possible in the selfservice

        response = self.validate_check(self.user, self.pin1, self.otp1)
        assert response.json["result"]["value"] is False, response

        response, _ = self._user_service_login(self.user, self.pw, self.otp1)
        assert response.json["result"]["value"] is True, response

        # ------------------------------------------------------------------ --

        # the valid authentication with the rollout token
        # should make the rollout token not disappeared

        response = self.make_admin_request("show")
        assert self.ROLLOUT_TOKEN_SERIAL in response, response

        # ------------------------------------------------------------------ --

        # after the valid authentication with the second token
        # the rollout token should not disappeared as the policy is not set

        response, _ = self._user_service_login(self.user, self.pw, self.otp2)
        assert response.json["result"]["value"] is True, response

        response = self.make_admin_request("show")
        assert self.ROLLOUT_TOKEN_SERIAL in response, response

    def do_enroll_token_purge_scope_validate(self, scope):
        """
        test janitor - do purge rollout tokens that have scope
        userservice AND validate
        """
        self._setup_purge_policy()

        self.init_rollout_token(self.user, self.otp1, self.pin1, scopes=scope)
        self.init_token(self.user, self.otp2, self.pin2)

        # ------------------------------------------------------------------ --
        # ensure that login with rollout token is possible
        # via scopes

        response = self.validate_check(self.user, self.pin1, self.otp1)
        if "validate" in scope:
            assert response.json["result"]["value"] is True, response
        else:
            assert response.json["result"]["value"] is False, response

        # Login via selfservice
        response, _ = self._user_service_login(self.user, self.pw, self.otp1)
        if "userservice" in scope:
            assert response.json["result"]["value"] is True, response
        else:
            assert response.json["result"]["value"] is False, response

        # ------------------------------------------------------------------ --

        # the valid authentication with the rollout token
        # should not have purged the rollout token

        response = self.make_admin_request("show")
        tokens = response.json["result"]["value"]["data"]

        assert len(tokens) == 2
        assert any(
            token["LinOtp.TokenSerialnumber"] == self.ROLLOUT_TOKEN_SERIAL
            and token["LinOtp.TokenDesc"] == self.ROLLOUT_TOKEN_DESC
            for token in tokens
        ), response

        # ------------------------------------------------------------------ --

        # after the valid authentication with the second token the
        # rollout token should have been purged as the policy is set

        response, _ = self._user_service_login(self.user, self.pw, self.otp2)
        assert response.json["result"]["value"] is True, response

        response = self.make_admin_request("show")

        assert len(response.json["result"]["value"]["data"]) == 1

        assert self.ROLLOUT_TOKEN_SERIAL not in response, response

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

        self.init_token(self.user, self.otp1, self.pin1, serial="KIPW01")
        self.init_token(self.user, self.otp1, self.pin2, serial="KIPW02")

        # ------------------------------------------------------------------ --
        # do a login with both tokens

        response = self.validate_check(self.user, self.pin1, self.otp1)
        assert response.json["result"]["value"] is True, response

        response = self.validate_check(self.user, self.pin2, self.otp1)
        assert response.json["result"]["value"] is True, response

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
        self.init_rollout_token(self.user, self.otp1, self.pin1, rollout=True)
        self.init_token(self.user, self.otp2, self.pin2)

        # ----------------------------------------------------------------- --

        auth_user = {
            "login": "passthru_user1@myDefRealm",
            "password": self.pw,
            "otp": self.otp1,
        }

        # verify that the rollout token is available to the user
        response = self.make_userselfservice_request(
            "usertokenlist", auth_user=auth_user
        )
        assert len(response.json["result"]["value"]) == 2
        assert self.ROLLOUT_TOKEN_SERIAL in response, response

        # verify that the rollout token is not shown in the selfservice UI html
        response = self.make_selfservice_request(
            "usertokenlist", None, auth_user=auth_user
        )
        assert self.ROLLOUT_TOKEN_SERIAL not in response.body, response

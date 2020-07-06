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

    def tearDown(self):
        TestController.tearDown(self)

    def user_service_login(self, user, password, otp):
        """
        """
        response, auth_cookie = self._user_service_login(
            auth_user=user,
            password=password,
            otp=otp)

        return response

    def validate_check(self, user, pin, password):
        params = {
            "user": user,
            "pass": pin+password
        }
        response = self.make_validate_request("check", params=params)

        return response

    # ---------------------------------------------------------------------- --

    def test_scope_both(self):
        """
        test token with both scopes defined
        """
        params = {
            'name': 'mfa',
            'scope': 'selfservice',
            'action': 'mfa_login, mfa_3_fields',
            'user': '*',
            'realm': '*',
            'active': True
        }

        response = self.make_system_request('setPolicy', params)
        assert 'false' not in response, response

        user = 'passthru_user1@myDefRealm'
        password = 'geheim1'
        otp = 'verry_verry_secret'
        pin = '1234567890'

        params = {
            "otpkey": otp,
            "user": user,
            "pin": pin,

            "type": "pw",
            "serial": "KIPW0815",
            "description": "enrollment test token",
            "scope": json.dumps({
                "path": ["validate", "userservice"]})
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        response = self.validate_check(user, pin, otp)
        assert ' "value": true' in response, response

        response = self.user_service_login(user, password, otp)
        assert ' "value": true' in response, response

        return

    def test_scope_both2(self):
        """
        test token with both scopes defined
        """
        params = {
            'name': 'mfa',
            'scope': 'selfservice',
            'action': 'mfa_login, mfa_3_fields',
            'user': '*',
            'realm': '*',
            'active': True
        }

        response = self.make_system_request('setPolicy', params)
        assert 'false' not in response, response

        user = 'passthru_user1@myDefRealm'
        password = 'geheim1'
        otp = 'verry_verry_secret'
        pin = '1234567890'

        params = {
            "otpkey": otp,
            "user": user,
            "pin": pin,

            "type": "pw",
            "serial": "KIPW0815",
            "description": "enrollment test token"
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        response = self.validate_check(user, pin, otp)
        assert ' "value": true' in response, response

        response = self.user_service_login(user, password, otp)
        assert ' "value": true' in response, response

        return

    def test_scope_selfservice(self):
        """
        test token with both scopes defined
        """
        params = {
            'name': 'mfa',
            'scope': 'selfservice',
            'action': 'mfa_login, mfa_3_fields',
            'user': '*',
            'realm': '*',
            'active': True
        }

        response = self.make_system_request('setPolicy', params)
        assert 'false' not in response, response

        user = 'passthru_user1@myDefRealm'
        password = 'geheim1'
        otp = 'verry_verry_secret'
        pin = '1234567890'

        params = {
            "otpkey": otp,
            "user": user,
            "pin": pin,

            "type": "pw",
            "serial": "KIPW0815",
            "description": "enrollment test token",
            "scope": json.dumps({
                "path": ["userservice"]})
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        response = self.validate_check(user, pin, otp)
        assert ' "value": false' in response, response

        response = self.user_service_login(user, password, otp)
        assert ' "value": true' in response, response

        return

    def test_scope_selfservice_alias(self):
        """
        test token with both scopes defined
        """
        params = {
            'name': 'mfa',
            'scope': 'selfservice',
            'action': 'mfa_login, mfa_3_fields',
            'user': '*',
            'realm': '*',
            'active': True
        }

        response = self.make_system_request('setPolicy', params)
        assert 'false' not in response, response

        user = 'passthru_user1@myDefRealm'
        password = 'geheim1'
        otp = 'verry_verry_secret'
        pin = '1234567890'

        params = {
            "otpkey": otp,
            "user": user,
            "pin": pin,

            "type": "pw",
            "serial": "KIPW0815",
            "description": "enrollment test token",
            "rollout": "True"
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        response = self.validate_check(user, pin, otp)
        assert ' "value": false' in response, response

        response = self.user_service_login(user, password, otp)
        assert ' "value": true' in response, response

        return

    def test_scope_validate(self):
        """
        test token with both scopes defined
        """
        params = {
            'name': 'mfa',
            'scope': 'selfservice',
            'action': 'mfa_login, mfa_3_fields',
            'user': '*',
            'realm': '*',
            'active': True
        }

        response = self.make_system_request('setPolicy', params)
        assert 'false' not in response, response

        user = 'passthru_user1@myDefRealm'
        password = 'geheim1'
        otp = 'verry_verry_secret'
        pin = '1234567890'

        params = {
            "otpkey": otp,
            "user": user,
            "pin": pin,

            "type": "pw",
            "serial": "KIPW0815",
            "description": "enrollment test token",
            "scope": json.dumps({
                "path": ["validate"]})
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        response = self.validate_check(user, pin, otp)
        assert ' "value": true' in response, response

        response = self.user_service_login(user, password, otp)
        assert ' "value": false' in response, response

        return

    @pytest.mark.exclude_sqlite
    def test_enrollment_janitor(self):
        """
        test janitor - remove rollout token via validate/check
        """
        params = {
            'name': 'mfa',
            'scope': 'selfservice',
            'action': 'mfa_login, mfa_3_fields',
            'user': '*',
            'realm': '*',
            'active': True
        }

        response = self.make_system_request('setPolicy', params)
        assert 'false' not in response, response

        params = {
            'name': 'purge',
            'scope': 'enrollment',
            'action': 'purge_rollout_token',
            'user': '*',
            'realm': 'myMixedRealm',
            'active': True
        }

        response = self.make_system_request('setPolicy', params)
        assert 'false' not in response, response

        user = 'passthru_user1@myDefRealm'
        password = 'geheim1'
        otp = 'verry_verry_secret'
        pin = '1234567890'

        params = {
            "otpkey": otp,
            "user": user,
            "pin": pin,
            "type": "pw",
            "serial": "KIPW0815",
            "scope": json.dumps({
                "path": ["userservice"]})
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        # enroll second token - the enrollment token should disapear now

        params = {
            "otpkey": 'second',
            "user": user,
            "pin": "Test123!",
            "type": "pw",
            "description": "second token",
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        # ------------------------------------------------------------------ --

        # ensure the rollout is only valid in scope userservice

        response = self.validate_check(user, pin, otp)
        assert ' "value": false' in response, response

        response = self.user_service_login(user, password, otp)
        assert ' "value": true' in response, response

        response = self.make_admin_request('show', params=params)
        assert 'KIPW0815' in response, response

        # ------------------------------------------------------------------ --

        # verify that the default description of the token is 'rollout token'

        tokens = json.loads(response.body).get(
            'result', {}).get(
            'value', {}).get(
            'data', [])

        assert len(tokens) > 1

        for token in tokens:
            if token["LinOtp.TokenSerialnumber"] == "KIPW0815":
                assert token['LinOtp.TokenDesc'] == 'rollout token'
                break

        # ------------------------------------------------------------------ --

        # after the valid authentication with the second token
        # the rollout token should have disappeared

        response = self.validate_check(user, pin="Test123!", password='second')
        assert ' "value": true' in response, response

        response = self.make_admin_request('show', params=params)
        assert 'KIPW0815' not in response, response

        # ------------------------------------------------------------------ --

        # verify that the audit log reflects the purge of the rollout tokens

        found_in_audit_log = False

        params = {
            'rp': 20,
            'page': 1,
            'sortorder': 'desc',
            'sortname': 'number',
            'qtype': 'action',
            'query': 'validate/check',
        }

        response = self.make_audit_request('search', params=params)

        entries = json.loads(response.body).get('rows', [])
        for entry in entries:
            data = entry['cell']
            if 'purged rollout tokens:KIPW0815' in data[12]:
                found_in_audit_log = True
                break

        assert found_in_audit_log, entries

        return

    def test_enrollment_janitor2(self):
        """
        test janitor - remove rollout token via selfservice login
        """
        params = {
            'name': 'mfa',
            'scope': 'selfservice',
            'action': 'mfa_login, mfa_3_fields',
            'user': '*',
            'realm': '*',
            'active': True
        }

        response = self.make_system_request('setPolicy', params)
        assert 'false' not in response, response

        params = {
            'name': 'purge',
            'scope': 'enrollment',
            'action': 'purge_rollout_token',
            'user': '*',
            'realm': '*',
            'active': True
        }

        response = self.make_system_request('setPolicy', params)
        assert 'false' not in response, response

        user = 'passthru_user1@myDefRealm'
        password = 'geheim1'
        otp = 'verry_verry_secret'
        pin = '1234567890'

        params = {
            "otpkey": otp,
            "user": user,
            "pin": pin,

            "type": "pw",
            "serial": "KIPW0815",
            "description": "enrollment test token",
            "scope": json.dumps({
                "path": ["userservice"]})
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        # enroll second token

        params = {
            "otpkey": 'second',
            "user": user,
            "pin": "Test123!",
            "type": "pw",
            "description": "second token",
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        # ------------------------------------------------------------------ --
        # ensure that login with rollout token is only
        # possible in the selfservice

        response = self.validate_check(user, pin, otp)
        assert ' "value": false' in response, response

        response = self.user_service_login(user, password, otp)
        assert ' "value": true' in response, response

        # ------------------------------------------------------------------ --

        # the valid authentication with the rollout token
        # should make the rollout token not disappeared

        response = self.make_admin_request('show', params=params)
        assert 'KIPW0815' in response, response

        # ------------------------------------------------------------------ --

        # after the valid authentication with the second token
        # the rollout token should have disappeared

        response = self.user_service_login(user, password, otp='second')
        assert ' "value": true' in response, response

        response = self.make_admin_request('show', params=params)
        assert 'KIPW0815' not in response, response

        return

    def test_enrollment_janitor3(self):
        """
        test janitor - do not remove rollout token via selfservice login
        """
        params = {
            'name': 'mfa',
            'scope': 'selfservice',
            'action': 'mfa_login, mfa_3_fields',
            'user': '*',
            'realm': '*',
            'active': True
        }

        response = self.make_system_request('setPolicy', params)
        assert 'false' not in response, response

        user = 'passthru_user1@myDefRealm'
        password = 'geheim1'
        otp = 'verry_verry_secret'
        pin = '1234567890'

        params = {
            "otpkey": otp,
            "user": user,
            "pin": pin,

            "type": "pw",
            "serial": "KIPW0815",
            "description": "enrollment test token",
            "scope": json.dumps({
                "path": ["userservice"]})
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        # enroll second token

        params = {
            "otpkey": 'second',
            "user": user,
            "pin": "Test123!",
            "type": "pw",
            "description": "second token",
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        # ------------------------------------------------------------------ --
        # ensure that login with rollout token is only
        # possible in the selfservice

        response = self.validate_check(user, pin, otp)
        assert ' "value": false' in response, response

        response = self.user_service_login(user, password, otp)
        assert ' "value": true' in response, response

        # ------------------------------------------------------------------ --

        # the valid authentication with the rollout token
        # should make the rollout token not disappeared

        response = self.make_admin_request('show', params=params)
        assert 'KIPW0815' in response, response

        # ------------------------------------------------------------------ --

        # after the valid authentication with the second token
        # the rollout token should not disappeared as the policy is not set

        response = self.user_service_login(user, password, otp='second')
        assert ' "value": true' in response, response

        response = self.make_admin_request('show', params=params)
        assert 'KIPW0815' in response, response

        return

    def test_selfservice_usertokenlist(self):
        """
        test token with both scopes defined
        """
        params = {
            'name': 'mfa',
            'scope': 'selfservice',
            'action': 'mfa_login, mfa_3_fields',
            'user': '*',
            'realm': '*',
            'active': True
        }

        response = self.make_system_request('setPolicy', params)
        assert 'false' not in response, response

        user = 'passthru_user1@myDefRealm'
        password = 'geheim1'
        otp = 'verry_verry_secret'
        pin = '1234567890'

        params = {
            "otpkey": otp,
            "user": user,
            "pin": pin,

            "type": "pw",
            "serial": "KIPW0815",
            "description": "enrollment test token",
            "rollout": "True"
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        # enroll second token

        params = {
            "otpkey": 'second',
            "user": user,
            "pin": "Test123!",
            "type": "pw",
            "description": "second token",
        }

        response = self.make_admin_request('init', params=params)
        assert '"value": true' in response, response

        # ----------------------------------------------------------------- --

        # now login into selfservice and query the users token list

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1',
            'otp': otp
        }

        response = self.make_userselfservice_request(
            'usertokenlist', auth_user=auth_user)

        # verify that the rollout token is not in the list

        assert 'KIPW0815' in response, response
        assert 'LinOtp.TokenSerialnumber' in response, response

        response = self.make_selfservice_request(
            'usertokenlist', None, auth_user=auth_user)
        assert 'KIPW0815' not in response.body, response

        return

# eof

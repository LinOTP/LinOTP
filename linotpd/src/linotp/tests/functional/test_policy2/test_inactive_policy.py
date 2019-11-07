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
Test inactive policies are not evaluated
"""

import json

from linotp.tests import TestController


class TestInactivePolicy(TestController):
    """
    Test the non-evaluation of inactive policies.
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

    def test_inactive_policy(self):
        """
        test that no inactive policy is evaluated for the old and new engine
        """

        # get the currently used policy engine and preserve this for restore

        params = {'key': 'NewPolicyEvaluation'}
        response = self.make_system_request('getConfig', params=params)
        assert '"getConfig NewPolicyEvaluation"' in response, response

        jresp = json.loads(response.body)

        restore_new_policy_engine = jresp.get(
            'result', {}).get(
                'value', {}).get('getConfig NewPolicyEvaluation', False)

        # ----------------------------------------------------------------- --

        # run the usage of 'active policy only' verification for both machines

        try:

            for policy_engine_version in ['new', 'old']:

                if policy_engine_version == 'new':
                    params = {'NewPolicyEvaluation': 'True'}
                    response = self.make_system_request('setConfig',
                                                        params=params)
                    assert '"setConfig NewPolicyEvaluation:True"' in response, \
                        response

                if policy_engine_version == 'old':
                    params = {'key': 'NewPolicyEvaluation'}
                    response = self.make_system_request('delConfig',
                                                        params=params)
                    assert '"delConfig NewPolicyEvaluation"' in response, \
                        response

                self.run_inactive_policy_verifcation()

        # ----------------------------------------------------------------- --

        finally:

            # restore the inital policy engine behaviour

            if not restore_new_policy_engine:
                params = {'key': 'NewPolicyEvaluation'}
                response = self.make_system_request('delConfig', params=params)

            else:
                params = {'NewPolicyEvaluation': 'True'}
                response = self.make_system_request('setConfig', params=params)

        return

    def run_inactive_policy_verifcation(self):
        """
        verify that no inactive policy is evaluated

        the test is using the otppin=1 policy, which is checked to active
        in the first place. After the first check, the policy is disabled
        and the former authenication test will fail but the authentication
        without policy will work again.
        """

        user = 'passthru_user1'
        pw_pass = "geheim1"
        pw_otp = 'Test123'
        pw_pin = "123!"

        params = {
            "serial": 'KIPW_007',
            "type": "pw",
            'otpkey': pw_otp,
            'pin': pw_pin,
            'user': user,
            "description": "myTest123"}

        response = self.make_admin_request('init', params=params)
        jresp = json.loads(response.body)

        serial = jresp.get('detail', {}.get('serial'))
        assert serial is not None, response

        # ----------------------------------------------------------------- --

        # run a simple validate check test without otppin policy

        params = {
            'user': user,
            'pass': pw_pin + pw_otp}
        response = self.make_validate_request('check', params=params)

        jresp = json.loads(response.body)
        value = jresp.get('result', {}).get('value')
        assert value, response

        # ----------------------------------------------------------------- --

        # we use the otppin policy

        policy = {
            'name': 'inactive_policy',
            'active': True,
            'scope': 'authentication',
            'realm': '*',
            'client': '*',
            'user': '*',
            'action': 'otppin=1'}

        response = self.make_system_request('setPolicy', policy)

        jresp = json.loads(response.body)
        p_loaded = jresp.get(
            'result', {}).get(
                'value', {}).get(
                    "setPolicy %s" % policy.get('name'))
        assert p_loaded is not None, response

        # ----------------------------------------------------------------- --

        # run a validate check test with otppin=1 parameters

        params = {
            'user': user,
            'pass': pw_pass + pw_otp}

        response = self.make_validate_request('check', params=params)

        jresp = json.loads(response.body)
        value = jresp.get('result', {}).get('value')
        assert value, response

        # ----------------------------------------------------------------- --

        # now disable the otppin policy

        policy = {
            'name': 'inactive_policy',
            'active': False,
            'scope': 'authentication',
            'realm': '*',
            'client': '*',
            'user': '*',
            'action': 'otppin=1'}

        response = self.make_system_request('setPolicy', policy)

        jresp = json.loads(response.body)
        p_loaded = jresp.get(
            'result', {}).get(
                'value', {}).get(
                    "setPolicy %s" % policy.get('name'))
        assert p_loaded is not None, response

        # ----------------------------------------------------------------- --

        # run a validate check test with otppin=1 parameters again
        # which now will fail

        params = {
            'user': user,
            'pass': pw_pass + pw_otp}

        response = self.make_validate_request('check', params=params)

        jresp = json.loads(response.body)
        value = jresp.get('result', {}).get('value')
        assert not value, response

        # ----------------------------------------------------------------- --

        # run a simple validate check test without otppin policy again

        params = {
            'user': user,
            'pass': pw_pin + pw_otp}
        response = self.make_validate_request('check', params=params)

        jresp = json.loads(response.body)
        value = jresp.get('result', {}).get('value')
        assert value, response

        return

# eof #

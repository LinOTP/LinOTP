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
Test the tokencount Policy.
"""

import json
from linotp.tests import TestController


class TestPolicyEngine(TestController):
    """
    Test the new Policy Engine.
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

    def test_token_enrollment(self):
        """
        switch the new engine on and compare the result of the old one

        the difference between the old an the new one is the ability to
        evaluate the policy time based
        """

        # the test first creates a new token

        serial = 'NewEngineTestToken'

        params = {'type': 'spass', 'serial': 'NewEngineTestToken'}
        response = self.make_admin_request('init', params)
        assert serial in response, response

        # ----------------------------------------------------------------- --

        # setup the policies

        policy = {
            'name': 'adm_1',
            'scope': 'admin',
            'action': 'show',
            'user': '*',
            'realm': '*',
            'time': '*',
            'active': True
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert '"setPolicy adm_1"' in response, response

        able_policy = {
            'name': 'adm_2',
            'scope': 'admin',
            'action': 'enable, disable',
            'user': '*',
            'realm': '*',
            'time': '! *  0-24  * * * *',
            'active': True
        }
        response = self.make_system_request('setPolicy', params=able_policy)
        assert '"setPolicy adm_2"' in response, response

        # ----------------------------------------------------------------- --

        params = {'key': 'NewPolicyEvaluation'}
        response = self.make_system_request('getConfig', params=params)
        new_eng = json.loads(response.body).get(
                    'result', {}).get(
                        'value', {}).get(
                            'getConfig NewPolicyEvaluation')

        params = {'NewPolicyEvaluation': True}
        response = self.make_system_request('setConfig', params=params)
        assert 'NewPolicyEvaluation:True": true' in response, \
                        response
        try:

            # ------------------------------------------------------------- --

            # first the access is disable for enable/disable but show must work

            params = {}
            response = self.make_admin_request('show', params)
            assert serial in response, response

            params = {'serial': serial}
            response = self.make_admin_request('disable', params)
            msg = "You do not have the administrative right to disable "
            assert msg in response, response

            # ------------------------------------------------------------- --

            # now enable the acces time for enable/disable

            able_policy['time'] = '*  0-24  * * * *;'
            response = self.make_system_request(
                                        'setPolicy', params=able_policy)
            assert '"setPolicy adm_2"' in response, response

            # and check if this works

            params = {}
            response = self.make_admin_request('show', params)
            assert serial in response, response

            params = {'serial': serial}
            response = self.make_admin_request('disable', params)
            assert msg not in response, response
            assert '"value": 1' in response, response

            # ------------------------------------------------------------- --

        finally:
            if new_eng is None:
                params = {'key': 'NewPolicyEvaluation'}
                response = self.make_system_request('delConfig', params=params)
                assert 'NewPolicyEvaluation:True": true' in response, \
                                response
            else:
                params = {'NewPolicyEvaluation': new_eng}
                response = self.make_system_request('setConfig', params=params)
                assert 'NewPolicyEvaluation' in response, \
                                response

        return

# eof ##

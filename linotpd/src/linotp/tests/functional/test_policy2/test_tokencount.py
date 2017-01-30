# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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

import unittest2
from copy import deepcopy

from linotp.tests import TestController


class TestPolicyTokencount(TestController):
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

        response = self.make_admin_request('init', params=parameters)
        self.assertTrue('"value": true' in response, response)
        return parameters['serial']

    def test_tokencount_with_assign(self):
        """
        tokencount test with assign

        test if tokencount policy is working correctly during assign:
        - 5 tokens are enrolled, 4 tokens are allowd in mydefrealm
        - incremential assign the tokens to a user in the mydefrealm
        """
        # all policies are deleted before

        for i in range(1,6):
            token_params = {'serial': '#TCOUNT%d' % i}
            serial = self.enroll_token(token_params)
            self.assertTrue(serial == '#TCOUNT%d' % i)

        # set tokencount policy
        policy = {
            'name': 'token_count_policy',
            'scope': 'enrollment',
            'action': 'tokencount=4, ',
            'user': '*',
            'realm': 'mydefrealm',
        }

        response = self.create_policy(policy)

        # check that at least 4 tokens could be assigned

        for i in range(1,5):
            params = {'serial': '#TCOUNT%d' % i,
                      'user': 'def'}
            response = self.make_admin_request('assign', params=params)
            self.assertTrue('"value": true' in response, response)

        # check that the policy will raise an error

        i = 5
        params = {'serial': '#TCOUNT%d' % i,
                  'user': 'def'}
        response = self.make_admin_request('assign', params=params)
        self.assertFalse('"value": true' in response, response)
        msg = ('The maximum allowed number of tokens for the realm mydefrealm'
               ' was reached. You can not init any more tokens. Check the '
               'policies scope=enrollment, action=tokencount.')
        self.assertTrue(msg in response, response)

        # check that overall only 4 tokens belong to user 'def'

        params = {'user': 'def'}
        response = self.make_admin_request('show', params=params)
        self.assertTrue('"tokens": 4,' in response, response)

        # now we do an unassign and assign the token #5 to the user:
        # as the token will remain in the realm the new assign has to fail!

        params = {'serial': '#TCOUNT1'}
        response = self.make_admin_request('unassign', params=params)
        self.assertTrue('"value": true' in response, response)

        # check that the policy will raise an error, as there are
        # already 4 tokens in realm

        i = 5
        params = {'serial': '#TCOUNT%d' % i,
                  'user': 'def'}
        response = self.make_admin_request('assign', params=params)
        self.assertFalse('"value": true' in response, response)
        msg = ('The maximum allowed number of tokens for the realm mydefrealm'
               ' was reached. You can not init any more tokens. Check the '
               'policies scope=enrollment, action=tokencount.')
        self.assertTrue(msg in response, response)

        return

# eof ##

# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#


"""
Test the autoassignment Policy.
"""

import unittest2
from copy import deepcopy

from linotp.tests import TestController


class TestAdminShowController(TestController):
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

    def create_admin_policy(self, policy_def=None):
        """
        """
        admin_policy = {
            'name': 'admin_policy',
            'scope': 'admin',
            'action': '*',
            'user': '*',
            'realm': '*',
        }
        if policy_def:
            admin_policy.update(policy_def)

        response = self.create_policy(admin_policy)

        return response

    def test_admin_show_policy(self):
        """
        by default, there should be no restriction to show an token
        """
        # all policies are deleted before

        serial = self.enroll_token()
        params = {'serial': serial}
        response = self.make_admin_request('show', params=params)

        self.assertTrue(serial in response, response)

        # set open policy without restrictions
        self.create_admin_policy()

        params = {'serial': serial}
        response = self.make_admin_request('show', params=params)

        self.assertTrue(serial in response, response)

        # set policy with explicit show action and wildcard action
        policy_def = {'action': 'show, *'}
        self.create_admin_policy(policy_def=policy_def)

        params = {'serial': serial}
        response = self.make_admin_request('show', params=params)

        self.assertTrue(serial in response, response)

        # set policy with not specified realm and wildcard action
        policy_def = {'action': '*',
                      'realm': 'unspecified_realm'}
        self.create_admin_policy(policy_def=policy_def)

        params = {'serial': serial}
        response = self.make_admin_request('show', params=params)

        self.assertTrue(serial not in response, response)

        # set policy with not specified realm and wildcard realm and
        # dedicated action
        policy_def = {'action': 'show',
                      'realm': 'unspecified_realm, *'}
        self.create_admin_policy(policy_def=policy_def)

        params = {'serial': serial}
        response = self.make_admin_request('show', params=params)

        self.assertTrue(serial in response, response)

        return

    def test_manage_tokeninfo(self):
        """
        by default, there should be no restriction to show an token
        """
        # all policies are deleted before

        serial = self.enroll_token()
        params = {'serial': serial}
        response = self.make_manage_request('tokeninfo', params=params)

        self.assertTrue(serial in response, response)

        # set open policy without restrictions
        self.create_admin_policy()

        params = {'serial': serial}
        response = self.make_manage_request('tokeninfo', params=params)

        self.assertTrue(serial in response, response)

        # set policy with explicit show action and wildcard action
        policy_def = {'action': 'show, *'}
        self.create_admin_policy(policy_def=policy_def)

        params = {'serial': serial}
        response = self.make_manage_request('tokeninfo', params=params)

        self.assertTrue(serial in response, response)

        # set policy with not specified realm and wildcard action
        policy_def = {'action': '*',
                      'realm': 'unspecified_realm'}
        self.create_admin_policy(policy_def=policy_def)

        params = {'serial': serial}
        response = self.make_manage_request('tokeninfo', params=params)

        self.assertTrue(serial not in response, response)

        # set policy with not specified realm and wildcard realm and
        # dedicated action
        policy_def = {'action': 'show',
                      'realm': 'unspecified_realm, *'}
        self.create_admin_policy(policy_def=policy_def)

        params = {'serial': serial}
        response = self.make_manage_request('tokeninfo', params=params)

        self.assertTrue(serial in response, response)

        return

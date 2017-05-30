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
Test the setrealm policy using resolver spec as selector
"""

from linotp.tests import TestController


class TestPolicySetrealm(TestController):
    """
    Test the setrealm policy.
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

    def define_setrealm_policies(self):
        """ define setrealm policy with resolver selctor """

        # ------------------------------------------------------------------ --

        # define the policies

        params = {
            'name': 'set_realm_test',
            'action': 'setrealm=mydefrealm',
            'user': 'myDefRes:',
            'realm': 'mymixrealm',
            'scope': 'authorization'}

        response = self.make_system_request('setPolicy', params)
        self.assertTrue('"active": true,' in response, response)

        params = {
            'name': 'passthru',
            'action': 'passthru',
            'user': '*',
            'realm': 'mydefrealm',
            'scope': 'authentication'}

        response = self.make_system_request('setPolicy', params)
        self.assertTrue('"active": true,' in response, response)

    def test_setrealm_policy_negative(self):
        """ test setrealm with resolver selctor """

        self.define_setrealm_policies()

        # asigne an token to the user

        user = 'max1@mymixrealm'
        user_pass = 'password1'
        token_pin = 'Test123!'

        params = {'type': 'spass',
                  'user': user,
                  'pin': token_pin}

        response = self.make_admin_request('init', params=params)
        self.assertTrue('"otpkey"' in response, response)

        # ------------------------------------------------------------------ --

        # check by the authentication, that the user is not mapped in
        # the passthru realm

        params = {'user': user,
                  'pass': user_pass}

        response = self.make_validate_request('check', params)
        self.assertTrue('"value": false' in response, response)

        params = {'user': user,
                  'pass': token_pin}

        response = self.make_validate_request('check', params)
        self.assertTrue('"value": true' in response, response)

        return

    def test_setrealm_policy_positiv(self):
        """ test setrealm with resolver selctor """

        self.define_setrealm_policies()

        # asigne an token to the user

        user = 'passthru_user1@mymixrealm'
        user_pass = 'geheim1'
        token_pin = 'Test123!'

        params = {'type': 'spass',
                  'user': user,
                  'pin': token_pin}

        response = self.make_admin_request('init', params=params)
        self.assertTrue('"otpkey"' in response, response)

        # ------------------------------------------------------------------ --

        # check by the authentication, that the user is mapped in
        # the passthru realm

        params = {'user': user,
                  'pass': user_pass}

        response = self.make_validate_request('check', params)
        self.assertTrue('"value": true' in response, response)

        return

# eof #

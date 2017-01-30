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
Test the maxtoken Policy.
"""


from linotp.tests import TestController


class TestPolicyMaxtoken(TestController):
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
        return response

    def test_maxtoken_assign(self):
        """
        test maxtoken check for multiple same user in realm and user wildcard

        the maxtoken could happen in two cases - during init and during assign

        """
        policy = {
                  'name': 'maxtoken',
                  'realm': '*',
                  'active': 'True',
                  'client': "",
                  'user': '*',
                  'time': "",
                  'action': "maxtoken=2, ",
                  'scope': 'enrollment',
                  }

        self.create_policy(policy)

        for i in range(1, 3):
            token_params = {'serial': '#TCOUNT%d' % i, }
            response = self.enroll_token(token_params)
            self.assertTrue('#TCOUNT%d' % i in response)

        for i in range(1, 3):

            params = {'serial': '#TCOUNT%d' % i,
                      'user': 'def'}
            response = self.make_admin_request('assign', params=params)
            self.assertTrue('"value": true' in response, response)

        i = 3
        params = {'serial': '#TCOUNT%d' % i,
                  'user': 'def'}
        response = self.make_admin_request('assign', params=params)
        message = "ERR410: the maximum number of allowed tokens is exceeded"
        self.assertTrue(message in response, response)

        return

    def test_maxtoken_enroll(self):
        """
        test maxtoken check for multiple same user in realm and user wildcard

        the maxtoken could happen in two cases - during init and during assign

        """
        policy = {
                  'name': 'maxtoken',
                  'realm': '*',
                  'active': "True",
                  'client': "",
                  'user': '*',
                  'time': "",
                  'action': "maxtoken=2, ",
                  'scope': 'enrollment',
                  }

        response = self.create_policy(policy)

        for i in range(1, 3):
            token_params = {'serial': '#TCOUNT%d' % i,
                            'user': 'def'}
            response = self.enroll_token(token_params)
            self.assertTrue('#TCOUNT%d' % i in response)

        i = 3
        token_params = {'serial': '#TCOUNT%d' % i,
                        'user': 'def'}
        response = self.enroll_token(token_params)
        message = ("ERR410: The maximum number of allowed tokens per user "
                   "is exceeded")
        self.assertTrue(message in response, response)

        return

# eof ##

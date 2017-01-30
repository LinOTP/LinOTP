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
Test the passthrough Policy in combination with the passOnNoToken
"""


from linotp.tests import TestController


class TestPolicyPassthrough(TestController):
    """
    Policy test
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

    def test_pass_through(self):
        """
        test passthrough policy in combination with the passOnNoToken
        """
        policy1 = {
                  'name': 'passOnNoToken',
                  'realm': '*',
                  'active': 'True',
                  'client': "*",
                  'user': '*',
                  'time': "",
                  'action': "passOnNoToken",
                  'scope': 'authentication',
                  }

        policy2 = {
                  'name': 'passthrough',
                  'realm': '*',
                  'active': 'True',
                  'client': "192.168.13.14",
                  'user': '*',
                  'time': "",
                  'action': "passthru",
                  'scope': 'authentication',
                  }

        self.create_policy(policy1)
        self.create_policy(policy2)

        # test that passonNoToken works

        params = {'user': 'passthru_user1',
                  'pass': 'password_not_required'}

        response = self.make_validate_request('check', params,
                                              client='127.0.0.1')

        self.assertTrue('"value": true' in response, response)

        # test that authentication with wrong password
        # from client 192.168.13.14 will fail

        params = {'user': 'passthru_user1',
                  'pass': 'wrong_password'}

        response = self.make_validate_request('check', params,
                                              client='192.168.13.14')

        self.assertTrue('"value": false' in response, response)

        # test that authentication with valid password
        # from client 192.168.13.14 is ok

        params = {'user': 'passthru_user1',
                  'pass': 'geheim1'}

        response = self.make_validate_request('check', params,
                                              client='192.168.13.14')

        self.assertTrue('"value": true' in response, response)

        return

# eof ##

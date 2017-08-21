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


""" used to do functional testing of the server forwarding"""


from mock import patch

from linotp.tests import TestController

Rad_Serv = None


class MockForwardServerPolicy(object):

    @staticmethod
    def do_request(servers, env, user, passw, options):

        global Rad_Serv
        Rad_Serv = servers

        return True, None


class TestForwardServer(TestController):

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_token()
        self.delete_all_policies()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def define_user_forward(self):
        # ------------------------------------------------------------------ --

        params = {
            'name': 'forward_user',
            'realm': 'mydefrealm',
            'action': ("forward_server=radius://127.0.0.1:1812/"
                       "?secret=geheim1"),
            'client': '',
            'user': 'passthru_user1',
            'time': '',
            'active': True,
            'scope': 'authentication'}

        response = self.make_system_request('setPolicy', params=params)

        name = params['name']
        self.assertTrue('setPolicy ' + name in response, response)

    def define_all_forward(self):

        params = {
            'name': "forward",
            'realm': 'mydefrealm',
            'action': ("forward_server=radius://192.168.100.180:1812/"
                       "?secret=geheim1"),
            'client': '',
            'user': '*',
            'time': '',
            'active': True,
            'scope': 'authentication'}

        response = self.make_system_request('setPolicy', params=params)

        name = params['name']
        self.assertTrue('setPolicy ' + name in response, response)

    @patch('linotp.lib.auth.validate.ForwardServerPolicy',
           MockForwardServerPolicy)
    def test_server_forwarding(self):
        '''
        Checking auth forwarding with check
        '''

        # ------------------------------------------------------------------ --

        self.define_all_forward()

        self.define_user_forward()

        # check passthru_user1

        params = {
            'user': 'passthru_user1',
            'pass': 'geheim1'}

        _response = self.make_validate_request(action='check', params=params)

        self.assertTrue('127.0.0.1' in Rad_Serv)

        params = {
            'user': 'passthru_user2',
            'pass': 'geheim1'}

        _response = self.make_validate_request(action='check', params=params)

        self.assertTrue('127.0.0.1' not in Rad_Serv)

        return

    @patch('linotp.lib.auth.validate.ForwardServerPolicy',
           MockForwardServerPolicy)
    def test_server_forwarding2(self):
        '''
        Checking auth forwarding with check
        '''

        # ------------------------------------------------------------------ --

        self.define_user_forward()

        self.define_all_forward()

        # check passthru_user1

        params = {
            'user': 'passthru_user1',
            'pass': 'geheim1'}

        _response = self.make_validate_request(action='check', params=params)

        self.assertTrue('127.0.0.1' in Rad_Serv)

        params = {
            'user': 'passthru_user2',
            'pass': 'geheim1'}

        _response = self.make_validate_request(action='check', params=params)

        self.assertTrue('127.0.0.1' not in Rad_Serv)

        return

# eof #

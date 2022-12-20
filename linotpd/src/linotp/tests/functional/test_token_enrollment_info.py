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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#


"""
test the token class api that displays the token status:
  enrolled but not active
"""
import json
from linotp.tests import TestController


class TestTokenEnrollmentInfo(TestController):
    '''
    test the search on a token list
    '''
    serials = []

    def setUp(self):
        ''' setup the Test Controller'''
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        ''' make the dishes'''
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)
        return

    def test_tokeninfo_for_pushtoken(self):
        """ get token enrollment status for the pushtoken """
        params = {'name': 'push_enrollment',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'pushtoken_pairing_callback_url=foo',
                  'user': '*'}

        response = self.make_system_request('setPolicy', params=params)
        self.assertTrue('setPolicy push_enrollment' in response)
        self.assertTrue('false' not in response)

        params = {
            'type': 'push',
            'pin': "Test123!",
            'serial': 'my_push',
            'user': 'passthru_user1'
        }
        response = self.make_admin_request('init', params)
        self.assertTrue('my_push' in response)

        # check via admin/show the token status
        params = {'serial': 'my_push', 'tokeninfo_format': 'json'}
        response = self.make_admin_request('show', params)

        jresp = json.loads(response.body)
        for token in jresp.get('result', {}).get('value', {}).get('data', []):
            state = token.get('LinOtp.TokenInfo', {}).get('state')
            self.assertTrue(state == 'unpaired')

        # check via userserice/usertokenlist the token status
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')

        response = self.make_userservice_request('usertokenlist',
                                                 params={},
                                                 auth_user=auth_user)

        jresp = json.loads(response.body)
        for token in jresp.get('result', {}).get('value', []):
            enrollment = token.get('Enrollment')
            self.assertTrue('not completed' in enrollment.get('status'))
            self.assertTrue('unpaired' in enrollment.get('detail'))

        return

    def test_tokeninfo_for_qrtoken(self):
        """ get token enrollment status for the qrtoken """

        params = {
            'name': 'qr_enrollment',
            'scope': 'authentication',
            'action': ('qrtoken_challenge_callback_url=foo://, '
                       'qrtoken_pairing_callback_sms=foo://'),
            'realm': '*',
            'user': '*'
        }

        response = self.make_system_request('setPolicy', params=params)
        self.assertTrue('setPolicy qr_enrollment' in response)
        self.assertTrue('false' not in response)

        params = {
            'type': 'qr',
            'pin': "Test123!",
            'serial': 'my_qr',
            'user': 'passthru_user1'
        }
        response = self.make_admin_request('init', params)
        self.assertTrue('my_qr' in response)

        # check via admin/show the token status
        params = {'serial': 'my_qr', 'tokeninfo_format': 'json'}
        response = self.make_admin_request('show', params)

        jresp = json.loads(response.body)
        for token in jresp.get('result', {}).get('value', {}).get('data', []):
            state = token.get('LinOtp.TokenInfo', {}).get('state')
            self.assertTrue(state == 'pairing_url_sent')

        # check via userserice/usertokenlist the token status
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')

        response = self.make_userservice_request('usertokenlist',
                                                 params={},
                                                 auth_user=auth_user)

        jresp = json.loads(response.body)
        for token in jresp.get('result', {}).get('value', []):
            enrollment = token.get('Enrollment')
            self.assertTrue('not completed' in enrollment.get('status'))
            self.assertTrue('pairing_url_sent' in enrollment.get('detail'))

        return

    def test_tokeninfo_for_ocra2(self):
        """ get token enrollment status for the ocra2 token """

        params = {'name': 'ocra2_enrollment',
                  'scope': 'authentication',
                  'realm': 'mydefrealm',
                  'user': '*', }
        params['action'] = (
            "qrtanurl_init.one=https://<user>:<password>/init/one/<serial>/, "
            "qrtanurl.one=https://<user>:<password>/one/<serial>/<transactionid>,"
        )

        response = self.make_system_request('setPolicy', params=params)
        self.assertTrue('setPolicy ocra2_enrollment' in response)
        self.assertTrue('false' not in response)

        params = {
            "serial": 'my_ocra2',
            'pin': "Test123!",
            'user': 'passthru_user1',
            'type': 'ocra2',
            'sharedsecret': '1',
            'genkey': '1',
            'ocrasuite': 'OCRA-1:HOTP-SHA1-6:QN06-T1M'
            }

        response = self.make_admin_request('init', params)
        self.assertTrue('false' not in response)

        # check via admin/show the token status
        params = {'serial': 'my_ocra2', 'tokeninfo_format': 'json'}
        response = self.make_admin_request('show', params)

        jresp = json.loads(response.body)
        for token in jresp.get('result', {}).get('value', {}).get('data', []):
            info = token.get('LinOtp.TokenInfo', {})
            self.assertTrue('rollout' in info)
            self.assertTrue('ocrasuite' in info)

        # check via userserice/usertokenlist the token status
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')

        response = self.make_userservice_request('usertokenlist',
                                                 params={},
                                                 auth_user=auth_user)

        jresp = json.loads(response.body)
        for token in jresp.get('result', {}).get('value', []):
            enrollment = token.get('Enrollment')
            self.assertTrue('not completed' in enrollment.get('status'))
            self.assertTrue('rollout' in enrollment)

        return

# eof #

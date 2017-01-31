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


""" used to do functional testing of the forward token"""

import logging
import json

from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestForwardToken(TestController):

    serials = []

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

    def create_HMAC_token(self):
        """
        """
        otps = {
            0: '870581',
            1: '793334',
            2: '088491',
            3: '013126',
            4: '818771',
            5: '454594',
            6: '217219',
            7: '250710',
            8: '478893',
            9: '517407',
               }
        parameters = {
                      "serial": "Target",
                      "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
                      "pin": "321!",
                      "description": "Target Token",
                      }

        response = self.make_admin_request('init', params=parameters)
        self.assertTrue('"value": true' in response, response)

        return (parameters['serial'], otps)

    def create_forward_token(self, target_serial):
        """
        create the forward token
        """
        param_fw = {"serial": "Forward",
                    "type": "forward",
                    "pin": "123!",
                    'forward.serial': target_serial,
                    }

        response = self.make_admin_request('init', params=param_fw)
        self.assertTrue('"value": true' in response, response)

        return param_fw['serial']

    def create_policy(self, params):
        name = params['name']
        response = self.make_system_request('setPolicy', params=params)
        self.assertTrue('setPolicy ' + name in response, response)

    def test_check_s(self):
        '''
        Checking auth forwarding with check_s
        '''
        target_serial, otps = self.create_HMAC_token()
        forward_serial = self.create_forward_token(target_serial)

        parameters = {"serial": target_serial, "pass": "321!" + otps[0]}
        response = self.make_validate_request('check_s', params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": forward_serial, "pass": "123!" + otps[1]}
        response = self.make_validate_request('check_s', params=parameters)
        self.assertTrue('"value": true' in response, response)

        return

    def test_check_s_challenge_response(self):
        '''
        Checking auth forwarding with check_s and challenge response
        '''
        target_serial, otps = self.create_HMAC_token()
        forward_serial = self.create_forward_token(target_serial)

        params = {'scope': 'authentication',
                  'action': 'challenge_response=forward,',
                  'realm': '*',
                  'user': '*',
                  'name': 'forward_challenge'}
        self.create_policy(params)

        parameters = {"serial": target_serial, "pass": "321!" + otps[0]}
        response = self.make_validate_request('check_s', params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": forward_serial, "pass": "123!"}
        response = self.make_validate_request('check_s', params=parameters)
        self.assertTrue('"value": false' in response, response)

        # now extract the transaction id and test the challenges
        jresp = json.loads(response.body)
        transid = jresp.get('detail', {}).get('transactionid')

        # same otp should not work
        parameters = {"serial": forward_serial, "pass": otps[0],
                      'transactionid': transid}
        response = self.make_validate_request('check_s', params=parameters)
        self.assertTrue('"value": false' in response, response)

        # new one should work
        parameters = {"serial": forward_serial, "pass": otps[1],
                      'transactionid': transid}
        response = self.make_validate_request('check_s', params=parameters)
        self.assertTrue('"value": true' in response, response)

        return

    def test_tokencounter_forwarding(self):
        '''
        Checking auth forwarding with check_s and fail counter forwarding
        '''
        target_serial, otps = self.create_HMAC_token()
        forward_serial = self.create_forward_token(target_serial)

        parameters = {"serial": target_serial, "pass": "321!" + otps[0]}
        response = self.make_validate_request('check_s', params=parameters)
        self.assertTrue('"value": true' in response, response)

        # check that fail counter is forwarded
        for i in [2, 3, 4, 5]:
            parameters = {"serial": forward_serial,
                          "pass": "123!" + '12378%d' % i}
            response = self.make_validate_request('check_s', params=parameters)
            self.assertTrue('"value": false' in response, response)

        parameters = {"serial": forward_serial}
        response = self.make_admin_request('show', params=parameters)
        self.assertTrue('"LinOtp.FailCount": 4' in response, response)

        parameters = {"serial": target_serial}
        response = self.make_admin_request('show', params=parameters)
        self.assertTrue('"LinOtp.FailCount": 4' in response, response)

        # check that otp counter matches and failcounter is reseted
        for i in [2, 3, 4, 5]:
            parameters = {"serial": forward_serial,
                          "pass": "123!" + otps[i]}
            response = self.make_validate_request('check_s', params=parameters)
            self.assertTrue('"value": true' in response, response)

        parameters = {"serial": forward_serial}
        response = self.make_admin_request('show', params=parameters)
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)
        self.assertTrue('"LinOtp.Count": 6' in response, response)

        parameters = {"serial": target_serial}
        response = self.make_admin_request('show', params=parameters)

        self.assertTrue('"LinOtp.FailCount": 0' in response, response)
        self.assertTrue('"LinOtp.Count": 6' in response, response)

    def test_tokencounter_not_forwarded(self):
        '''
        Checking auth forwarding with check_s and no_forwarding policy
        '''
        target_serial, otps = self.create_HMAC_token()
        forward_serial = self.create_forward_token(target_serial)

        params = {'scope': 'authentication',
                  'action': 'forwardtoken:no_failcounter_forwarding, ',
                  'realm': '*',
                  'user': '*',
                  'name': 'no_counter_forwarding'}
        self.create_policy(params)

        parameters = {"serial": target_serial, "pass": "321!" + otps[0]}
        response = self.make_validate_request('check_s', params=parameters)
        self.assertTrue('"value": true' in response, response)

        # check that fail counter is not forwarded
        for i in [2, 3, 4, 5]:
            parameters = {"serial": forward_serial,
                          "pass": "123!" + '12378%d' % i}
            response = self.make_validate_request('check_s', params=parameters)
            self.assertTrue('"value": false' in response, response)

        parameters = {"serial": forward_serial}
        response = self.make_admin_request('show', params=parameters)
        self.assertTrue('"LinOtp.FailCount": 4' in response, response)

        parameters = {"serial": target_serial}
        response = self.make_admin_request('show', params=parameters)
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)

        # check that otp counter matches and fail counter is reseted
        for i in [2, 3, 4, 5]:
            parameters = {"serial": forward_serial,
                          "pass": "123!" + otps[i]}
            response = self.make_validate_request('check_s', params=parameters)
            self.assertTrue('"value": true' in response, response)

        parameters = {"serial": forward_serial}
        response = self.make_admin_request('show', params=parameters)
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)
        self.assertTrue('"LinOtp.Count": 6' in response, response)

        parameters = {"serial": target_serial}
        response = self.make_admin_request('show', params=parameters)

        self.assertTrue('"LinOtp.FailCount": 0' in response, response)
        self.assertTrue('"LinOtp.Count": 6' in response, response)

    def test_check_owner(self):
        '''
        Checking auth forwarding with user check
        '''
        target_serial, otps = self.create_HMAC_token()
        forward_serial = self.create_forward_token(target_serial)

        parameters = {"serial": target_serial, "pass": "321!" + otps[0]}
        response = self.make_validate_request('check_s', params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": forward_serial, 'user': 'passthru_user1'}
        response = self.make_admin_request('assign', params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": forward_serial, 'pin': 'hugo'}
        response = self.make_admin_request('set', params=parameters)
        self.assertTrue('"set pin": 1' in response, response)

        # check that user is authenticated
        parameters = {"user": 'passthru_user1', "pass": "hugo" + otps[2]}
        response = self.make_validate_request('check', params=parameters)
        self.assertTrue('"value": true' in response, response)

        return

    def test_check_owner_otppin(self):
        '''
        Checking auth forwarding with user check and otppin policy
        '''
        target_serial, otps = self.create_HMAC_token()
        forward_serial = self.create_forward_token(target_serial)

        parameters = {"serial": target_serial, "pass": "321!" + otps[0]}
        response = self.make_validate_request('check_s', params=parameters)
        self.assertTrue('"value": true' in response, response)

        params = {'scope': 'authentication',
                  'action': 'otppin=1, ',
                  'realm': '*',
                  'user': '*',
                  'name': 'check_user_password'}
        self.create_policy(params)

        parameters = {"serial": forward_serial, 'user': 'passthru_user1'}
        response = self.make_admin_request('assign', params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": forward_serial, 'pin': 'hugo'}
        response = self.make_admin_request('set', params=parameters)
        self.assertTrue('"set pin": 1' in response, response)

        # check that user is authenticated
        parameters = {"user": 'passthru_user1', "pass": "geheim1" + otps[2]}
        response = self.make_validate_request('check', params=parameters)
        self.assertTrue('"value": true' in response, response)

        return

# eof #########################################################################

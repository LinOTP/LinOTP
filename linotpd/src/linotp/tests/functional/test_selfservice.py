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
"""

import logging
import json

from linotp.tests import TestController

log = logging.getLogger(__name__)



class TestSelfserviceController(TestController):

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def createPolicy(self, policy):
        response = self.make_system_request('setPolicy',
                                params={'name' : 'self01',
                                        'scope' : 'selfservice',
                                        'realm' : 'myDefRealm',
                                        'action' : policy,
                                        })
        assert '"status": true' in response
        assert '"setPolicy self01": {' in response

        return response

    def deleteToken(self, serial):
        response = self.make_admin_request('remove',
                                params={
                                    'serial': serial,
                                    })

        log.debug(response)

    def test_history(self):
        '''
        Selfservice: Testing history
        '''
        self.createPolicy("history")

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('history',
                                auth_user=auth_user)
        print(response)
        assert '"rows": [' in response

        response = self.make_selfservice_request('history',
                                auth_user=auth_user)
        print(response)
        assert 'view_audit_selfservice' in response

    def test_reset(self):
        '''
        Selfservice: Testing user reset
        '''

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('reset',
                                auth_user=auth_user)
        print(response)
        assert '"status": false' in response
        assert '"code": -311' in response

        self.createPolicy("reset")
        response = self.make_userselfservice_request('reset',
                                auth_user=auth_user)
        print(response)
        assert 'Missing parameter: ' in response
        assert '"code": 905' in response

        response = self.make_admin_request('init',
                                params={'serial':'reset01',
                                        'type': 'spass',
                                        'user': 'passthru_user1@myDefRealm',
                                        'pin': "secret"
                                        })
        print(response)
        assert '"status": true' in response

        for i in "12345678901234567890":
            response = self.make_validate_request('check',
                                    params={'user': 'passthru_user1@myDefRealm',
                                            'pass': 'wrongpass'})
            print(response)
            assert '"value": false' in response

        response = self.make_userselfservice_request('reset',
                                auth_user=auth_user,
                                params={'serial': 'reset01'})
        print(response)
        assert '"status": true' in response
        assert '"reset Failcounter": 1' in response

        response = self.make_validate_request('check',
                                params={'user': 'passthru_user1@myDefRealm',
                                        'pass': 'secret'})
        print(response)
        assert '"value": true' in response

        response = self.make_selfservice_request('reset',
                                auth_user=auth_user)
        print(response)
        assert "<div id='resetform'>" in response

    def test_resync(self):
        '''
        Selfservice: Testing user resync
        '''

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('resync',
                                auth_user=auth_user)
        print(response)
        assert '"status": false' in response
        assert '"code": -311' in response

        self.createPolicy("resync")
        response = self.make_userselfservice_request('resync',
                                auth_user=auth_user)
        print(response)
        assert 'Missing parameter' in response
        assert '"code": 905' in response

        response = self.make_admin_request('init',
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'user': 'passthru_user1@myDefRealm',
                                        'pin': "secret",
                                        'otpkey': '6161e082d736d3d9d67bc1d4711ff1a81af26160'
                                        })
        print(response)
        assert '"status": true' in response

        response = self.make_userselfservice_request('resync',
                                auth_user=auth_user,
                                params={'serial': 'XXXX',
                                        "otp1": "359864",
                                        "otp2": "348448" })
        print(response)
        assert '"status": false' in response
        assert 'no token found!' in response

        response = self.make_userselfservice_request('resync',
                                auth_user=auth_user,
                                params={'serial': 'token01',
                                        "otp1": "885497",
                                        "otp2": "696793" })
        print(response)
        assert '"status": true' in response
        assert '"resync Token": true' in response

        response = self.make_selfservice_request('resync',
                                auth_user=auth_user)
        print(response)
        assert "<div id='resyncform'>" in response



    def test_setmpin(self):
        '''
        Selfservice: setting mOTP PIN
        '''

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('setmpin',
                                auth_user=auth_user,
                                params={'serial': 'XXXX',
                                        'pin': '1234'})
        print(response)
        assert '"status": false' in response
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy("setMOTPPIN")
        response = self.make_userselfservice_request('setmpin',
                                auth_user=auth_user)
        print(response)
        assert "Missing parameter: ''pin''" in response
        assert '"code": 905' in response


        response = self.make_admin_request('init',
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'user': 'passthru_user1@myDefRealm',
                                        'pin': "secret",
                                        'otpkey': '6161e082d736d3d9d67bc1d4711ff1a81af26160'
                                        })
        print(response)
        assert '"status": true' in response

        response = self.make_userselfservice_request('setmpin',
                                auth_user=auth_user,
                                params={'serial': 'token01',
                                        'pin': '1234'})
        print(response)
        assert '"status": true' in response
        assert '"set userpin": 1' in response

        response = self.make_selfservice_request('setmpin',
                                auth_user=auth_user)
        print(response)
        assert "<div id='passwordform'>" in response


    def test_setpin(self):
        '''
        Selfservice: testing setting PIN
        '''
        response = self.make_admin_request('init',
                                params={'serial':'spass01',
                                        'type': 'spass',
                                        'user': 'passthru_user1@myDefRealm',
                                        })
        print(response)
        assert '"status": true' in response

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('setpin',
                                auth_user=auth_user,
                                params={'serial': 'spass01',
                                        'pin': '1234'})
        print(response)
        assert '"status": false' in response
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy("setOTPPIN")
        response = self.make_userselfservice_request('setpin',
                                auth_user=auth_user)
        print(response)
        assert "Missing parameter: ''userpin''" in response
        assert '"code": 905' in response


        response = self.make_userselfservice_request('setpin',
                                auth_user=auth_user,
                                params={'serial': 'spass01',
                                        'userpin': 'secretPin'})
        print(response)
        assert '"status": true' in response
        assert '"set userpin": 1' in response

        response = self.make_validate_request('check',
                                params={'user': 'passthru_user1@myDefRealm',
                                        'pass': 'secretPin'})
        print(response)
        assert '"status": true' in response
        assert '"value": true' in response

        response = self.make_selfservice_request('setpin',
                                auth_user=auth_user)
        print(response)
        assert "<div id='passwordform'>" in response

        # testing the index and the list of the tokens
        response = self.make_selfservice_request('index',
                                auth_user=auth_user)

        print("%r" % response)

    def test_get_serial_by_otp(self):
        '''
        selfservice: get serial by otp value
        '''
        self.deleteToken('token01')

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('getSerialByOtp',
                                auth_user=auth_user,
                                params={'type': 'hmac',
                                        'otp': '885497'})
        print(response)
        assert '"status": false' in response
        assert '"message": "ERR410: The policy settings do not allow you to request a serial by OTP!"' in response

        response = self.make_admin_request('init',
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d'
                                        })
        print(response)
        assert '"status": true' in response

        self.createPolicy("getserial")
        response = self.make_userselfservice_request('getSerialByOtp',
                                auth_user=auth_user,
                                params={'type': 'hmac',
                                        'otp': '459812'})
        print(response)
        # The token is not found, as it is not in the realm of the user
        assert '"serial": ""' in response

        response = self.make_admin_request('tokenrealm',
                                params={'serial': 'token01',
                                        'realms': 'myDefRealm'})
        print(response)
        assert '"value": 1' in response

        # NOw the token is found
        response = self.make_userselfservice_request('getSerialByOtp',
                                auth_user=auth_user,
                                params={'type': 'hmac',
                                        'otp': '459812'})
        print(response)
        assert '"serial": "token01"' in response

    def test_assign(self):
        '''
        selfservice: testing assign token and unassign token
        '''
        self.deleteToken('token01')

        # init token
        response = self.make_admin_request('init',
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d'
                                        })
        print(response)
        assert '"status": true' in response

        # put into realm
        response = self.make_admin_request('tokenrealm',
                                params={'serial': 'token01',
                                        'realms': 'myDefRealm'})
        print(response)
        assert '"value": 1' in response

        # Now try to assign

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('assign',
                            auth_user=auth_user, params={'serial': 'token01'})

        print(response)
        assert '"message": "ERR410: ' in response

        self.createPolicy("assign")
        response = self.make_userselfservice_request('assign',
                                auth_user=auth_user,
                                params={'serial': 'token01'})
        print(response)
        assert '"assign token": true' in response

        # unassign
        response = self.make_userselfservice_request('unassign',
                                auth_user=auth_user,
                                params={'serial': 'token01'})
        print(response)
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy("unassign")
        response = self.make_userselfservice_request('unassign',
                                auth_user=auth_user,
                                params={'serial': 'token01'})
        print(response)
        assert '"unassign token": true' in response

        # UI
        response = self.make_selfservice_request('assign',
                                auth_user=auth_user)
        print(response)
        assert "<div id='assignform'>" in response

        response = self.make_selfservice_request('unassign',
                                auth_user=auth_user)
        print(response)
        assert "<div id='unassignform'>" in response


    def test_delete(self):
        '''
        selfservice: testing deleting token
        '''
        self.deleteToken('token01')

        response = self.make_admin_request('init',
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d',
                                        'user': 'passthru_user1@myDefRealm'
                                        })
        print(response)
        assert '"status": true' in response

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('delete',
                                auth_user=auth_user,
                                params={'serial': 'token01'})
        print(response)
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy("delete")
        response = self.make_userselfservice_request('delete',
                                auth_user=auth_user,
                                params={'serial': 'token01'})
        print(response)
        assert '"delete token": 1' in response

        # UI
        response = self.make_selfservice_request('delete',
                                auth_user=auth_user)
        print(response)
        assert "<div id='deleteform'>" in response

    def test_disable(self):
        '''
        selfservice: testing disable and enable token
        '''
        self.deleteToken('token01')

        response = self.make_admin_request('init',
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d',
                                        'user': 'passthru_user1@myDefRealm'
                                        })
        print(response)
        assert '"status": true' in response

        # disable

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('disable',
                                auth_user=auth_user,
                                params={'serial': 'token01'})
        print(response)
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy("disable")
        response = self.make_userselfservice_request('disable',
                                auth_user=auth_user,
                                params={'serial': 'token01'})
        print(response)
        assert '"disable token": 1' in response

        response = self.make_admin_request('show',
                                params={'serial': 'token01'})
        print(response)
        assert '"LinOtp.TokenSerialnumber": "token01",' in response
        assert '"LinOtp.Isactive": false' in response

        # now enable again

        response = self.make_userselfservice_request('enable',
                                auth_user=auth_user,
                                params={'serial': 'token01'})
        print(response)
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy("enable")
        response = self.make_userselfservice_request('enable',
                                auth_user=auth_user,
                                params={'serial': 'token01'})
        print(response)
        assert '"enable token": 1' in response

        response = self.make_admin_request(
                        'show', params={'serial': 'token01'})
        print(response)
        assert '"LinOtp.TokenSerialnumber": "token01",' in response
        assert '"LinOtp.Isactive": true' in response

        # UI
        response = self.make_selfservice_request('disable',
                                auth_user=auth_user)
        print(response)
        assert "<div id='disableform'>" in response

        response = self.make_selfservice_request('enable',
                                auth_user=auth_user)
        print(response)
        assert "<div id='enableform'>" in response

    def test_init(self):
        '''
        selfservice: testing enrollment of token as normal user
        '''
        self.deleteToken('token01')

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('enroll',
                                auth_user=auth_user,
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d'
                                        })
        print(response)
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy('enrollHMAC')

        response = self.make_userselfservice_request('enroll',
                                auth_user=auth_user,
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d'
                                        })
        print(response)
        assert '"status": true' in response

        response = self.make_admin_request(
                        'show', params={'serial': 'token01'})
        print(response)
        assert '"LinOtp.TokenSerialnumber": "token01",' in response
        assert '"LinOtp.Isactive": true' in response

    def test_enroll_onetime_spass(self):
        '''
        selfservice: testing enrollment of a onetime spass token as normal user
        '''
        self.deleteToken('token01')

        ''' Verify that the relevant policy is required '''

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('enroll',
                                auth_user=auth_user,
                                params={'serial':'token01',
                                        'type': 'spass',
                                        'pin': '!token0secret!'
                                        })
        print(response)
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        ''' Verify that a spass token is properly created '''
        self.createPolicy('enrollSPASS')

        response = self.make_userselfservice_request('enroll',
                                auth_user=auth_user,
                                params={'serial':'token01',
                                        'type': 'spass',
                                        'onetime': 'true',
                                        'pin': '!token0secret!'
                                        })
        print(response)
        assert '"status": true' in response

        response = self.make_admin_request(
                        'show', params={'serial': 'token01'})
        print(response)
        assert '"LinOtp.TokenSerialnumber": "token01",' in response
        assert '"LinOtp.Isactive": true' in response

        ''' Verify this spass works once... '''
        parameters = {
                      "user"     : 'passthru_user1@myDefRealm',
                      "pass"     : '!token0secret!',
                      }
        response = self.make_validate_request('check', params=parameters)
        assert '"status": true' in response
        assert '"value": true'  in response

        ''' ... and exactly once '''
        response = self.make_validate_request('check', params=parameters)
        assert '"status": true' in response
        assert '"value": false'  in response

    def test_webprovision(self):
        '''
        selfservice: testing user webprovision
        '''
        self.deleteToken('token01')

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('webprovision',
                                auth_user=auth_user,
                                params={'serial':'token01',
                                        'type': 'hmac'})

        message = ("You provided hmac")
        assert message in response.json['result']['error']['message'], response

        response = self.make_userselfservice_request('webprovision',
                                auth_user=auth_user,
                                params={'serial':'token01',
                                        'type': 'googleauthenticator'
                                        })

        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response,response

        self.createPolicy('webprovisionGOOGLE')

        response = self.make_userselfservice_request('webprovision',
                                auth_user=auth_user,
                                params={'prefix':'LSGO',
                                        'type': 'googleauthenticator'
                                        })
        assert '"url": "otpauth://hotp/LinOTP:LSGO' in response, \
                        response

        # test
        response = self.make_admin_request(
                    'show', params={'user': 'passthru_user1@myDefRealm'})
        assert '"LinOtp.TokenSerialnumber": "LSGO' in response,response
        assert '"LinOtp.Isactive": true' in response, response

        # UI

        response = self.make_selfservice_request('webprovisiongoogletoken',
                                auth_user=auth_user)
        assert "googletokenform" in response.body, response

        return

    def test_getmultiotp(self):
        '''selfservice: testing getting multiple otps.

        1. user has no policy to lookup hotp otps, only for totp token
          -> the lookup will fail
        2. define system policy which allows the hotp lookup
          -> the lookup will be successfull
        '''

        user = 'passthru_user1@myDefRealm'
        selfservice_user = {
            'login': user,
            'password': 'geheim1'
        }

        serial = 'multi_otp'
        params = {
            'type': 'hmac',
            'serial': serial,
            'genkey': 1,
            'user': user
            }

        response = self.make_admin_request('init', params=params)
        assert "googleurl" in response, response

        # ----------------------------------------------------------------- --

        # 1. user  is not allowed to lookup hotp otps only totp

        policy = {
            'name': 'user',
            'action': 'max_count_totp=5,',
            'user': 'passthru_user1',
            'realm': '*',
            'scope': 'selfservice',
            'active': True,
        }

        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response

        params={
            'serial': serial,
            'count': 5
        }

        response = self.make_userselfservice_request(
            'getmultiotp', params=params, auth_user=selfservice_user)

        assert not response.json['result']['status']

        # ----------------------------------------------------------------- --

        # 2. in general its now allowed to lookup hotp otps

        policy = {
            'name': 'general',
            'action': 'max_count_hotp=10,',
            'user': ' *',
            'realm': '*',
            'scope': 'selfservice',
            'active': True,
        }

        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response

        params={
            'serial': serial,
            'count': 5
        }

        response = self.make_userselfservice_request(
            'getmultiotp', params=params, auth_user=selfservice_user)

        jresp = response.json
        assert jresp['result']['value']['type'] == "HMAC"
        otps = jresp['result']['value']['otp']

        assert len(otps) == 5

    def test_privilege_escalation_fix(self):

        """
        Check if logged in users can not see token data
        of another user through /userservice/context

        refers LINOTP-702
        """

        auth_user = {
             'login': 'passthru_user1@myDefRealm',
             'password': 'geheim1'}

        response = self.make_userselfservice_request('context',
                                auth_user=auth_user,
                                params={'user': 'hans'})

        response_dict = json.loads(response.body)

        user = response_dict['detail']['user']['username']
        assert user == 'passthru_user1'

    def test_setdescription(self):
        '''
        selfservice: testing set token description as normal user
        '''

        policy = {
            'name': 'T1',
            'action': 'setDescription',
            'user': ' *',
            'realm': '*',
            'scope': 'selfservice'
        }

        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response

        user = 'passthru_user1@myDefRealm'
        selfservice_user = {
            'login': user,
            'password': 'geheim1'
        }

        serial = 'set_description_token'
        params = {
            'type': 'hmac',
            'serial': serial,
            'genkey': 1,
            'user': user
            }

        response = self.make_admin_request('init', params=params)
        assert "googleurl" in response, response

        params={
            'serial': serial,
            'description': 'my super token'
        }

        response = self.make_userselfservice_request(
            'setdescription', params=params, auth_user=selfservice_user)

        assert '"set description": 1' in response

        response = self.make_admin_request('show', params={'serial': serial})
        assert 'my super token' in response

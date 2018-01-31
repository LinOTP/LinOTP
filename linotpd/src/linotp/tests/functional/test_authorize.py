# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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

import datetime

from linotp.tests import TestController


class TestAuthorizeController(TestController):
    '''
    This test tests the authorization policies

    scope: authorization
    action: authorize
    realm:
    user:
    client:

        /validate/check
        /validate/simplecheck
        get_multi_otp
    '''

    def setUp(self):
        '''
        This sets up all the resolvers and realms
        '''
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

        self.curTime = datetime.datetime(2012, 5, 16, 9, 0, 52, 227413)
        self.TOTPcurTime = datetime.datetime.fromtimestamp(1337292860.585256)
        self.initToken()

    def tearDown(self):
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    ##########################################################################

    def createPWToken(self, serial, pin="", pw=""):
        '''
        creates the test tokens
        '''
        parameters = {
            "serial": serial,
            "type": "PW",
            # 64 byte key
            "otpkey": pw,
            "otppin": pin,
            "otplen": len(pw),
            "description": "PW testtoken",
        }

        response = self.make_admin_request(action='init',
                                           params=parameters)
        self.assertTrue('"value": true' in response, response)

    def setTokenRealm(self, serial, realms):
        parameters = {"serial": serial,
                      "realms": realms}

        response = self.make_admin_request(action="tokenrealm",
                                           params=parameters)
        return response

    def setPolicy(self, parameters):
        response = self.make_system_request(action='setPolicy',
                                            params=parameters)
        self.assertTrue('"status": true' in response, response)
        # check for policy
        response = self.make_system_request(action='getPolicy',
                                            params=parameters)
        self.assertTrue('"action": ' in response, response)

    def initToken(self):
        '''
        init one DPW token
        '''

        self.createPWToken("pw1", pin="1234", pw="secret1")
        resp = self.make_admin_request(action='assign',
                                       params={'user': 'localuser',
                                               'serial': 'pw1'})
        self.assertTrue('"status": true' in resp, resp)
        resp = self.make_admin_request(action='set',
                                       params={'pin': '1234',
                                               'serial': 'pw1'})
        self.assertTrue('"status": true' in resp, resp)

        self.createPWToken("pw2", pin="1234", pw="secret2")
        resp = self.make_admin_request(action='assign',
                                       params={'user': 'horst',
                                               'serial': 'pw2'})
        self.assertTrue('"status": true' in resp, resp)
        resp = self.make_admin_request(action='set',
                                       params={'pin': '1234',
                                               'serial': 'pw2'})
        self.assertTrue('"status": true' in resp, resp)

    def create_policy(self):
        '''
        create the policy
        '''
        response = self.make_system_request(action="setConfig",
                                            params={"mayOverwriteClient": None})
        self.assertTrue('"status": true' in response, response)

        parameters1 = {'name': 'authorization1',
                       'scope': 'authorization',
                       'realm': '*',
                       'action': 'authorize',
                       'user': 'localuser',
                       'client': '172.16.200.0/24'
                       }
        self.setPolicy(parameters1)

    def create_policy2(self):
        '''
        create the policy
        '''
        response = self.make_system_request(action="setConfig",
                                            params={"mayOverwriteClient": None})
        self.assertTrue('"status": true' in response, response)

        parameters1 = {'name': 'authorization1',
                       'scope': 'authorization',
                       'realm': '*',
                       'action': 'authorize',
                       'user': 'horst',
                       'client': '172.16.200.0/24'
                       }
        self.setPolicy(parameters1)

    def create_policy3(self):
        '''
        create the policy
        '''
        response = self.make_system_request(action="setConfig",
                                            params={"mayOverwriteClient": None})
        self.assertTrue('"status": true' in response, response)

        parameters1 = {'name': 'authorization1',
                       'scope': 'authorization',
                       'realm': '*',
                       'action': 'authorize',
                       'user': '',
                       'client': '10.0.0.0/8'
                       }
        self.setPolicy(parameters1)

    def test_00_localuser_allowed(self):
        '''
        Auth Test 00: Without policy the user is authorized to login
        '''
        parameters = {'user': 'localuser',
                      'pass': '1234secret1'}
        client = '172.16.200.10'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_00_horst_allowed(self):
        '''
        Auth Test 00: without policy the user host is allowed
        '''
        parameters = {'user': 'horst',
                      'pass': '1234secret2'}
        client = '172.16.200.10'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_01_localuser_allowed(self):
        '''
        Auth Test 01: test if localuser is allowed to authenticate
        '''
        self.create_policy()

        parameters = {'user': 'localuser',
                      'pass': '1234secret1'}
        client = '172.16.200.10'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_02_horst_not_allowed(self):
        '''
        Auth Test 02: test if horst is not allowed to authenticate. horst is not authorized, since he is not mentioned in the policy1 as user.
        '''
        parameters = {'user': 'horst',
                      'pass': '1234secret2'}
        client = '172.16.200.10'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": false' in response, response)

    def test_03_localuser_not_allowed(self):
        '''
        Auth Test 03: localuser is not allowed to authenticate to another host than 172.16.200.X
        localuser is not authorized, since he tries to login to 10.1.1.3
        '''
        parameters = {'user': 'localuser',
                      'pass': '1234secret1'}
        client = '10.1.1.3'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": false' in response, response)

    def test_04_horst_allowed(self):
        '''
        Auth Test 04: Now we set a new policy, and horst should be allowed
        '''
        self.create_policy2()

        parameters = {'user': 'horst',
                      'pass': '1234secret2'}
        client = '172.16.200.10'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_05_blank_user(self):
        '''
        Auth Test 05: test if blank users are working for all users
        '''
        self.create_policy3()

        parameters = {'user': 'horst',
                      'pass': '1234secret2'}
        client = '10.0.1.2'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)


# ############################################################################
#
# PIN Policy tests
#
# There are two users in def-passwd:
#    localuser -> password test123
#    horst    -> password test123

    def test_06_a_pinpolicy(self):
        '''
        Auth Test 06 a: check a client policy with password PIN on one client
        '''

        # deleting authorization policy
        self.delete_policy("authorization1")

        # setting pin policy
        parameters = {'name': 'pinpolicy1',
                      'scope': 'authentication',
                      'realm': '*',
                      'action': 'otppin=1',
                      'user': '',
                      'client': '10.0.0.0/8'
                      }

        self.setPolicy(parameters)

        parameters = {'user': 'horst',
                      'pass': 'test123secret2'}
        client = '10.0.1.2'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_06_b_named_pinpolicy(self):
        '''
        Auth Test 06 b: check a client policy with named password PIN on client
        '''

        # setting pin policy
        parameters = {'name': 'pinpolicy1',
                      'scope': 'authentication',
                      'realm': '*',
                      'action': 'otppin=password',
                      'user': '',
                      'client': '10.0.0.0/8'
                      }

        self.setPolicy(parameters)

        parameters = {'user': 'horst',
                      'pass': 'test123secret2'}
        client = '10.0.1.2'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_07_pinpolicy(self):
        '''
        Auth Test 07: check on a client, that is not contained in policy => authenticate with OTP PIN
        '''

        parameters = {'user': 'horst',
                      'pass': '1234secret2'}
        client = '192.168.200.10'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_08_pinpolicy(self):
        '''
        Auth Test 08: check user on client, but user not contained in policy for this client => authenticate with OTP PIN
        '''
        parameters = {'name': 'pinpolicy2',
                      'scope': 'authentication',
                      'realm': '*',
                      'action': 'otppin=1',
                      'user': 'horst',
                      'client': '172.16.200.0/8'
                      }
        self.setPolicy(parameters)

        parameters = {'user': 'localuser',
                      'pass': '1234secret1'}
        client = '172.16.200.10'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

##########################################################################
#
# Toke Type tests
#
    def test_10_tokentype(self):
        '''
        Auth Test 10: client not in policy. So every tokentype should be able to authenticate
        '''
        # clear pin policy
        self.delete_policy("pinpolicy1")
        self.delete_policy("pinpolicy2")
        #
        #
        #
        parameters = {'name': 'tokentypepolicy1',
                      'scope': 'authorization',
                      'realm': '*',
                      'action': 'tokentype=HMAC',
                      'user': 'horst',
                      'client': '172.16.200.0/24'
                      }
        self.setPolicy(parameters)

        parameters = {'user': 'horst',
                      'pass': '1234secret2'}
        client = '10.0.0.2'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_11_tokentype(self):
        '''
        Auth Test 11: Tokentype policy contains list of tokentypes. A token is allowed to authenticate
        '''
        parameters = {'name': 'tokentypepolicy1',
                      'scope': 'authorization',
                      'realm': '*',
                      'action': 'tokentype=HMAC MOTP PW',
                      'user': 'horst',
                      'client': '172.16.200.0/24'
                      }
        self.setPolicy(parameters)

        parameters = {'user': 'horst',
                      'pass': '1234secret2'}
        client = '172.16.200.10'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_12_tokentype(self):
        '''
        Auth Test 12: Tokentype policy contains list of tokentypes. the tokentype is not contained and not allowed to authenticate
        '''
        parameters = {'name': 'tokentypepolicy1',
                      'scope': 'authorization',
                      'realm': '*',
                      'action': 'tokentype=HMAC MOTP TOTP',
                      'user': 'horst',
                      'client': '172.16.200.0/24'
                      }
        self.setPolicy(parameters)

        parameters = {'user': 'horst',
                      'pass': '1234secret2'}
        client = '172.16.200.10'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": false' in response, response)

    def test_13_tokentype(self):
        '''
        Auth Test 13: Tokentype policy contains '*' and the token type is allowed to authenticate.
        '''
        parameters = {'name': 'tokentypepolicy1',
                      'scope': 'authorization',
                      'realm': '*',
                      'action': 'tokentype=HMAC * TOTP MOTP',
                      'user': 'horst',
                      'client': '172.16.200.0/24'
                      }
        self.setPolicy(parameters)

        parameters = {'user': 'horst',
                      'pass': '1234secret2'}
        client = '172.16.200.10'
        response = self.make_validate_request(action='check',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

        self.delete_policy("tokentypepolicy1")

##########################################################################
#
# SMSText test
#
    def test_14_smstext(self):
        '''
        TODO: Testing policy for smstext
        '''
        pass

##########################################################################
#
#  AutoSMS

    def test_20_autosms(self):
        '''
        Auth Test 20: autosms enabled with no client and no user. Will do for all clients in a realm
        '''
        self.setPolicy({'name': 'autosms',
                        'scope': 'authentication',
                        'realm': '*',
                        'action': 'autosms',
                        })

        parameters = {'user': 'horst'}
        client = '1.2.3.4'
        response = self.make_t_esting_request(action='autosms',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_21_autosms(self):
        '''
        Auth Test 21: autosms enabled for a client. Will send autosms for a client in the subnet
        '''
        self.setPolicy({'name': 'autosms',
                        'scope': 'authentication',
                        'realm': '*',
                        'action': 'autosms',
                        'client': '172.16.200.0/24'
                        })

        parameters = {'user': 'horst'}
        client = '172.16.200.123'
        response = self.make_t_esting_request(action='autosms',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_22_autosms(self):
        '''
        Auth Test 22: autosms enabled for a client. Will not send autosms for a client outside this subnet
        '''
        self.setPolicy({'name': 'autosms',
                        'scope': 'authentication',
                        'realm': '*',
                        'action': 'autosms',
                        'client': '172.16.200.0/24'
                        })

        parameters = {'user': 'horst'}
        client = '192.168.20.1'
        response = self.make_t_esting_request(action='autosms',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": false' in response, response)

    def test_23_autosms(self):
        '''
        Auth Test 23: autosms enabled for a client and for a user. Will send autosms for this user
        '''
        self.setPolicy({'name': 'autosms',
                        'scope': 'authentication',
                        'realm': '*',
                        'action': 'autosms',
                        'client': '172.16.200.0/24',
                        'user': 'horst'
                        })

        parameters = {'user': 'horst'}
        client = '172.16.200.10'
        response = self.make_t_esting_request(action='autosms',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": true' in response, response)

    def test_24_autosms(self):
        '''
        Auth Test 24: autosms enabled for a client and for a user. Will not send autosms for another user
        '''
        self.setPolicy({'name': 'autosms',
                        'scope': 'authentication',
                        'realm': '*',
                        'action': 'autosms',
                        'client': '172.16.200.0/24',
                        'user': 'horst'
                        })

        parameters = {'user': 'localuser'}
        client = '172.16.200.10'
        response = self.make_t_esting_request(action='autosms',
                                              params=parameters,
                                              client=client)

        self.assertTrue('"value": false' in response, response)

###################################################################
#
#   set realm tests
#
    def test_31_setrealm(self):
        '''
        Auth Test 31: setrealm for a user in the not default realm.
        '''
        self.setPolicy({"name": "setrealm",
                        "scope": "authorization",
                        "realm": "*",
                        "action": "setrealm=mydefrealm",
                        "client": "10.0.0.0/8"})
        parameters = {'user': 'horst',
                      'pass': '1234secret2',
                      'realm': 'realm_does_not_exist'}
        client = '10.0.0.1'
        response = self.make_validate_request(action="check",
                                              params=parameters,
                                              client=client)
        self.assertTrue('"value": true' in response, response)

    def test_32_setrealm(self):
        '''
        Auth Test 32: setrealm for a user, but user provides wrong password
        '''
        parameters = {'user': 'horst',
                      'pass': '1234secret2xxxx',
                      'realm': 'realm_does_not_exist'}
        client = '10.0.0.1'
        response = self.make_validate_request(action="check",
                                              params=parameters,
                                              client=client)
        self.assertTrue('"value": false' in response, response)

    def test_33_setrealm(self):
        '''
        Auth Test 33: setrealm, but not for the right client
        '''
        parameters = {'user': 'horst',
                      'pass': '1234secret2',
                      'realm': 'realm_does_not_exist'}
        client = '172.0.0.1'
        response = self.make_validate_request(action="check",
                                              params=parameters,
                                              client=client)
        self.assertTrue('"value": false' in response, response)

    def test_34_setrealm(self):
        '''
        Auth Test 34: setrealm, rewrite realm to a not existing realm. Auth will fail
        '''
        self.setPolicy({"name": "setrealm",
                        "scope": "authorization",
                        "realm": "defRealm realm2 realm3",
                        "action": "setrealm=not_existing",
                        "client": "10.0.0.0/8"})

        parameters = {'user': 'horst',
                      'pass': '1234secret2',
                      'realm': 'defRealm'}
        client = '10.0.0.1'
        response = self.make_validate_request(action="check",
                                              params=parameters,
                                              client=client)
        self.assertTrue('"value": false'in response, response)

    def test_99_setrealm(self):

        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_realms()


# eof #########################################################################

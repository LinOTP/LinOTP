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
"""

import logging

from linotp.tests import TestController, url

log = logging.getLogger(__name__)



class TestSelfserviceController(TestController):

    def setUp(self):
        TestController.setUp(self)
        self.set_config_selftest()
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def createPolicy(self, policy):
        response = self.app.get(url(controller='system', action='setPolicy'),
                                params={'name' : 'self01',
                                        'scope' : 'selfservice',
                                        'realm' : 'myDefRealm',
                                        'action' : policy,
                                        'selftest_admin' : 'superadmin'
                                        })
        print response
        assert '"status": true' in response
        assert '"setPolicy self01": {' in response


    def deleteToken(self, serial):
        response = self.app.get(url(controller='admin', action='remove'),
                                params={'serial': serial,
                                        'selftest_admin' : 'superadmin'})

        log.debug(response)

    def test_history(self):
        '''
        Selfservice: Testing history
        '''
        self.createPolicy("history")

        response = self.app.get(url(controller='userservice', action='history'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert '"rows": [' in response

        response = self.app.get(url(controller='selfservice', action='history'),
                                params={'selftest_user':'root@myDefRealm'})
        print response
        assert 'view_audit_selfservice' in response

    def test_reset(self):
        '''
        Selfservice: Testing user reset
        '''
        response = self.app.get(url(controller='userservice', action='reset'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert '"status": false' in response
        assert '"code": -311' in response

        self.createPolicy("reset")
        response = self.app.get(url(controller='userservice', action='reset'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert 'Missing parameter: ' in response
        assert '"code": 905' in response

        response = self.app.get(url(controller='admin', action='init'),
                                params={'serial':'reset01',
                                        'type': 'spass',
                                        'user': 'root',
                                        'pin': "secret"
                                        })
        print response
        assert '"status": true' in response

        for i in "12345678901234567890":
            response = self.app.get(url(controller='validate', action='check'),
                                    params={'user': 'root',
                                            'pass': 'wrongpass'})
            print response
            assert '"value": false' in response

        response = self.app.get(url(controller='userservice', action='reset'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'serial': 'reset01'})
        print response
        assert '"status": true' in response
        assert '"reset Failcounter": 1' in response

        response = self.app.get(url(controller='validate', action='check'),
                                params={'user': 'root',
                                        'pass': 'secret'})
        print response
        assert '"value": true' in response

        response = self.app.get(url(controller='selfservice', action='reset'),
                                params={'selftest_user':'root@myDefRealm'})
        print response
        assert "<div id='resetform'>" in response

    def test_resync(self):
        '''
        Selfservice: Testing user resync
        '''
        response = self.app.get(url(controller='userservice', action='resync'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert '"status": false' in response
        assert '"code": -311' in response

        self.createPolicy("resync")
        response = self.app.get(url(controller='userservice', action='resync'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert 'Missing parameter' in response
        assert '"code": 905' in response

        response = self.app.get(url(controller='admin', action='init'),
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'user': 'root',
                                        'pin': "secret",
                                        'otpkey': '6161e082d736d3d9d67bc1d4711ff1a81af26160'
                                        })
        print response
        assert '"status": true' in response

        response = self.app.get(url(controller='userservice', action='resync'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'serial': 'XXXX',
                                        "otp1": "359864",
                                        "otp2": "348448" })
        print response
        assert '"status": false' in response
        assert 'no token found!' in response

        response = self.app.get(url(controller='userservice', action='resync'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'serial': 'token01',
                                        "otp1": "885497",
                                        "otp2": "696793" })
        print response
        assert '"status": true' in response
        assert '"resync Token": true' in response

        response = self.app.get(url(controller='selfservice', action='resync'),
                                params={'selftest_user':'root@myDefRealm'})
        print response
        assert "<div id='resyncform'>" in response



    def test_setmpin(self):
        '''
        Selfservice: setting mOTP PIN
        '''

        response = self.app.get(url(controller='userservice', action='setmpin'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'serial': 'XXXX',
                                        'pin': '1234'})
        print response
        assert '"status": false' in response
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy("setMOTPPIN")
        response = self.app.get(url(controller='userservice', action='setmpin'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert 'Missing parameter: \'pin\'' in response
        assert '"code": 905' in response


        response = self.app.get(url(controller='admin', action='init'),
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'user': 'root',
                                        'pin': "secret",
                                        'otpkey': '6161e082d736d3d9d67bc1d4711ff1a81af26160'
                                        })
        print response
        assert '"status": true' in response

        response = self.app.get(url(controller='userservice', action='setmpin'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'serial': 'token01',
                                        'pin': '1234'})
        print response
        assert '"status": true' in response
        assert '"set userpin": 1' in response

        response = self.app.get(url(controller='selfservice', action='setmpin'),
                                params={'selftest_user':'root@myDefRealm'})
        print response
        assert "<div id='passwordform'>" in response


    def test_setpin(self):
        '''
        Selfservice: testing setting PIN
        '''
        response = self.app.get(url(controller='admin', action='init'),
                                params={'serial':'spass01',
                                        'type': 'spass',
                                        'user': 'root',
                                        })
        print response
        assert '"status": true' in response

        response = self.app.get(url(controller='userservice', action='setpin'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'serial': 'spass01',
                                        'pin': '1234'})
        print response
        assert '"status": false' in response
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy("setOTPPIN")
        response = self.app.get(url(controller='userservice', action='setpin'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert 'Missing parameter: \'userpin\'' in response
        assert '"code": 905' in response


        response = self.app.get(url(controller='userservice', action='setpin'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'serial': 'spass01',
                                        'userpin': 'secretPin'})
        print response
        assert '"status": true' in response
        assert '"set userpin": 1' in response

        response = self.app.get(url(controller='validate', action='check'),
                                params={'user': 'root@myDefRealm',
                                        'pass': 'secretPin'})
        print response
        assert '"status": true' in response
        assert '"value": true' in response

        response = self.app.get(url(controller='selfservice', action='setpin'),
                                params={'selftest_user':'root@myDefRealm'})
        print response
        assert "<div id='passwordform'>" in response

        # testing the index and the list of the tokens
        response = self.app.get(url(controller='selfservice', action='index'),
                                params={'selftest_user': 'root@myDefRealm'})

        print "%r" % response

    def test_get_serial_by_otp(self):
        '''
        selfservice: get serial by otp value
        '''
        self.deleteToken('token01')

        response = self.app.get(url(controller='userservice', action='getSerialByOtp'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'type': 'hmac',
                                        'otp': '885497'})
        print response
        assert '"status": false' in response
        assert '"message": "ERR410: The policy settings do not allow you to request a serial by OTP!",' in response

        response = self.app.get(url(controller='admin', action='init'),
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d'
                                        })
        print response
        assert '"status": true' in response

        self.createPolicy("getserial")
        response = self.app.get(url(controller='userservice', action='getSerialByOtp'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'type': 'hmac',
                                        'otp': '459812'})
        print response
        # The token is not found, as it is not in the realm of the user
        assert '"serial": ""' in response

        response = self.app.get(url(controller='admin', action='tokenrealm'),
                                params={'serial': 'token01',
                                        'realms': 'myDefRealm'})
        print response
        assert '"value": 1' in response

        # NOw the token is found
        response = self.app.get(url(controller='userservice', action='getSerialByOtp'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'type': 'hmac',
                                        'otp': '459812'})
        print response
        assert '"serial": "token01"' in response

    def test_assign(self):
        '''
        selfservice: testing assign token and unassign token
        '''
        self.deleteToken('token01')

        # init token
        response = self.app.get(url(controller='admin', action='init'),
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d'
                                        })
        print response
        assert '"status": true' in response

        # put into realm
        response = self.app.get(url(controller='admin', action='tokenrealm'),
                                params={'serial': 'token01',
                                        'realms': 'myDefRealm'})
        print response
        assert '"value": 1' in response

        # Now try to assign
        response = self.app.get(url(controller='userservice', action='assign'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'serial': 'token01'})
        print response
        assert '"message": "ERR410: ' in response

        self.createPolicy("assign")
        response = self.app.get(url(controller='userservice', action='assign'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'serial': 'token01'})
        print response
        assert '"assign token": true' in response

        # unassign
        response = self.app.get(url(controller='userservice', action='unassign'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'serial': 'token01'})
        print response
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!",' in response

        self.createPolicy("unassign")
        response = self.app.get(url(controller='userservice', action='unassign'),
                                params={'selftest_user': 'root@myDefRealm',
                                        'serial': 'token01'})
        print response
        assert '"unassign token": true' in response

        # UI
        response = self.app.get(url(controller='selfservice', action='assign'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert "<div id='assignform'>" in response

        response = self.app.get(url(controller='selfservice', action='unassign'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert "<div id='unassignform'>" in response


    def test_delete(self):
        '''
        selfservice: testing deleting token
        '''
        self.deleteToken('token01')

        response = self.app.get(url(controller='admin', action='init'),
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d',
                                        'user': 'root'
                                        })
        print response
        assert '"status": true' in response

        response = self.app.get(url(controller='userservice', action='delete'),
                                params={'serial': 'token01',
                                        'selftest_user': 'root@myDefRealm'})
        print response
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy("delete")
        response = self.app.get(url(controller='userservice', action='delete'),
                                params={'serial': 'token01',
                                        'selftest_user': 'root@myDefRealm'})
        print response
        assert '"delete token": 1' in response

        # UI
        response = self.app.get(url(controller='selfservice', action='delete'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert "<div id='deleteform'>" in response

    def test_disable(self):
        '''
        selfservice: testing disable and enable token
        '''
        self.deleteToken('token01')

        response = self.app.get(url(controller='admin', action='init'),
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d',
                                        'user': 'root'
                                        })
        print response
        assert '"status": true' in response

        # disable
        response = self.app.get(url(controller='userservice', action='disable'),
                                params={'serial': 'token01',
                                        'selftest_user': 'root@myDefRealm'})
        print response
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!",' in response

        self.createPolicy("disable")
        response = self.app.get(url(controller='userservice', action='disable'),
                                params={'serial': 'token01',
                                        'selftest_user': 'root@myDefRealm'})
        print response
        assert '"disable token": 1' in response

        response = self.app.get(url(controller='admin', action='show'),
                                params={'serial': 'token01'})
        print response
        assert '"LinOtp.TokenSerialnumber": "token01",' in response
        assert '"LinOtp.Isactive": false' in response

        # now enable again

        response = self.app.get(url(controller='userservice', action='enable'),
                                params={'serial': 'token01',
                                        'selftest_user': 'root@myDefRealm'})
        print response
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy("enable")
        response = self.app.get(url(controller='userservice', action='enable'),
                                params={'serial': 'token01',
                                        'selftest_user': 'root@myDefRealm'})
        print response
        assert '"enable token": 1' in response

        response = self.app.get(url(controller='admin', action='show'),
                                params={'serial': 'token01'})
        print response
        assert '"LinOtp.TokenSerialnumber": "token01",' in response
        assert '"LinOtp.Isactive": true' in response

        # UI
        response = self.app.get(url(controller='selfservice', action='disable'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert "<div id='disableform'>" in response

        response = self.app.get(url(controller='selfservice', action='enable'),
                                params={'selftest_user': 'root@myDefRealm'})
        print response
        assert "<div id='enableform'>" in response

    def test_init(self):
        '''
        selfservice: testing enrollment of token as normal user
        '''
        self.deleteToken('token01')

        response = self.app.get(url(controller='userservice', action='enroll'),
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d',
                                        'selftest_user': 'root@myDefRealm'
                                        })
        print response
        assert '"message": "ERR410: The policy settings do not allow you to issue this request!"' in response

        self.createPolicy('enrollHMAC')

        response = self.app.get(url(controller='userservice', action='enroll'),
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'otpkey': 'c4a3923c8d97e03af6a12fa40264c54b8429cf0d',
                                        'selftest_user': 'root@myDefRealm'
                                        })
        print response
        assert '"status": true' in response

        response = self.app.get(url(controller='admin', action='show'),
                                params={'serial': 'token01'})
        print response
        assert '"LinOtp.TokenSerialnumber": "token01",' in response
        assert '"LinOtp.Isactive": true' in response


    def test_webprovision(self):
        '''
        selfservice: testing user webprovision
        '''
        self.deleteToken('token01')
        response = self.app.get(url(controller='userservice', action='webprovision'),
                                params={'serial':'token01',
                                        'type': 'hmac',
                                        'selftest_user': 'root@myDefRealm'
                                        })
        self.assertTrue('"message": "valid types are \'oathtoken\' and \'googleauthenticator\' and \'googleauthenticator_time\'. You provided hmac",' in response,response)

        response = self.app.get(url(controller='userservice', action='webprovision'),
                                params={'serial':'token01',
                                        'type': 'googleauthenticator',
                                        'selftest_user': 'root@myDefRealm'
                                        })

        self.assertTrue('"message": "ERR410: The policy settings do not allow you to issue this request!"' in response,response)

        self.createPolicy('webprovisionGOOGLE')

        response = self.app.get(url(controller='userservice', action='webprovision'),
                                params={'prefix':'LSGO',
                                        'type': 'googleauthenticator',
                                        'selftest_user': 'root@myDefRealm'
                                        })
        self.assertTrue('"url": "otpauth://hotp/LSGO' in response, response)

        # test
        response = self.app.get(url(controller='admin', action='show'),
                                params={'user': 'root'})
        self.assertTrue('"LinOtp.TokenSerialnumber": "LSGO' in response,response)
        self.assertTrue('"LinOtp.Isactive": true' in response, response)

        # UI

        response = self.app.get(url(controller='selfservice', action='webprovisiongoogletoken'),
                                params={'selftest_user': 'root@myDefRealm'})
        self.assertTrue("googletokenform" in response.body, response)

        return


    def test_ocra(self):
        '''
        TODO selfservice: testing ocra
        '''
        pass


    def test_getmultiotp(self):
        '''
        TODO selfservice: testing getting multiple otps
        '''
        pass

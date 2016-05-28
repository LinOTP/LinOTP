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

import datetime
from simplejson import loads

from linotp.tests import TestController

import logging
log = logging.getLogger(__name__)


class TestGetOtpController(TestController):
    '''
    This test at the moment only tests the implementation
    for the Tagespasswort Token

        getotp
        get_multi_otp
    '''
    seed = "3132333435363738393031323334353637383930"
    seed32 = "3132333435363738393031323334353637383930313233343536373839303132"
    seed64 = ("31323334353637383930313233343536373839303132333435363738393031"
              "32333435363738393031323334353637383930313233343536373839303132"
              "3334")

    def setUp(self):
        '''
        This sets up all the resolvers and realms
        '''
        TestController.setUp(self)
        # for better reentrance and debuging make the cleanup upfront
        self.delete_all_policies()
        self.delete_all_realms()
        self.delete_all_resolvers()

        # create the test setup
        self.create_common_resolvers()
        self.create_common_realms()
        self.curTime = datetime.datetime(2012, 5, 16, 9, 0, 52, 227413)
        self.TOTPcurTime = datetime.datetime.fromtimestamp(1337292860.585256)
        self.initToken()

    def tearDown(self):
        TestController.tearDown(self)

    ###########################################################################

    def createDPWToken(self, serial, seed):
        '''
        creates the test tokens
        '''
        parameters = {"serial": serial,
                      "type": "DPW",
                      # 64 byte key
                      "otpkey": seed,
                      "otppin": "1234",
                      "pin": "pin",
                      "otplen": 6,
                      "description": "DPW testtoken",
                      }

        response = self.make_admin_request(action='init', params=parameters)
        self.assertTrue('"value": true' in response, response)

    def createHOTPToken(self, serial, seed):
        '''
        creates the test tokens
        '''
        parameters = {"serial": serial,
                      "type": "HMAC",
                      # 64 byte key
                      "otpkey": seed,
                      "otppin": "1234",
                      "pin": "pin",
                      "otplen": 6,
                      "description": "HOTP testtoken",
                      }

        response = self.make_admin_request(action='init', params=parameters)
        self.assertTrue('"value": true' in response, response)

    def createTOTPToken(self, serial, seed, timeStep=30):
        '''
        creates the test tokens
        '''
        parameters = {"serial": serial,
                      "type": "TOTP",
                      # 64 byte key
                      "otpkey": seed,
                      "otppin": "1234",
                      "pin": "pin",
                      "otplen": 8,
                      "description": "TOTP testtoken",
                      "timeStep": timeStep,
                      }

        response = self.make_admin_request(action='init', params=parameters)
        self.assertTrue('"value": true' in response, response)

    def setTokenRealm(self, serial, realms):
        parameters = {"serial": serial,
                      "realms": realms}

        response = self.make_admin_request(action="tokenrealm",
                                           params=parameters)
        return response

    def initToken(self):
        '''
        init one DPW token
        '''

        self.createDPWToken("dpw1", "12341234123412341234123412341234")
        '''
        curTime = datetime.datetime(2012, 5, 16, 9, 0, 52, 227413)
            "12-05-22": "202690",
            "12-05-23": "252315",
            "12-05-20": "6",
            "12-05-21": "325819",
            "12-05-24": "263973",
            "12-05-25": "321965",
            "12-05-17": "028193",
            "12-05-16": "427701",
            "12-05-19": "167074",
            "12-05-18": "857788"
        '''
        self.createHOTPToken("hotp1", "12341234123412341234123412341234")
        '''
            "0": "819132",
            "1": "301156",
            "2": "586172",
            "3": "720026",
            "4": "062511",
            "5": "598723",
            "6": "770725",
            "7": "596337",
            "8": "647211",
            "9": "294016",
            "10": "161051",
            "11": "886458"
        '''
        self.createTOTPToken("totp1", self.seed, timeStep=30)
        '''
        T0=44576428.686175205 (*30)
            "44576428": "33726427",
            "44576429": "84341529",
            "44576430": "35692495",
            "44576431": "70995873",
            "44576432": "12048114",
            "44576433": "06245460",
            "44576434": "10441015",
            "44576435": "50389782",
            "44576436": "78905052",
            "44576437": "52978758",
            "44576438": "90386435",
            "44576439": "76892112"

        '''

        response = self.setTokenRealm("dpw1", "mydefrealm")
        self.assertTrue('"status": true' in response, response)

        response = self.setTokenRealm("hotp1", "mydefrealm")
        self.assertTrue('"status": true' in response, response)

        response = self.setTokenRealm("totp1", "mydefrealm")
        self.assertTrue('"status": true' in response, response)

        params = {'user': 'passthru_user1',
                  'serial': 'totp1'}
        response = self.make_admin_request(action='assign', params=params)
        self.assertTrue('"status": true' in response, response)

        parameters = {}
        response = self.make_system_request(action='getRealms',
                                            params=parameters)

        self.assertTrue('"status": true' in response, response)

        parameters = {'name': 'getmultitoken',
                      'scope': 'gettoken',
                      'realm': 'mydefrealm',
                      'action': ('max_count_dpw=10, max_count_hotp=10, '
                                 'max_count_totp=10'),
                      'user': 'admin'
                      }
        response = self.make_system_request(action='setPolicy',
                                            params=parameters)
        self.assertTrue('"status": true' in response, response)

        response = self.make_system_request(action='getConfig', params={})
        self.assertTrue('"status": true' in response, response)

        return

    def test_01_getotp_dpw(self):
        '''
        test for the correct otp value of the DPW token
        '''
        parameters = {'serial': 'dpw1',
                      'curTime': self.curTime,
                      'selftest_admin': 'admin'}
        response = self.make_gettoken_request(action='getotp',
                                              params=parameters)

        self.assertTrue('"otpval": "427701"' in response,
                        "current time %s;%r" % (self.curTime, response))

        return

    def test_03_getmultiotp(self):
        '''
        test for the correct otp value of the DPW token
        '''
        parameters = {'serial': 'dpw1',
                      'curTime': self.curTime,
                      'count': "10",
                      'selftest_admin': 'admin'}
        response = self.make_gettoken_request(action='getmultiotp',
                                              params=parameters)

        self.assertTrue('"12-05-17": "028193"' in response, response)
        self.assertTrue('"12-05-18": "857788"' in response, response)

        return

    def test_05_getotp_hotp(self):
        '''
        test for the correct otp value of the HOTP token
        '''
        parameters = {'serial': 'hotp1'}
        response = self.make_gettoken_request(action='getotp',
                                              params=parameters)

        self.assertTrue('"otpval": "819132"' in response, response)

        return

    def test_06_getmultiotp(self):
        '''
        test for the correct otp value of the HOTP token
        '''
        parameters = {'serial': 'hotp1',
                      'curTime': self.curTime,
                      'count': "20",
                      'selftest_admin': 'admin'}
        response = self.make_gettoken_request(action='getmultiotp',
                                              params=parameters)

        self.assertTrue('"0": "819132"' in response, response)
        self.assertTrue('"1": "301156"' in response, response)

        return

    def test_07_getotp_totp(self):
        '''
        test for the correct otp value of the TOTP token


          +-------------+--------------+------------------+----------+--------+
          |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
          +-------------+--------------+------------------+----------+--------+
          |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
          |             |   00:00:59   |                  |          |        |
          |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
          |             |   01:58:29   |                  |          |        |
          |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
          |             |   01:58:31   |                  |          |        |
          |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
          |             |   23:31:30   |                  |          |        |
          |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
          |             |   03:33:20   |                  |          |        |
          | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
          |             |   11:33:20   |                  |          |        |

        '''
        cTimes = [('1970-01-01 00:00:59', '94287082'),
                  ('2005-03-18 01:58:29', '07081804'),
                  ('2005-03-18 01:58:31', '14050471'),
                  ('2009-02-13 23:31:30', '89005924'),
                  ('2033-05-18 03:33:20', '69279037'),
                  ]
        for cTime in cTimes:
            TOTPcurTime = cTime[0]
            otp = cTime[1]

            parameters = {'serial': 'totp1',
                          'curTime': TOTPcurTime}
            response = self.make_gettoken_request(action='getotp',
                                                  params=parameters)
            self.assertTrue(otp in response, response)

        return

    def test_08_getmultiotp(self):
        '''
        test for the correct otp value of the TOTP token
        '''
        parameters = {'serial': 'totp1',
                      'curTime': self.TOTPcurTime,
                      'count': "20",
                      'selftest_admin': 'admin'}
        response = self.make_gettoken_request(action='getmultiotp',
                                              params=parameters)

        resp = loads(response.body)
        otps = resp.get('result').get('value').get('otp')

        otp1 = otps.get('44576668')
        self.assertTrue(otp1.get('otpval') == '75301418', response)
        self.assertTrue(otp1.get('time') == "2012-05-18 02:14:00", response)

        otp2 = otps.get('44576669')
        self.assertTrue(otp2.get('otpval') == '28155992', response)
        self.assertTrue(otp2.get('time') == "2012-05-18 02:14:30", response)

        return

    def test_09_usergetmultiotp_no_policy(self):
        '''
        test for the correct OTP value for a users own token  with missing policy
        '''
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')
        parameters = {'serial': 'totp1',
                      'curTime': self.TOTPcurTime,
                      'count': "20"}
        response = self.make_userservice_request(action='getmultiotp',
                                                 params=parameters,
                                                 auth_user=auth_user)

        self.assertTrue('"message": "ERR410:' in response, response)
        return

    def test_10_usergetmultiotp(self):
        '''
        test for the correct OTP value for a users own token
        '''
        parameters = {'name': 'usertoken',
                      'scope': 'selfservice',
                      'realm': 'mydefrealm',
                      'action': ('max_count_dpw=10, max_count_hotp=10, '
                                 'max_count_totp=10')
                      }
        response = self.make_system_request(action='setPolicy',
                                            params=parameters)

        self.assertTrue('"status": true' in response, response)

        auth_user = ('passthru_user1@myDefRealm', 'geheim1')
        parameters = {'serial': 'totp1',
                      'curTime': self.TOTPcurTime,
                      'count': "20",
                      }
        response = self.make_userservice_request(action='getmultiotp',
                                                 params=parameters,
                                                 auth_user=auth_user)

        resp = loads(response.body)
        otps = resp.get('result').get('value').get('otp')

        otp1 = otps.get('44576668')
        self.assertTrue(otp1.get('otpval') == '75301418', response)
        self.assertTrue(otp1.get('time') == "2012-05-18 02:14:00", response)

        otp2 = otps.get('44576669')
        self.assertTrue(otp2.get('otpval') == '28155992', response)
        self.assertTrue(otp2.get('time') == "2012-05-18 02:14:30", response)

        return

    def test_11_usergetmultiotp_fail(self):
        '''
        test for the correct OTP value for a  token that does not belong to the user
        '''
        auth_user = ('passthru_user1@myDefRealm', 'geheim1')
        parameters = {'serial': 'hotp1',
                      'curTime': self.TOTPcurTime,
                      'count': "20",
                      }
        response = self.make_userservice_request(action='getmultiotp',
                                                 params=parameters,
                                                 auth_user=auth_user)
        print response
        self.assertTrue('"message": "The serial hotp1 does not belong'
                        ' to user passthru_user1@myDefRealm"' in response, response)

        return

# eof ########################################################################

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


""" """

import json
import time
import hmac
import logging
import binascii
import struct
import hashlib
import sys

(ma, mi, _, _, _,) = sys.version_info
pver = float(int(ma) + int(mi) * 0.1)

from linotp.tests import TestController, url

log = logging.getLogger(__name__)


class HmacOtp():
    def __init__(self, secret, counter=0, digits=6, hashfunc=hashlib.sha1):
        self.secret = secret
        self.counter = counter
        self.digits = digits

        # set up hashlib
        ty = type(hashfunc).__name__
        if  ty == 'str' or ty == 'unicode':
            self.hashfunc = self._getHashlib(hashfunc)
        else:
            self.hashfunc = hashfunc

    def _getHashlib(self, hLibStr):

        if hLibStr is None:
            return hashlib.sha1

        hashlibStr = hLibStr.lower()

        if hashlibStr == "md5":
            return hashlib.md5
        elif hashlibStr == "sha1":
            return hashlib.sha1
        elif hashlibStr == "sha224":
            return hashlib.sha224
        elif hashlibStr == "sha256":
            return hashlib.sha256
        elif hashlibStr == "sha384":
            return hashlib.sha384
        elif hashlibStr == "sha512":
            return hashlib.sha512
        else:
            return hashlib.sha1

    def calcHmac(self, counter=None):
        # log.error("hmacSecret()")
        counter = counter or self.counter

        # # retrieve the unicode key
        akey = self.secret

        # log.debug("[hmac] key: %s", akey)

        # # and convert it to binary    from linotp.lib.crypt import SecretObj
        key = binascii.unhexlify(akey)
        msg = struct.pack(">Q", counter)
        dige = hmac.new(key, msg, self.hashfunc)

        digStr = str(dige.digest())

        del akey
        del key
        del dige

        return digStr

    def truncate(self, digest):
        offset = ord(digest[-1:]) & 0x0f

        binary = (ord(digest[offset + 0]) & 0x7f) << 24
        binary |= (ord(digest[offset + 1]) & 0xff) << 16
        binary |= (ord(digest[offset + 2]) & 0xff) << 8
        binary |= (ord(digest[offset + 3]) & 0xff)

        return binary % (10 ** self.digits)

    def generate(self, counter=None):
        counter = counter or self.counter
        myHmac = self.calcHmac(counter)
        otp = unicode(self.truncate(myHmac))

        #  fill in the leading zeros
        sotp = (self.digits - len(otp)) * "0" + otp
        self.counter = counter + 1
        return sotp


class TestValidateController(TestController):
    """
    test the validate controller

    remark:
        validate test for the sms token test are in the
            test_sms2 and
            test_httpsms and
            test_challenge_response
    """

    def setUp(self):
        TestController.setUp(self)
        self.set_config_selftest()
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def createMOtpToken(self):
        parameters = {
                      "serial": "M722362",
                      "type": "motp",
                      "otpkey": "1234567890123456",
                      "otppin": "1234",
                      "user": "root",
                      "pin": "pin",
                      "description": "TestToken1",
                      }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

    def createTOtpToken(self, hashlib_def):
        '''
        // Seed for HMAC-SHA1 - 20 bytes
        String seed = "3132333435363738393031323334353637383930";
        // Seed for HMAC-SHA256 - 32 bytes
        String seed32 = "3132333435363738393031323334353637383930" +
        "313233343536373839303132";
        // Seed for HMAC-SHA512 - 64 bytes
        String seed64 = "3132333435363738393031323334353637383930" +
        "3132333435363738393031323334353637383930" +
        "3132333435363738393031323334353637383930" +
        "31323334";
        '''

        if hashlib_def == "SHA512":
            otpkey = (
            "313233343536373839303132333435363738393031323334353"
            "637383930313233343536373839303132333435363738393031323"
            "33435363738393031323334")
        elif hashlib_def == "SHA256":
            otpkey = (
            "3132333435363738393031323334353637383930313233343536373839303132"
            )
        else:
            otpkey = "3132333435363738393031323334353637383930"
        parameters = {
                          "serial": "TOTP",
                          "type": "totp",
                          # 64 byte key
                          "otpkey": otpkey,
                          "otppin": "1234",
                          "user": "root",
                          "pin": "pin",
                          "otplen": 8,
                          "description": "time based HMAC TestToken1",
                          "hashlib": hashlib_def,
                          }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        try:
            hmac_val = HmacOtp(otpkey, digits=8, hashfunc=hashlib_def)
        except Exception as e:
            raise e

        return hmac_val

    def createTOtpValue(self, hmac_func, T0=None, shift=0, timeStepping=30):
        ret = ""
        try:
            if T0 is None:
                T0 = time.time() - shift
            counter = int((T0 / timeStepping) + 0.5)
            ret = hmac_func.generate(counter)

        except Exception as e:
            raise e

        return ret

    def createToken1(self):
        """
            otp[0]: 870581 :
            otp[1]: 793334 :
            otp[2]: 088491 :
            otp[3]: 013126 :
            otp[4]: 818771 :
            otp[5]: 454594 :
            otp[6]: 217219 :
            otp[7]: 250710 :
            otp[8]: 478893 :
            otp[9]: 517407 :
        """
        parameters = {
                      "serial": "F722362",
                      "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
                      "user": "root",
                      "pin": "pin",
                      "description": "TestToken1",
                      }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

    def createRealmToken1(self, realm):
        """
            otp[0]: 870581 :
            otp[1]: 793334 :
            otp[2]: 088491 :
            otp[3]: 013126 :
            otp[4]: 818771 :
            otp[5]: 454594 :
            otp[6]: 217219 :
            otp[7]: 250710 :
            otp[8]: 478893 :
            otp[9]: 517407 :
        """
        parameters = {
                      "serial": "F722362",
                      "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
                      "user": "root",
                      "pin": "pin",
                      "description": "TestToken1",
                      }
        if realm is not None:
            parameters.update(realm)
        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

    def createToken(self):
        serials = set()
        parameters = {
                      "serial": "F722362",
                      "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
                      "user": "root",
                      "pin": "pin",
                      "description": "TestToken1",
                      }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        serials.add(parameters.get('serial'))

        parameters = {
                  "serial": "F722363",
                  "otpkey": "AD8EABE235FC57C815B26CEF3709075580B4473880B44738",
                  "user": "root",
                  "pin": "pin",
                  "description": "TestToken2",
                  }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        serials.add(parameters.get('serial'))

        # # test the update
        parameters = {
                      "serial": "F722364",
                      "otpkey": "AD8EABE235FC57C815B26CEF37090755",
                      "user": "root",
                      "pin": "Pin3",
                      "description": "TestToken3",
                      }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        serials.add(parameters.get('serial'))

        parameters = {
                      "serial": "F722364",
                      "otpkey": "AD8EABE235FC57C815B26CEF37090755",
                      "user": "root",
                      "pin": "pin",
                      "description": "TestToken3",
                      }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        serials.add(parameters.get('serial'))

        return serials

    def createToken2(self):
        parameters = {
                      "serial": "T2",
                      "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
                      "user": "root",
                      "pin": "T2PIN",
                      "description": "TestToken2",
                      }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

    def createToken3(self):
        parameters = {
                      "serial": "T3",
                      "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
                      "user": "root",
                      "pin": "T2PIN",
                      "description": "TestToken3",
                      }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

    def createTokenSMS(self):
        parameters = {
                      "serial": "SM1",
                      "user": "root",
                      "pin": "test",
                      "description": "TestSMS",
                      "type": "sms",
                      "phone": "007"
                      }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

    def createSpassToken(self, serial=None):
        if serial is None:
            serial = "TSpass"
        parameters = {
                      "serial": serial,
                      "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
                      "user": "root",
                      "pin": "pin",
                      "description": "TestToken1",
                      "type": "spass"
                      }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)
        return serial

    def test_cryptedPin(self):

        _realmsResp = self.app.get(url(controller='system',
                                      action='getDefaultRealm'), params=None)
        # og.debug(realmsResp)
        # assert '"value": true' in response

        parameters = {"realm": "mydef"}
        _defRealmsResp = self.app.get(url(controller='system',
                                         action='setDefaultRealm'),
                                     params=parameters)
        # log.debug(defRealmsResp)
        # assert '"value": true' in response

        serial = self.createSpassToken("mySpass")
        self.delete_token(serial)

    #
    #    Use case:
    #        user:                 w.Token / wo.Token / unknown
    #        PassOnUserNotFound:   true / False / 'unset'
    #        Realm:                _default_  / myDomain
    #

    def checkFalse(self, realm):

        parameters = {"user": "root", "pass": "pin870581"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "postgres", "pass": "pin"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": false' in response, response)

        parameters = {"user": "postgres"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": false' in response, response)

        parameters = {"user": "UnKnownUser"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": false' in response, response)

    def checkFalse2(self, realm):

        parameters = {"user": "postgres"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n", response)
        # Test response...
        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "postgres", "pass": "pin"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "UnKnownUser"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": false' in response, response)

        parameters = {"user": "root", "pass": "pin088491"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "root"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        return

    def checkFalse3(self, realm):

        parameters = {"user": "postgres"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": false' in response, response)

        parameters = {"user": "postgres", "pass": "pin"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": false' in response, response)

        parameters = {"user": "UnKnownUser"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "root", "pass": "pin818771"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "root"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

    def checkTrue(self, realm):

        parameters = {"user": "postgres", "pass": "pin"}
        parameters.update(realm)
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "postgres"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "UnKnownUser"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "root", "pass": "pin217219"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "root"}
        parameters.update(realm)

        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        #
        #    otp[0]: 870581 :
        #    otp[1]: 793334 :
        #    otp[2]: 088491 :
        #    otp[3]: 013126 :
        #    otp[4]: 818771 :
        #    otp[5]: 454594 :
        #    otp[6]: 217219 :
        #    otp[7]: 250710 :
        #    otp[8]: 478893 :
        #    otp[9]: 517407 :
        #

    def test_autousercheck(self):
        '''
        testing PassOnUserNoToken and UserNotFound.
        '''
        realm = {}

        self.createToken1()

        self.app.get(url(controller='system', action='getRealms'))
        parameters = {"username": "*"}
        self.app.get(url(controller='admin', action='userlist'),
                                params=parameters)
        self.checkFalse(realm)

        parameters = {"PassOnUserNoToken": "True"}
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)
        self.assertTrue('"setConfig PassOnUserNoToken:True": true' in response,
                        response)

        self.checkFalse2(realm)

        parameters = {"PassOnUserNoToken": "False"}
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)
        self.assertTrue('"setConfig PassOnUserNoToken:False": true' in
                        response, response)

        parameters = {"PassOnUserNotFound": "True"}
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)
        self.assertTrue('"setConfig PassOnUserNotFound:True": true' in
                        response, response)

        self.checkFalse3(realm)

        parameters = {"PassOnUserNoToken": "True"}
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)
        self.assertTrue('"setConfig PassOnUserNoToken:True": true' in response,
                        response)

        self.checkTrue(realm)

        parameters = {"key": "PassOnUserNotFound"}
        response = self.app.get(url(controller='system', action='delConfig'),
                                params=parameters)
        self.assertTrue('"delConfig PassOnUserNotFound": true' in response,
                        response)

        parameters = {"key": "PassOnUserNoToken"}
        response = self.app.get(url(controller='system', action='delConfig'),
                                params=parameters)
        self.assertTrue('"delConfig PassOnUserNoToken": true' in response,
                        response)

        self.delete_token("F722362")

    def test_check(self):
        '''
        checking several different tokens /validate/check
        '''
        self.createToken()

        parameters = {"user": "root", "pass": "pin123456"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        parameters = {"serial": "F722362"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.FailCount": 1' in response, response)
        self.assertTrue('"LinOtp.FailCount": 0' not in response, response)

        # check all 3 tokens - the last one is it
        parameters = {"user": "root", "pass": "pin280395"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": "F722364"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.Count": 1' in response, response)
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)

        parameters = {"serial": "F722362"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        # change with token counter fix:
        # if one token of a set of tokens is valid,
        # all others involved are resetted
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)

        # check all 3 tokens - the last one is it
        parameters = {"pin": "TPIN", "serial": "F722364"}
        response = self.app.get(url(controller='admin', action='set'),
                                params=parameters)
        self.assertTrue('"set pin": 1' in response, response)

        # check all 3 tokens - the last one is it
        parameters = {"user": "root", "pass": "TPIN552629"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": "F722364"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.Count": 4' in response, response)
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)

        # now increment the failcounter to 19
        for _i in range(1, 20):
            # check if otp could be reused
            parameters = {"user": "root", "pass": "TPIN552629"}
            response = self.app.get(url(controller='validate', action='check'),
                                    params=parameters)
            self.assertTrue('"value": false' in response, response)

        parameters = {"user": "root"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        jresp = json.loads(response.body)
        data = jresp.get('result', {}).get('value', {}).get('data', [])

        # assure that we have at least one data row found
        self.assertGreater(len(data), 0, response)

        # now check, if the FailCounter has incremented
        tokens = 0
        for token_entry in data:
            tokens += 1
            fail_count = token_entry.get('LinOtp.FailCount', 0)
            self.assertEqual(fail_count, 19, response)

        # check if we did see any token
        self.assertEqual(tokens, 3, response)

        self.delete_token("F722364")
        self.delete_token("F722363")
        self.delete_token("F722362")

    def test_resync(self):
        """
        test the admin resync: jump ahead in the sync window from 0 to 40
        """

        self.createToken2()

        parameters = {"serial": "T2", "otp1": "719818", "otp2": "204809"}
        response = self.app.get(url(controller='admin', action='resync'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": "T2"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.Count": 40' in response, response)

        parameters = {"user": "root", "pass": "T2PIN204809"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        # 957690
        parameters = {"user": "root", "pass": "T2PIN957690"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": "T2"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.Count": 41' in response, response)

        self.delete_token("T2")

    def test_resync2(self):
        '''
            test of resync with two similar tokens
        '''

        self.createToken2()
        self.createToken3()

        parameters = {"user": "root", "pass": "T2PIN204809"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        parameters = {"user": "root", "otp1": "719818", "otp2": "204809"}
        response = self.app.get(url(controller='admin', action='resync'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": "T2"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.Count": 40' in response, response)

        parameters = {"serial": "T3"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.Count": 40' in response, response)

        parameters = {"serial": "T3", "pin": "T3PIN"}
        response = self.app.get(url(controller='admin', action='set'),
                                params=parameters)
        self.assertTrue('"set pin": 1' in response, response)

        parameters = {"user": "root", "pass": "T2PIN204809"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        # 957690
        parameters = {"user": "root", "pass": "T2PIN957690"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": "T2"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.Count": 41' in response, response)

        self.delete_token("T2")
        self.delete_token("T3")

    def test_autoresync(self):
        '''
        auto resync:

        use case:
        - on the otp device the otp became out of sync as the user triggered
          the generation of otps to often. Now he will be able to automaticaly
          resync his token automatically by providing two consecutive otp's.

        test implementaion
        - switch the autosync: /system/set?autosync=true
        - do two consecutive otp validation requests

        no test:
        - disable autosync and same test should fail
        - test no consecutive otp's
        - test otp's out of sync window

        '''

        self.createToken2()

        # test resync of token 2
        parameters = {"AutoResync": "true"}
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)
        self.assertTrue('setConfig AutoResync:true": true' in response,
                        response)

        # 35
        parameters = {"user": "root", "pass": "T2PIN732866"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        # 36
        parameters = {"user": "root", "pass": "T2PIN920079"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "root", "pass": "T2PIN732866"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        parameters = {"user": "root", "pass": "T2PIN957690"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        self.delete_token("T2")

        ###############################################
        # no test

        # no consecutive otps
        self.createToken2()

        # test resync of token 2
        parameters = {"AutoResync": "true"}
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)
        self.assertTrue('setConfig AutoResync:true": true' in response,
                        response)

        # 35
        parameters = {"user": "root", "pass": "T2PIN732866"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        # 37
        parameters = {"user": "root", "pass": "T2PIN328973"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        self.delete_token("T2")

        ###############################################
        # no test

        # now unset the autosync
        self.createToken2()

        # test resync of token 2
        parameters = {"AutoResync": "false"}
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)
        self.assertTrue('setConfig AutoResync:false": true' in response,
                        response)

        # 35
        parameters = {"user": "root", "pass": "T2PIN732866"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        # 36
        parameters = {"user": "root", "pass": "T2PIN920079"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        self.delete_token("T2")

    def test_checkMOtp(self):

        self.createMOtpToken()

        parameters = {"serial": "M722362"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)

        parameters = {"user": "root", "pass": "pin7215e7"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        parameters = {"serial": "M722362"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.FailCount": 1' in response, response)

        #
        #    only in selfTest mode, it's allowed to set
        #    the start time for the mobile otp
        #

        parameters = {"user": "root", "pass": "pin7215e7", "init": "126753360"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)

        if self.isSelfTest == True:
            self.assertTrue('"value": true' in response, response)
        else:
            log.error("""-------------------------
motp not tested for correctness
please enable 'linotp.selfTest = True' in your *.ini
""")
            self.assertTrue('"value": false' in response, response)

        self.delete_token("M722362")

    def test_checkOTPAlgo(self):

        """
           The test token shared secret uses the ASCII string value
           "12345678901234567890".  With Time Step X = 30, and the Unix epoch
           as the initial value to count time steps, where T0 = 0, the TOTP
           algorithm will display the following values for specified modes and
           timestamps.

          +-------------+--------------+------------------+----------+--------+
          |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
          +-------------+--------------+------------------+----------+--------+
          |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
          |             |   00:00:59   |                  |          |        |
          |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
          |             |   00:00:59   |                  |          |        |
          |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
          |             |   01:58:31   |                  |          |        |
          |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
          |             |   23:31:30   |                  |          |        |
          |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
          |             |   03:33:20   |                  |          |        |
          | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
          |             |   11:33:20   |                  |          |        |


          |      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
          |             |   00:00:59   |                  |          |        |
          |  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
          |             |   01:58:29   |                  |          |        |
          |  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
          |             |   01:58:31   |                  |          |        |
          |  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
          |             |   23:31:30   |                  |          |        |
          |  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
          |             |   03:33:20   |                  |          |        |
          | 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
          |             |   11:33:20   |                  |          |        |


          |      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
          |             |   01:58:29   |                  |          |        |
          |  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
          |             |   01:58:29   |                  |          |        |
          |  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
          |             |   01:58:31   |                  |          |        |
          |  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
          |             |   23:31:30   |                  |          |        |
          |  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
          |             |   03:33:20   |                  |          |        |
          | 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |
          |             |   11:33:20   |                  |          |        |
          +-------------+--------------+------------------+----------+--------+
        """

        testVector = {
                     'SHA1': [(59, '94287082'),
                                 (1111111109, '07081804'),
                                 (1111111111, '14050471'),
                                 (1234567890, '89005924'),
                                 (2000000000, '69279037'),
                                 (20000000000, '65353130'),
                                 ],
                     'SHA256': [(59, '46119246'),
                                 (1111111109, '68084774'),
                                 (1111111111, '67062674'),
                                 (1234567890, '91819424'),
                                 (2000000000, '90698825'),
                                 (20000000000, '77737706'),
                                 ],
                     'SHA512': [(59, '90693936'),
                                 (1111111109, '25091201'),
                                 (1111111111, '99943326'),
                                 (1234567890, '93441116'),
                                 (2000000000, '38618901'),
                                 (20000000000, '47863826'),
                                 ],
                     }

        try:
            for hashAlgo in testVector.keys():
                totp = self.createTOtpToken(hashAlgo)
                arry = testVector.get(hashAlgo)
                for tupp in arry:
                    (T0, otp) = tupp
                    val = self.createTOtpValue(totp, T0)
                    assert otp == val
        except Exception as e:
            log.exception("Error in TOTP algorithm!!")
            raise Exception(e)
        return

    def test_checkTOtp(self):

        self.createTOtpToken("SHA1")

        parameters = {"serial": "TOTP"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)

        parameters = {"user": "root", "pass": "pin12345678"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        self.assertTrue('"value": false' in response, response)

        parameters = {"serial": "TOTP"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        log.info("1 response /admin/hhow %s\n" % response)
        self.assertTrue('"LinOtp.FailCount": 1' in response, response)

        #
        #    only in selfTest mode, it's allowed to set
        #    the start time for the mobile otp
        #    ..
        # |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
        #     ..
        #

        parameters = {"user": "root", "pass": "pin94287082", "init": "59"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)

        if self.isSelfTest == True:
            self.assertTrue('"value": true' in response, response)
        else:
            log.error("""
-------------------------
motp not tested for correctness
please enable 'linotp.selfTest = True' in your *.ini
""")
            self.assertTrue('"value": false' in response, response)

        # second test value
        # |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
        #

        parameters = {"user": "root", "pass": "pin07081804",
                      "init": "1111111109"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)

        if self.isSelfTest == True:
            self.assertTrue('"value": true' in response, response)
        else:
            log.error("""
-------------------------
totp not tested for correctness
please enable 'linotp.selfTest = True' in your *.ini
""")
            self.assertTrue('"value": false' in response, response)

        parameters = {"user": "root", "pass": "pin89005924",
                      "init": "1234567890"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)

        if self.isSelfTest == True:
            self.assertTrue('"value": true' in response, response)
        else:
            log.error("""
-------------------------
totp not tested for correctness
please enable 'linotp.selfTest = True' in your *.ini
""")
            self.assertTrue('"value": false' in response, response)

        self.delete_token("TOTP")

        #
        # |      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
        # |             |   00:00:59   |                  |          |        |
        # |      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
        #

        self.createTOtpToken("SHA256")

        parameters = {"user": "root", "pass": "pin46119246", "init": "59"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)

        if self.isSelfTest == True:
            self.assertTrue('"value": true' in response, response)
        else:
            log.error("""
-------------------------
totp not tested for correctness
please enable 'linotp.selfTest = True' in your *.ini
""")
            self.assertTrue('"value": false' in response, response)

        self.delete_token("TOTP")

        self.createTOtpToken("SHA512")

        parameters = {"user": "root", "pass": "pin90693936", "init": "59"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        log.error("response %s\n", response)

        if self.isSelfTest == True:
            self.assertTrue('"value": true' in response, response)
        else:
            log.error("""
-------------------------
totp not tested for correctness
please enable 'linotp.selfTest = True' in your *.ini
""")
            self.assertTrue('"value": false' in response, response)

        self.delete_token("TOTP")

    def test_totp_resync(self):

        try:
            self.delete_token("TOTP")
        except Exception as exx:
            log.debug("Token does not existed: %r" % exx)

        totp = self.createTOtpToken("SHA1")

        parameters = {"serial": "TOTP"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)

        parameters = {"DefaultSyncWindow": "200"}
        response = self.app.get(url(controller='system', action='setDefault'),
                                params=parameters)
        self.assertTrue('"set DefaultSyncWindow": true' in response, response)

        parameters = {"AutoResync": "true"}
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)
        self.assertTrue('setConfig AutoResync:true": true' in response,
                        response)

        parameters = {"user": "root", "pass": "pin12345678"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        parameters = {"serial": "TOTP"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        # log.error("response %s\n", response)
        self.assertTrue('"LinOtp.FailCount": 1' in response, response)

        #
        #    now test TOTP resync - backward lookup
        #    This test usese the verified HMAC algo
        #    for generating hmac keys
        #

        myTime = time.time()

        otp1 = self.createTOtpValue(totp, myTime - 100)
        otp2 = self.createTOtpValue(totp, myTime - 70)

        parameters = {"user": "root", "otp1": otp1, "otp2": otp2}
        response = self.app.get(url(controller='admin', action='resync'),
                                params=parameters)
        # self.assertTrue('"value": true' in response

        #
        #    now test TOTP resync - forward lookup
        #    This test usese the verified HMAC algo
        #    for generating hmac keys
        #

        myTime = time.time()

        otp1 = self.createTOtpValue(totp, myTime + 122)
        otp2 = self.createTOtpValue(totp, myTime + 152)

        parameters = {"user": "root", "otp1": otp1, "otp2": otp2}
        response = self.app.get(url(controller='admin', action='resync'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        self.delete_token("TOTP")

    def test_totp_autosync(self):
        '''
            now let's test the autosync !!!
        '''

        parameters = {"DefaultSyncWindow": "200"}
        response = self.app.get(url(controller='system', action='setDefault'),
                                params=parameters)
        self.assertTrue('"set DefaultSyncWindow": true' in response, response)

        parameters = {"AutoResync": "true"}
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)
        self.assertTrue('setConfig AutoResync:true": true' in response,
                        response)

        try:
            self.delete_token("TOTP")
        except Exception as exx:
            log.debug("Token does not existed: %r" % exx)

        totp = self.createTOtpToken("SHA512")

        myTime = time.time()

        otp1 = self.createTOtpValue(totp, myTime + 255)
        otp2 = self.createTOtpValue(totp, myTime + 286)

        parameters = {"user": "root", "pass": "pin" + otp1}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)

        parameters = {"user": "root", "pass": "pin" + otp2}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)

        self.delete_token("TOTP")

    def test_failCount(self):
        """
        Idea: test if MaxFailCount works and if Token could not be resetted in
              case of a valid OTP if MaxFailCount exceeded
        """

        self.createToken1()

        parameters = {"serial": "F722362", "MaxFailCount": "15"}
        response = self.app.get(url(controller='admin', action='set'),
                                params=parameters)
        self.assertTrue('"set MaxFailCount": 1' in response, response)

        parameters = {"user": "root", "pass": "pin870581"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": "F722362"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)

        # Test if FailCount increments and in case of a valid OTP is resetted

        for _i in range(0, 14):
            parameters = {"user": "root", "pass": "pin123456"}
            response = self.app.get(url(controller='validate', action='check'),
                                    params=parameters)
            self.assertTrue('"value": false' in response, response)

        parameters = {"serial": "F722362"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.FailCount": 14' in response, response)

        # check all 3 tokens - the last one is it
        parameters = {"user": "root", "pass": "pin818771"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)

        # Test response...
        self.assertTrue('"value": true' in response, response)

        parameters = {"serial": "F722362"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)

        # Test response...
        self.assertTrue('"LinOtp.Count": 5' in response, response)
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)

        # Test if FailCount increments and in case of a maxFailCount
        # could not be reseted by a valid OTP

        for _i in range(0, 15):
            parameters = {"user": "root", "pass": "pin123456"}
            response = self.app.get(url(controller='validate', action='check'),
                                    params=parameters)
            self.assertTrue('"value": false' in response, response)

        parameters = {"serial": "F722362"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.Count": 5' in response, response)
        self.assertTrue('"LinOtp.FailCount": 15' in response, response)

        # the reset by a valid OTP must fail and
        # the OTP Count must be incremented anyway

        parameters = {"user": "root", "pass": "pin250710"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)
        self.assertTrue('"value": false' in response, response)

        parameters = {"serial": "F722362"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)

        self.assertTrue('"LinOtp.Count": 5' in response, response)
        self.assertTrue('"LinOtp.FailCount": 16' in response, response)

        parameters = {"serial": "F722362"}
        response = self.app.get(url(controller='admin', action='reset'),
                                params=parameters)
        self.assertTrue('"value": 1' in response, response)

        parameters = {"serial": "F722362"}
        response = self.app.get(url(controller='admin', action='show'),
                                params=parameters)
        self.assertTrue('"LinOtp.Count": 5' in response, response)
        self.assertTrue('"LinOtp.FailCount": 0' in response, response)

        self.delete_token("F722362")

    def test_samlcheck(self):
        """
        Test the /validate/samlcheck
        """
        parameters = {
                      "serial": "saml0001",
                      "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
                      "user": "root",
                      "pin": "test",
                      "type": "spass"
                      }

        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)

        parameters = {"allowSamlAttributes": "True"}
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)

        parameters = {"user": "root", "pass": "test"}
        response = self.app.get(url(controller='validate', action='samlcheck'),
                                params=parameters)
        self.assertTrue('"auth": true' in response, response)
        self.assertTrue('"username": "root"' in response, response)

        self.delete_token("saml0001")

    def test_unicode(self):
        '''
        checking /validate/check with corrupted unicode
        '''
        serials = self.createToken()

        parameters = {"user": "root", "pass": "\xC0"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=parameters)

        self.assertTrue('"value": false' in response or
                        '"status": false' in response, response)

        for serial in serials:
            self.delete_token(serial)

        return

    def test_simple_check(self):
        '''
        Testing simplecheck
        '''
        response = self.app.get(url(controller='admin', action='init'),
                                    params={'type': 'spass',
                                            'user': 'root',
                                            'pin': 'topSecret',
                                            'serial': 'simple634'})
        self.assertTrue('"status": true' in response, response)

        response = self.app.get(url(controller='validate',
                                    action='simplecheck'),
                                params={'user': 'root',
                                        'pass': 'topSecret'})

        self.assertTrue(':-)' in response, response)

        response = self.app.get(url(controller='validate',
                                    action='simplecheck'),
                                params={'user': 'root',
                                        'pass': 'wrongPW'})
        self.assertTrue(':-(' in response, response)

        return

#eof###########################################################################

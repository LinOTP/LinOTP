# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
"""paralell test"""

import base64
import binascii
import json
import logging
import os
import random
import sys
import threading
import time
import unittest
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

from Cryptodome.Hash import HMAC
from Cryptodome.Hash import SHA as SHA1
from Cryptodome.Hash import SHA256 as SHA256

# FIXME:  from linotp.tokens.ocra import OcraSuite
from linotp.lib.crypto.utils import (
    check,
    createActivationCode,
    decrypt,
    encrypt,
    geturandom,
    kdf2,
)
from linotp.lib.ext.pbkdf2 import PBKDF2
from linotp.tests import *

log = logging.getLogger(__name__)


class OcraOtp(object):
    def __init__(self, ocrapin=None):
        self.ocra = None
        self.bkey = None
        self.ocrapin = ocrapin
        self.activationkey = None
        self.sharedsecret = None
        self.ocrasuite = None
        self.serial = None
        self.counter = 0

    def init_1(self, response):
        """take the response of the first init to setup the OcraOtp"""

        jresp = json.loads(response.body)
        app_import = str(jresp.get("detail").get("app_import"))
        self.sharedsecret = str(jresp.get("detail").get("sharedsecret"))
        self.serial = str(jresp.get("detail").get("serial"))

        """ now parse the appurl for the ocrasuite """
        uri = urlparse(app_import.replace("lseqr://", "http://"))
        qs = uri.query
        qdict = parse_qs(qs)

        ocrasuite = qdict.get("os", None)
        if ocrasuite is not None and len(ocrasuite) > 0:
            ocrasuite = ocrasuite[0]

        self.ocrasuite = ocrasuite

        return (self.ocrasuite, self.sharedsecret, self.serial)

    def init_2(self, response, activationKey):
        self.activationkey = activationKey

        jresp = json.loads(response.body)
        self.nonce = str(jresp.get("detail").get("nonce"))
        self.transid = str(jresp.get("detail").get("transactionid"))
        app_import = str(jresp.get("detail").get("app_import"))

        """ now parse the appurl for the ocrasuite """
        uri = urlparse(app_import.replace("lseqr://", "http://"))
        qs = uri.query
        qdict = parse_qs(qs)
        nonce = qdict.get("no", None)
        if nonce is not None and len(nonce) > 0:
            nonce = nonce[0]

        challenge = qdict.get("ch", None)
        if challenge is not None and len(challenge) > 0:
            challenge = challenge[0]

        self.challenge = challenge
        self.ocra = None
        self.bkey = None

        return (self.challenge, self.transid)

    def _setup_(self):
        if self.ocra is not None and self.bkey is not None:
            return

        key_len = 20
        if self.ocrasuite.find("-SHA256"):
            key_len = 32
        elif self.ocrasuite.find("-SHA512"):
            key_len = 64

        self.bkey = kdf2(self.sharedsecret, self.nonce, self.activationkey, len=key_len)
        self.ocra = OcraSuite(self.ocrasuite)

        self.counter = 0

        return

    def callcOtp(self, challenge=None, ocrapin=None, counter=-1):
        if self.ocra is None:
            self._setup_()

        if ocrapin is None:
            ocrapin = self.ocrapin

        if challenge is None:
            challenge = self.challenge
        if counter == -1:
            counter = self.counter

        param = {}
        param["C"] = counter
        param["Q"] = challenge
        param["P"] = ocrapin
        param["S"] = ""
        if self.ocra.T is not None:
            """Default value for G is 1M, i.e., time-step size is one minute and the
            T represents the number of minutes since epoch time [UT].
            """
            now = datetime.now()
            stime = now.strftime("%s")
            itime = int(stime)
            param["T"] = itime

        data = self.ocra.combineData(**param)
        otp = self.ocra.compute(data, self.bkey)

        if counter == -1:
            self.counter += 1

        return otp


class doRequest(threading.Thread):
    def __init__(self, utest, rid=1, test=None):
        threading.Thread.__init__(self)

        # unit test obj
        self.utest = utest
        self.test_name = test

        # the identificator
        self.rid = rid
        self.response = None

    def run(self):
        if hasattr(self.utest, self.test_name):
            self.response = getattr(self.utest, self.test_name)(self.rid)
        return

    def status(self):
        res = '"status": true,' in self.response
        return res

    def stat(self):
        return (self.rid, self.response)


def genUrl(controller="admin", action="init"):
    return "/%s/%s" % (controller, action)


class OcraTest(TestController):
    fkey = bytes.fromhex("a74f89f9251eda9a5d54a9955be4569f9720abe8")
    key20h = "3132333435363738393031323334353637383930"
    key20 = bytes.fromhex(key20h)

    key32h = "3132333435363738393031323334353637383930313233343536373839303132"
    key32 = bytes.fromhex(key32h)
    key64h = "31323334353637383930313233343536373839303132333435363738393031323\
334353637383930313233343536373839303132333435363738393031323334"
    key64 = bytes.fromhex(key64h)

    pin = "1234"
    pin_sha1 = bytes.fromhex("7110eda4d09e062aa5e4a390b0a572ac0d2c0220")

    testsnp = [
        {
            "ocrasuite": "OCRA-1:HOTP-SHA1-6:QN08",
            "key": key20,
            "keyh": key20h,
            "vectors": [
                {"params": {"Q": "00000000"}, "result": "237653"},
                {"params": {"Q": "11111111"}, "result": "243178"},
                {"params": {"Q": "22222222"}, "result": "653583"},
                {"params": {"Q": "33333333"}, "result": "740991"},
                {"params": {"Q": "44444444"}, "result": "608993"},
                {"params": {"Q": "55555555"}, "result": "388898"},
                {"params": {"Q": "66666666"}, "result": "816933"},
                {"params": {"Q": "77777777"}, "result": "224598"},
                {"params": {"Q": "88888888"}, "result": "750600"},
                {"params": {"Q": "99999999"}, "result": "294470"},
            ],
        },
        {
            "ocrasuite": "OCRA-1:HOTP-SHA512-8:C-QN08",
            "key": key64,
            "keyh": key64h,
            "vectors": [
                {
                    "params": {"C": "00000", "Q": "00000000"},
                    "result": "07016083",
                },
                {
                    "params": {"C": "00001", "Q": "11111111"},
                    "result": "63947962",
                },
                {
                    "params": {"C": "00002", "Q": "22222222"},
                    "result": "70123924",
                },
                {
                    "params": {"C": "00003", "Q": "33333333"},
                    "result": "25341727",
                },
                {
                    "params": {"C": "00004", "Q": "44444444"},
                    "result": "33203315",
                },
                {
                    "params": {"C": "00005", "Q": "55555555"},
                    "result": "34205738",
                },
                {
                    "params": {"C": "00006", "Q": "66666666"},
                    "result": "44343969",
                },
                {
                    "params": {"C": "00007", "Q": "77777777"},
                    "result": "51946085",
                },
                {
                    "params": {"C": "00008", "Q": "88888888"},
                    "result": "20403879",
                },
                {
                    "params": {"C": "00009", "Q": "99999999"},
                    "result": "31409299",
                },
            ],
        },
        {
            "ocrasuite": "OCRA-1:HOTP-SHA512-8:QN08-T1M",
            "key": key64,
            "keyh": key64h,
            "vectors": [
                {
                    "params": {
                        "Q": "00000000",
                        "T_precomputed": int("132d0b6", 16),
                    },
                    "result": "95209754",
                },
                {
                    "params": {
                        "Q": "11111111",
                        "T_precomputed": int("132d0b6", 16),
                    },
                    "result": "55907591",
                },
                {
                    "params": {
                        "Q": "22222222",
                        "T_precomputed": int("132d0b6", 16),
                    },
                    "result": "22048402",
                },
                {
                    "params": {
                        "Q": "33333333",
                        "T_precomputed": int("132d0b6", 16),
                    },
                    "result": "24218844",
                },
                {
                    "params": {
                        "Q": "44444444",
                        "T_precomputed": int("132d0b6", 16),
                    },
                    "result": "36209546",
                },
            ],
        },
    ]

    tests = [
        {
            "ocrasuite": "OCRA-1:HOTP-SHA1-6:QN08",
            "key": key20,
            "keyh": key20h,
            "vectors": [
                {"params": {"Q": "00000000"}, "result": "237653"},
                {"params": {"Q": "11111111"}, "result": "243178"},
                {"params": {"Q": "22222222"}, "result": "653583"},
                {"params": {"Q": "33333333"}, "result": "740991"},
                {"params": {"Q": "44444444"}, "result": "608993"},
                {"params": {"Q": "55555555"}, "result": "388898"},
                {"params": {"Q": "66666666"}, "result": "816933"},
                {"params": {"Q": "77777777"}, "result": "224598"},
                {"params": {"Q": "88888888"}, "result": "750600"},
                {"params": {"Q": "99999999"}, "result": "294470"},
            ],
        },
        {
            "ocrasuite": "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1",
            "key": key32,
            "keyh": key32h,
            "vectors": [
                {"params": {"C": 0, "Q": "12345678"}, "result": "65347737"},
                {"params": {"C": 1, "Q": "12345678"}, "result": "86775851"},
                {"params": {"C": 2, "Q": "12345678"}, "result": "78192410"},
                {"params": {"C": 3, "Q": "12345678"}, "result": "71565254"},
                {"params": {"C": 4, "Q": "12345678"}, "result": "10104329"},
                {"params": {"C": 5, "Q": "12345678"}, "result": "65983500"},
                {"params": {"C": 6, "Q": "12345678"}, "result": "70069104"},
                {"params": {"C": 7, "Q": "12345678"}, "result": "91771096"},
                {"params": {"C": 8, "Q": "12345678"}, "result": "75011558"},
                {"params": {"C": 9, "Q": "12345678"}, "result": "08522129"},
            ],
        },
        {
            "ocrasuite": "OCRA-1:HOTP-SHA256-8:QN08-PSHA1",
            "key": key32,
            "keyh": key32h,
            "vectors": [
                {"params": {"Q": "00000000"}, "result": "83238735"},
                {"params": {"Q": "11111111"}, "result": "01501458"},
                {"params": {"Q": "22222222"}, "result": "17957585"},
                {"params": {"Q": "33333333"}, "result": "86776967"},
                {"params": {"Q": "44444444"}, "result": "86807031"},
            ],
        },
        {
            "ocrasuite": "OCRA-1:HOTP-SHA512-8:C-QN08",
            "key": key64,
            "keyh": key64h,
            "vectors": [
                {
                    "params": {"C": "00000", "Q": "00000000"},
                    "result": "07016083",
                },
                {
                    "params": {"C": "00001", "Q": "11111111"},
                    "result": "63947962",
                },
                {
                    "params": {"C": "00002", "Q": "22222222"},
                    "result": "70123924",
                },
                {
                    "params": {"C": "00003", "Q": "33333333"},
                    "result": "25341727",
                },
                {
                    "params": {"C": "00004", "Q": "44444444"},
                    "result": "33203315",
                },
                {
                    "params": {"C": "00005", "Q": "55555555"},
                    "result": "34205738",
                },
                {
                    "params": {"C": "00006", "Q": "66666666"},
                    "result": "44343969",
                },
                {
                    "params": {"C": "00007", "Q": "77777777"},
                    "result": "51946085",
                },
                {
                    "params": {"C": "00008", "Q": "88888888"},
                    "result": "20403879",
                },
                {
                    "params": {"C": "00009", "Q": "99999999"},
                    "result": "31409299",
                },
            ],
        },
        {
            "ocrasuite": "OCRA-1:HOTP-SHA512-8:QN08-T1M",
            "key": key64,
            "keyh": key64h,
            "vectors": [
                {
                    "params": {
                        "Q": "00000000",
                        "T_precomputed": int("132d0b6", 16),
                    },
                    "result": "95209754",
                },
                {
                    "params": {
                        "Q": "11111111",
                        "T_precomputed": int("132d0b6", 16),
                    },
                    "result": "55907591",
                },
                {
                    "params": {
                        "Q": "22222222",
                        "T_precomputed": int("132d0b6", 16),
                    },
                    "result": "22048402",
                },
                {
                    "params": {
                        "Q": "33333333",
                        "T_precomputed": int("132d0b6", 16),
                    },
                    "result": "24218844",
                },
                {
                    "params": {
                        "Q": "44444444",
                        "T_precomputed": int("132d0b6", 16),
                    },
                    "result": "36209546",
                },
            ],
        },
    ]

    def setUp(self):
        TestController.setUp(self)
        self.removeTokens()
        self.setupPolicies()
        self.sqlconnect = self.appconf.get("sqlalchemy.url")
        # sys.argv[1] = 'arg'
        # del sys.argv[2] # remember that -s is in sys.argv[2], see below
        print(sys.argv)

        self.runs = 5
        self.threads = 6

        for arg in sys.argv:
            if arg.startswith("ptest"):
                k = arg.split("=")
                if k[0] == "ptest.threads":
                    self.threads = int(k[1])
                if k[0] == "ptest.runs":
                    self.runs = int(k[1])
        return

    def tearDown(self):
        return

    def setupPolicies(self, check_url="http://127.0.0.1/ocra/check_t"):
        params = {
            "name": "CheckURLPolicy",
            "scope": "authentication",
            "realm": "mydefrealm",
        }
        params["action"] = "qrtanurl=%s" % (str(check_url))
        response = self.app.get(
            genUrl(controller="system", action="setPolicy"), params=params
        )

        return response

    def check_otp(self, transid, otp, pin="pin"):
        """-3.a- verify the otp value to finish the rollout"""
        parameters = {"transactionid": transid, "pass": "" + pin + otp}
        response = self.app.get(
            genUrl(controller="ocra", action="check_t"), params=parameters
        )
        return response

    def gen_challenge_data(self):
        testchall = [
            {
                "ocrasuite": "OCRA-1:HOTP-SHA256-6:C-QA64",
                "key": "12345678901234567890",
                "app_import1": "lseqr://init?sh=12345678901234567890&os=OCRA-1%3AHOTP-SHA256-6%3AC-QA64&se=LSOC00000001",
                "app_import2": "lseqr://nonce?me=abcdefg+1234567+%2B-%2A%23+%C3%B6%C3%A4%C3%BC%C3%9F&ch=abcdefg12345670000Xch3tNAkIWpmj6du0PVBSvFOmJqWu0wq9AL9BKYxGjGkVg&no=492321549d56446d31682adabe64efc4bc6d7f0e31202ebdd75335b550a87690a1a3fcafc9e52a04e4dde40dea5634ad0c7becfe9d3961690b95d135844b866d&tr=954472011597&u=http%253A%252F%252F127.0.0.1%252Focra%252Fcheck_t&se=LSOC00000001&si=790eb52b398c5b37aaeba56b374947e0b3193ff98e2553c04ac15ae49440abb9",
                "vectors": [
                    {"param": {"data": "irgendwas"}, "otp": "12345"},
                    {"param": {"data": "DasisteinTest"}, "otp": "12345"},
                    {"param": {"data": "Irgendwas"}, "otp": "12345"},
                    {"param": {"data": "1234567890123"}, "otp": "12345"},
                    {"param": {"data": "Dasisteintest"}, "otp": "12345"},
                    {"param": {"data": "Dasisteintest"}, "otp": "12345"},
                    {"param": {"data": "Dasist"}, "otp": "12345"},
                    {"param": {"data": "EinTestdasist"}, "otp": "12345"},
                    {"param": {"data": "ss"}, "otp": "12345"},
                    {"param": {"data": "SS"}, "otp": "12345"},
                    {
                        "param": {"data": "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS"},
                        "otp": "12345",
                    },
                    {"param": {"data": "DasisteinTExt"}, "otp": "12345"},
                    {"param": {"data": "Das"}, "otp": "12345"},
                    {"param": {"data": "EinLeerzeichen"}, "otp": "12345"},
                    {"param": {"data": "Ein Leerzeichen"}, "otp": "12345"},
                    {"param": {"data": "Ein+Leerzeichen"}, "otp": "12345"},
                ],
            },
        ]

        self.setupPolicies(check_url="https://ebanking.1882.de")

        tt = []
        for test in testchall:
            testdata = {}

            ocra = OcraOtp()
            response1 = self.init_0_QR_Token(user="root", ocrasuite=test["ocrasuite"])
            ocra.init_1(response1)

            jresp = json.loads(response1.body)
            app_import_1 = str(jresp.get("detail").get("app_import"))

            message = "abc"
            (response2, activationkey) = self.init_1_QR_Token(
                user="root",
                message=message,
                activationkey="GEZDGNBVGY3TQOJQ01",
                ocrasuite=test["ocrasuite"],
            )
            (challenge, transid) = ocra.init_2(response2, activationkey)

            jresp = json.loads(response2.body)
            app_import_2 = str(jresp.get("detail").get("app_import"))

            testdata["ocrasuite"] = ocra.ocrasuite
            testdata["nonce"] = ocra.nonce
            testdata["activationcode"] = ocra.activationkey
            testdata["sharedsecret"] = ocra.sharedsecret
            testdata["app_import_1"] = app_import_1
            testdata["app_import_2"] = app_import_2

            counter = 0
            """ finish rollout """
            otp = ocra.callcOtp(challenge, counter=counter)

            bkey = ocra.bkey
            key = binascii.hexlify(bkey)
            testdata["key"] = key

            response = self.check_otp(transid, otp)
            assert '"result": true' in response

            testv = []

            """ initial challenge """
            test_set = {}
            test_set["message"] = message
            test_set["data"] = app_import_2
            test_set["challenge"] = challenge
            test_set["otp"] = otp
            testv.append(test_set)

            for v in test.get("vectors"):
                param = v.get("param")
                """ get next challenge"""
                (response, challenge, transid) = self.get_challenge(
                    ocra.serial, challenge_data=param.get("data")
                )
                jresp = json.loads(response.body)
                app_import = str(jresp.get("detail").get("data"))
                challenge = str(jresp.get("detail").get("challenge"))

                counter += 1
                otp = ocra.callcOtp(challenge, counter=counter)

                """ correct response """
                response = self.check_otp(transid, otp)
                assert '"result": true' in response

                """ push test data in our test set"""
                test_set = {}
                test_set["message"] = param.get("data")
                test_set["data"] = app_import
                test_set["challenge"] = challenge
                test_set["otp"] = otp
                testv.append(test_set)

            testdata["vectors"] = testv
            tt.append(testdata)

        self.removeTokens(serial=ocra.serial)

        f = open("/tmp/challengeTestSet", "w+")
        testStr = json.dumps(tt, indent=4)
        f.write(testStr)
        f.close()

        return

    def randOTP(self, otp):
        """randomly change the chars in an otp - to gen a wron otp"""
        rotp = otp
        lenotp = len(str(otp))
        if lenotp > 1:
            while rotp == otp:
                for i in range(0, 3):
                    idx1 = random.randint(0, lenotp - 1)
                    idx2 = random.randint(0, lenotp - 1)
                    if idx1 != idx2:
                        c1 = rotp[idx1]
                        c2 = rotp[idx2]
                        rotp = rotp[:idx1] + c2 + rotp[idx1 + 1 :]
                        rotp = rotp[:idx2] + c1 + rotp[idx2 + 1 :]
        return rotp

    def init_0_QR_Token(
        self,
        tokentype="ocra",
        ocrapin="",
        pin="pin",
        user="root",
        description="QRTestToken",
        serial="QR123",
        sharedsecret="1",
        genkey="1",
        otpkey=None,
        ocrasuite="OCRA-1:HOTP-SHA256-8:C-QA64",
    ):
        """-1- create an ocra token"""
        parameters = {}

        if tokentype is not None:
            parameters["type"] = tokentype

        if pin is not None:
            parameters["pin"] = pin

        if genkey is not None:
            parameters["genkey"] = genkey

        if otpkey is not None:
            parameters["otpkey"] = otpkey

        if sharedsecret is not None:
            parameters["sharedsecret"] = sharedsecret

        if ocrapin is not None:
            parameters["ocrapin"] = ocrapin

        if ocrasuite is not None:
            parameters["ocrasuite"] = ocrasuite

        if user is not None:
            parameters["user"] = user
        elif serial is not None:
            parameters["serial"] = serial

        response = self.app.get(
            genUrl(controller="admin", action="init"), params=parameters
        )
        return response

    def init_1_QR_Token(
        self,
        activationkey=None,
        tokentype="ocra",
        serial=None,
        user=None,
        pin="pin",
        message="Message",
        ocrapin="",
        genkey="1",
        ocrasuite="OCRA-1:HOTP-SHA256-8:C-QA64",
    ):
        """-2- acivate ocra token"""
        parameters = {}

        if tokentype is not None:
            parameters["type"] = tokentype

        if pin is not None:
            parameters["pin"] = pin

        if message is not None:
            parameters["message"] = message

        if genkey is not None:
            parameters["genkey"] = genkey

        if ocrapin is not None:
            parameters["ocrapin"] = ocrapin

        if user is not None:
            parameters["user"] = user
        elif serial is not None:
            parameters["serial"] = serial

        if activationkey is None:
            activationkey = createActivationCode("1234567890")
        parameters["activationcode"] = activationkey

        if ocrasuite is not None:
            parameters["ocrasuite"] = ocrasuite

        response = self.app.get(
            genUrl(controller="admin", action="init"), params=parameters
        )
        return (response, activationkey)

    def removeTokens(self, user=None, serial=None):
        serials = []

        if user is not None:
            p = {"user": user}
            response = self.app.get(
                genUrl(controller="admin", action="remove"), params=p
            )
            log.info("response %s\n", response)
            assert '"value": 1' in response

        if serial is not None:
            p = {"serial": serial}
            response = self.app.get(
                genUrl(controller="admin", action="remove"), params=p
            )
            log.info("response %s\n", response)
            assert '"value": 1' in response

        if serial is None and user is None:
            parameters = {}
            response = self.app.get(
                genUrl(controller="admin", action="show"), params=parameters
            )
            log.info("response %s\n", response)
            assert '"status": true' in response

            jresp = json.loads(response.body)

            d_root = jresp.get("result").get("value").get("data")
            for tok in d_root:
                serial = tok.get("LinOtp.TokenSerialnumber")
                serials.append(serial)

            for serial in serials:
                p = {"serial": serial}
                response = self.app.get(
                    genUrl(controller="admin", action="remove"), params=p
                )
                log.info("response %s\n", response)
                assert '"value": 1' in response

    def _getChallenge(
        self,
        ocrasuite,
        bkey,
        serial,
        ocrapin="",
        data=None,
        count=0,
        ttime=None,
    ):
        otp1 = None

        p = {
            "serial": serial,
            "data": "0105037311 Konto 50150850 BLZ 1752,03 Eur",
        }
        if data is not None:
            p[data] = data

        response = self.app.get(genUrl(controller="ocra", action="request"), params=p)
        log.info("response %s\n", response)
        assert '"value": true' in response

        """ -2b- from the response get the challenge """
        jresp = json.loads(response.body)
        challenge1 = str(jresp.get("detail").get("challenge"))
        transid1 = str(jresp.get("detail").get("transactionid"))

        now = datetime.now()
        if ttime is not None:
            now = ttime
        stime = now.strftime("%s")
        itime = int(stime)

        param = {}
        param["C"] = count
        param["Q"] = challenge1
        param["P"] = ocrapin
        param["S"] = ""
        param["T"] = itime

        ocra = OcraSuite(ocrasuite)
        data = ocra.combineData(**param)
        otp1 = ocra.compute(data, bkey)

        return (otp1, transid1)

    def get_challenge(self, serial, user=None, challenge_data=None):
        p = {
            "data": challenge_data,
        }
        if user is None:
            p["serial"] = serial
        else:
            p["user"] = user

        response = self.app.get(genUrl(controller="ocra", action="request"), params=p)
        try:
            jresp = json.loads(response.body)
            challenge = str(jresp.get("detail").get("challenge"))
            transid = str(jresp.get("detail").get("transactionid"))
        except Exception as e:
            challenge = None
            transid = None

        return (response, challenge, transid)

    def createSpassToken(self, serial=None, user="root", pin="spass"):
        if serial is None:
            serial = "TSpass"
        parameters = {
            "serial": serial,
            "user": user,
            "pin": pin,
            "description": "SpassToken",
            "type": "spass",
        }

        response = self.app.get(
            genUrl(controller="admin", action="init"), params=parameters
        )
        assert '"value": true' in response
        return serial

    def test_ocra_paralell(self):
        if "sqlite" in self.sqlconnect:
            error = "This test will fail for sqlite db, as it does not support enough concurrency"
            assert "sqlite" not in self.sqlconnect, error

        self.createPolicy_Super()

        if self.runs == -1:
            i = 0
            while 1 == 1:
                i = i + 1
                self._prun_(i, self.threads)
        else:
            for i in range(0, self.runs):
                self._prun_(i, self.threads)

        return

    def _prun_(self, run_num, numthreads):
        """
        worker method
        """
        p_tests = []

        for _i in range(0, numthreads):
            p_test = doRequest(self, rid=_i, test="ptest_OCRA_token_failcounterInc")
            p_tests.append(p_test)
            if "paste.registry" in environ:
                environ["paste.registry"].register(myglobal, p_test)

            # prevent that all threads start at same time:
            # this will cause an p_thread error within the odbc layer
            sleep = random.uniform(0.1, 0.3)
            time.sleep(sleep)

            p_test.start()

        """ wait till all threads are completed """
        for p_test in p_tests:
            p_test.join()

        log.debug(" %d Threads finished", numthreads)

    # as there are asserts in the test, the thread will stop
    # if something is wrong. So we don't care for the results

    def createPolicy_Super(self):
        """
        Policy 01: create a policy for the superadmin
        """
        parameters = {
            "name": "ManageAll",
            "scope": "admin",
            "realm": "*",
            "action": "*",
            "user": "superadmin, Administrator",
        }
        response = self.app.get(
            url(controller="system", action="setPolicy"), params=parameters
        )
        log.error(response)
        assert '"status": true' in response

    ##########################################################################
    # paralell test starts here
    ##########################################################################

    def ptest_OCRA_token_failcounterInc(self, tid=1):
        """
        test_OCRA_token_failcounterInc: failcounter increment

        description:
            for all ocrasuites:
               create and enroll token
               verify the first otp
               get some challenges
               4 times:
                  verify a wrong otp
                  verify a wrong transaction
                  check status and if fail counter has incremented
        """
        tcount = 0
        for test in self.tests:
            ocrasuite = test["ocrasuite"]
            key = test["keyh"]
            bkey = test["key"]
            ocrapin = "myocrapin"
            tid = tid
            serial = "QR_One_%r_%r_%r_%r" % (
                tid,
                tcount,
                int(time.time()),
                random.randint(0, 100),
            )
            log.info("## serial: %r", serial)
            count = 0
            tcount = tcount + 1

            ocra = OcraSuite(ocrasuite)
            pinlen = ocra.truncation
            """ -1- create an ocra token """
            parameters = {
                "serial": serial,
                "user": "root",
                "pin": "pin",
                "description": "first QRToken",
                "type": "ocra",
                "ocrapin": ocrapin,
                "otpkey": key,
                "ocrasuite": ocrasuite,
            }

            response = self.app.get(
                genUrl(controller="admin", action="init"), params=parameters
            )
            assert '"value": true' in response

            # verify that the token is usable
            """ -2- fetch the challenge """
            p = {
                "serial": serial,
                "data": "0105037311 Konto 50150850 BLZ 1752,03 Eur",
            }
            response = self.app.get(
                genUrl(controller="ocra", action="request"), params=p
            )
            log.info("response %s\n", response)
            if '"value": true' not in response:
                assert '"value": true' in response

            """ -3.a- from the response get the challenge """
            jresp = json.loads(response.body)
            challenge = str(jresp.get("detail").get("challenge"))
            transid = str(jresp.get("detail").get("transactionid"))

            param = {}
            param["C"] = count
            param["Q"] = challenge
            param["P"] = ocrapin
            param["S"] = ""
            if ocra.T is not None:
                """Default value for G is 1M, i.e., time-step size is one minute and the
                T represents the number of minutes since epoch time [UT].
                """
                now = datetime.now()
                stime = now.strftime("%s")
                itime = int(stime)
                param["T"] = itime

            ocra = OcraSuite(ocrasuite)
            data = ocra.combineData(**param)
            otp = ocra.compute(data, bkey)

            ppin = "pin" + otp

            """ -3.b- verify the correct otp value """
            parameters = {
                "transactionid": transid,
                "pass": ppin,
            }
            response = self.app.get(
                genUrl(controller="ocra", action="check_t"), params=parameters
            )
            log.info("response %s\n", response)
            if '"result": true' not in response:
                assert '"result": true' in response

            # verify that the failcounter increments (max is 10)
            fcount = 0
            for count in range(1, 3):
                # create more than one challenge
                chals = random.randint(2, 5)
                for cc in range(1, chals):
                    """-2- fetch the challenge"""
                    p = {
                        "serial": serial,
                        "data": "0105037311 Konto 50150850 BLZ 1752,03 Eur",
                    }
                    response = self.app.get(
                        genUrl(controller="ocra", action="request"), params=p
                    )
                    log.info("response %s\n", response)
                    if '"value": true' not in response:
                        assert '"value": true' in response

                """ -3.a- from the response get the challenge """
                jresp = json.loads(response.body)
                challenge = str(jresp.get("detail").get("challenge"))
                transid = str(jresp.get("detail").get("transactionid"))

                ppin = "pin" + "a" * pinlen

                """ -4- verify the wrong otp value """
                parameters = {
                    "transactionid": transid,
                    "pass": ppin,
                }
                response = self.app.get(
                    genUrl(controller="ocra", action="check_t"),
                    params=parameters,
                )
                log.info("response %s\n", response)
                if '"result": false' not in response:
                    assert '"result": false' in response
                fcount += 1

                ppin = "pin" + "4" * pinlen

                """ -5- verify the wrong otp value """
                parameters = {
                    "transactionid": transid,
                    "pass": ppin,
                }
                response = self.app.get(
                    genUrl(controller="ocra", action="check_t"),
                    params=parameters,
                )
                log.info("response %s\n", response)
                if '"result": false' not in response:
                    assert '"result": false' in response
                fcount += 1

                """ -6- check if the failcounter has incremented  """
                parameters = {
                    "transactionid": transid,
                }
                response = self.app.get(
                    genUrl(controller="ocra", action="checkstatus"),
                    params=parameters,
                )
                log.info("response %s\n", response)
                assert '"status": true' in response
                assstring = '"failcount": %d,' % (fcount)
                log.info("assert %s\n", assstring)
                if assstring not in response:
                    log.error(response)
                    assert assstring in response

                sleep = random.uniform(0.0, 0.3)
                time.sleep(sleep)

            """ -remove the ocra token """
            parameters = {
                "serial": serial,
            }
            response = self.app.get(
                genUrl(controller="admin", action="remove"), params=parameters
            )
            log.info("response %s\n", response)
            assert '"value": 1' in response

            for _iii in range(0, 3):
                parameters = {
                    "serial": serial,
                }
                response = self.app.get(
                    genUrl(controller="admin", action="remove"),
                    params=parameters,
                )

        return response

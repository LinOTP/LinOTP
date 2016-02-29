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
Test challenge response functionality for the remote token
"""


import binascii
from mock import patch
import smtplib
import httplib2
import re
import time
import json
import logging
import urlparse

from linotp.tests import url

from linotp.lib.HMAC import HmacOtp
import smsprovider.HttpSMSProvider

from . import TestChallengeResponseController
from . import calcOTP

log = logging.getLogger(__name__)

# mocking hook is startting here
HTTP_RESPONSE_FUNC = None
HTTP_RESPONSE = None

def mocked_http_request(HttpObject, *argparams, **kwparams):

    resp = 200

    content = {
        "version": "LinOTP MOCK",
        "jsonrpc": "2.0",
        "result": {
            "status": True,
            "value": True
        },
        "id": 0
    }

    global HTTP_RESPONSE
    if HTTP_RESPONSE:
        status, response = HTTP_RESPONSE
        if response:
            content = response
            resp = status
        HTTP_RESPONSE = None

    global HTTP_RESPONSE_FUNC
    if HTTP_RESPONSE_FUNC:
        test_func = HTTP_RESPONSE_FUNC
        body = kwparams.get('body')
        params = dict(urlparse.parse_qsl(body))
        resp, content = test_func(params)
        HTTP_RESPONSE_FUNC = None

    return resp, json.dumps(content)



class TestRemotetokenChallengeController(TestChallengeResponseController):

    def setUp(self):
        '''
        This sets up all the resolvers and realms
        '''
        TestChallengeResponseController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

        if hasattr(self, "policies") is False:
            setattr(self, "policies", [])

        if hasattr(self, "serials") is False:
            setattr(self, "serials", [])

        self.patch_smtp = None
        self.patch_sms = None

        self.delete_all_token()
        self.delete_all_policies()

        self.remote_url = "http://127.0.0.1:%s" % self.paster_port
        return

    def tearDown(self):

        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestChallengeResponseController.tearDown(self)


    def setup_remote_token(self,
                           typ="pw",
                           otpkey="123456",
                           remoteurl=None):
        if remoteurl is None:
            remoteurl = self.remote_url
        # local token
        serials = []
        params_list = [
                  # the token set with remote pin checking
                  {
                        "serial": "LSRE001",
                        "type": "remote",
                        "otpkey": otpkey,
                        "otppin": "",
                        "user": "remoteuser",
                        "pin": "lpin",
                        "description": "RemoteToken1",
                        'remote.server': remoteurl,
                        'remote.local_checkpin': 0,
                        'remote.serial': 'LSPW1',
                        'session': self.session,
                      },
                  # target is accessed via serial, so no user is required
                  {
                        "serial": "LSPW1",
                        "type": typ,
                        "otpkey": otpkey,
                        "otppin": "",
                        "user": "",
                        "pin": "rpin",
                        'session': self.session,
                  },
                  # the token set with local pin checking
                  {
                        "serial": "LSRE002",
                        "type": "remote",
                        "otpkey": otpkey,
                        "user": "localuser",
                        "pin": "lpin",
                        "description": "RemoteToken2",
                        'remote.server': remoteurl,
                        'remote.local_checkpin': 1,
                        'remote.serial': 'LSPW2',
                        'session': self.session,
                        },
                  # the target is accessed via serial, so no user is required
                  {
                        "serial": "LSPW2",
                        "type": typ,
                        "otpkey": otpkey,
                        "otppin": "",
                        "user": "",
                        "pin": "",
                        'session': self.session,
                         },
                  ]
        for params in params_list:
            serials.append(params.get('serial'))
            response = self.make_admin_request(action='init', params=params)
            self.assertTrue('"value": true' in response, response)

        # enforce the awareness of policy changes
        params = {
            'enableReplication': 'true',
            'session': self.session,
            }
        resp = self.make_system_request(action='setConfig', params=params)
        assert('"setConfig enableReplication:true": true' in resp)

        return serials

    @patch.object(httplib2.Http, 'request', mocked_http_request)
    def test_remotetoken_regression(self):
        '''
        Challenge Response Test: regression remoteToken can splits passw localy or remote
        '''
        global HTTP_RESPONSE_FUNC
        serials = self.setup_remote_token()

        def check_func1(params):
            resp = 200
            value = params.get('pass') == 'rpin123456'
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }
            return resp, content

        HTTP_RESPONSE_FUNC = check_func1

        params = {"user": "remoteuser", "pass": "rpin123456"}
        response = self.make_validate_request('check', params=params)

        self.assertTrue('"value": true' in response, response)

        def check_func2(params):
            resp = 200
            value = params.get('pass') == '123456'
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }

            return resp, content

        HTTP_RESPONSE_FUNC = check_func2

        params = {"user": "localuser", "pass": "lpin123456"}
        response = self.make_validate_request('check', params=params)

        self.assertTrue('"value": true' in response, response)

        for serial in serials:
            self.delete_token(serial)

        return

    @patch.object(httplib2.Http, 'request', mocked_http_request)
    def test_remote_challenge(self):
        '''
        Challenge Response Test: remoteToken with with remote pin check
        '''
        global HTTP_RESPONSE_FUNC

        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"
        user = "remoteuser"
        remoteurl = self.remote_url

        # setup the remote token pairs
        serials = self.setup_remote_token(typ="hmac", otpkey=otpkey,
                                          remoteurl=remoteurl)

        # now switch policy on for challenge_response for hmac token
        response = self.setPinPolicy(name="ch_resp", realm='*',
                                action='challenge_response=hmac remote')
        self.assertTrue('"status": true,' in response, response)

        response = self.setPinPolicy(name="ch_resp", realm='*',
                                action='challenge_response=hmac remote',
                                remoteurl=remoteurl)
        self.assertTrue('"status": true,' in response, response)

        # 1. part - pin belongs to remote token
        # check is simple auth works
        otp = calcOTP(key=otpkey, counter=counter, typ="hmac")

        # define validation function
        def check_func1(params):
            resp = 200
            value = params.get('pass') == 'rpin' + otp
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }

            return resp, content

        # establish this in the global context as validation hook
        HTTP_RESPONSE_FUNC = check_func1

        params = {"user": user, "pass": "rpin" + otp}
        response = self.make_validate_request('check', params=params)

        self.assertTrue('"value": true' in response, response)

        # 1.1 now trigger a challenge
        otp = calcOTP(key=otpkey, counter=counter + 1, typ="hmac")

        # define validation function
        def check_func2(params):
            resp = 200
            value = params.get('pass') == 'rpin'
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": not value
                },
                "detail" : {'message': "text",
                            'transactionid':'012345678901'},
                "id": 0
            }

            return resp, content

        # establish this in the global context as validation hook
        HTTP_RESPONSE_FUNC = check_func2

        params = {"user": user, "pass": "rpin"}
        response = self.make_validate_request('check', params=params)

        self.assertTrue('"value": false' in response, response)

        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', '')
        self.assertTrue(state != '', response)

        # 1.2 check the challenge
        otp = calcOTP(key=otpkey, counter=counter + 1, typ="hmac")

        # define validation function
        def check_func3(params):
            resp = 200
            value = False

            # now check if we are part of the triggered
            # remote transaction forwarding
            if (params.get('pass') == otp and
                params.get('state') == '012345678901'):
                value = True

            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }

            return resp, content

        # establish this in the global context as validation hook
        HTTP_RESPONSE_FUNC = check_func3

        params = {"user": user, "pass": otp, "state": state}
        response = self.make_validate_request('check', params=params)

        # hey, if this ok, we are done for the remote pin check
        self.assertTrue('"value": true' in response, response)

        for serial in serials:
            self.delete_token(serial)

        self.delete_policy(name="ch_resp")

        return

    @patch.object(httplib2.Http, 'request', mocked_http_request)
    def test_local_challenge(self):
        '''
        Challenge Response Test: remoteToken with with local pin check
        '''
        global HTTP_RESPONSE_FUNC

        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"
        user = "localuser"
        remoteurl = self.remote_url

        # setup the remote token pairs
        serials = self.setup_remote_token(typ="hmac",
                                          otpkey=otpkey,
                                          remoteurl=remoteurl)

        # now switch policy on for challenge_response for hmac token
        response = self.setPinPolicy(name="ch_resp",
                                     realm='*',
                                     action='challenge_response=hmac remote')
        self.assertTrue('"status": true,' in response, response)

        response = self.setPinPolicy(name="ch_resp",
                                     realm='*',
                                     action='challenge_response=hmac remote',
                                     remoteurl=remoteurl)

        # now we have to test the local pin
        # when using the local pin, we will keep the challenge in the
        # src token

        # 1. part - pin belongs to local token - remote has no pin
        # check is simple auth works
        otp = calcOTP(key=otpkey, counter=counter, typ="hmac")

        # define validation function
        def check_func1(params):
            resp = 200
            value = params.get('pass') == otp
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }

            return resp, content

        # establish this in the global context as validation hook
        HTTP_RESPONSE_FUNC = check_func1

        params = {"user": user, "pass": "lpin" + otp}
        response = self.make_validate_request('check', params=params)

        self.assertTrue('"value": true' in response, response)

        # 2.1 now trigger a challenge
        counter = counter + 1
        otp = calcOTP(key=otpkey, counter=counter, typ="hmac")

        # define validation function
        def check_func2(params):
            resp = 200
            value = params.get('pass') == otp
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }

            return resp, content

        # establish this in the global context as validation hook
        HTTP_RESPONSE_FUNC = check_func2

        params = {"user": user, "pass": "lpin"}
        response = self.make_validate_request('check', params=params)

        self.assertTrue('"value": false' in response, response)

        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', '')
        self.assertTrue(state != '', response)

        # 2.2 check the challenge
        counter = counter + 1
        otp = calcOTP(key=otpkey, counter=counter, typ="hmac")

        # define validation function
        def check_func3(params):
            resp = 200
            value = params.get('pass') == otp
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }

            return resp, content

        # establish this in the global context as validation hook
        HTTP_RESPONSE_FUNC = check_func3

        params = {"user": user, "pass": otp, "state" : state}
        response = self.make_validate_request('check', params=params)

        # hey, if this ok, we are done for the remote pin check
        self.assertTrue('"value": true' in response, response)

        for serial in serials:
            self.delete_token(serial)

        self.delete_policy(name="ch_resp")

        return

##eof##########################################################################

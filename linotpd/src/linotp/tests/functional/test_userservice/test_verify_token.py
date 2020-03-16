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


import math
import binascii
from datetime import datetime
from hashlib import sha1
from mock import patch

import linotp.provider.smsprovider.FileSMSProvider

from linotp.tests import TestController
from linotp.lib.HMAC import HmacOtp


# mocking hook is starting here
SMS_MESSAGE_OTP = ('', '')
SMS_MESSAGE_CONFIG = {}


def mocked_submitMessage(FileSMS_Object, *argparams, **kwparams):

    # this hook is defined to grep the otp and make it globaly available
    global SMS_MESSAGE_OTP
    SMS_MESSAGE_OTP = argparams

    # we call here the original sms submitter - as we are a functional test
    global SMS_MESSAGE_CONFIG
    SMS_MESSAGE_CONFIG = FileSMS_Object.config

    return True


unix_start_time = datetime(year=1970, month=1, day=1)


def time2counter(t_time, t_step=60):
    t_delta = (t_time - unix_start_time).total_seconds()
    counts = t_delta / t_step

    return math.floor(counts)


def get_otp(key, counter=None, digits=8):

    hmac = HmacOtp(digits=digits, hashfunc=sha1)
    return hmac.generate(counter=counter, key=binascii.unhexlify(key))


class TestUserserviceTokenTest(TestController):
    '''
    support userservice api endpoint to allow to verify an enrolled token
    '''

    def setUp(self):
        response = self.make_system_request(
            'setConfig', params={'splitAtSign': 'true'})
        assert 'false' not in response.body

        TestController.setUp(self)
        # clean setup
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        # create the common resolvers and realm
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        TestController.tearDown(self)

    def define_provider(self, provider_params=None):
        """
        define the new provider via setProvider
        """
        params = {'name': 'newone',
                  'config': '{"file":"/tmp/newone"}',
                  'timeout': '301',
                  'type': 'sms',
                  'class': 'smsprovider.FileSMSProvider.FileSMSProvider'
                  }

        if provider_params:
            params.update(provider_params)

        response = self.make_system_request('setProvider', params=params)

        return response

    def test_verify_hmac_token(self):

        policy = {
            'name': 'T1',
            'action': 'enrollHMAC, delete, history, verify,',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response, response

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        serial = 'hmac123'

        params = {'type': 'hmac', 'genkey': '1', 'serial': serial}
        response = self.make_userselfservice_request(
            'enroll', params=params, auth_user=auth_user, new_auth_cookie=True)

        assert '"img": "<img ' in response, response

        seed_value = response.json['detail']['otpkey']['value']
        _, _, seed = seed_value.partition('//')

        otp = get_otp(seed, 1, digits=6)

        params = {'serial': serial, 'otp': otp}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'false' not in response

    def test_verify_totp_token(self):

        policy = {
            'name': 'T1',
            'action': 'enrollTOTP, delete, history, verify,',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response, response

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        serial = 'totp123'

        params = {'type': 'totp', 'genkey': '1', 'serial': serial}
        response = self.make_userselfservice_request(
            'enroll', params=params, auth_user=auth_user, new_auth_cookie=True)

        assert '"img": "<img ' in response, response

        seed_value = response.json['detail']['otpkey']['value']
        _, _, seed = seed_value.partition('//')

        t_counter = time2counter(t_time=datetime.utcnow(), t_step=30)

        otp = get_otp(seed, counter=t_counter,  digits=6)

        params = {'serial': serial, 'otp': otp}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'false' not in response

    def test_negative_userservice_verify(self):
        """
        verify that error handling is in place
        """

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        # ------------------------------------------------------------------ --

        policy = {
            'name': 'T1',
            'action': 'enrollTOTP, enrollHMAC, delete, history, verify,',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response, response

        # ------------------------------------------------------------------ --

        # 1. token

        serial1 = 'token_1'

        params = {'type': 'totp', 'genkey': '1', 'serial': serial1}
        response = self.make_userselfservice_request(
            'enroll', params=params, auth_user=auth_user, new_auth_cookie=True)

        assert '"img": "<img ' in response, response

        seed_value = response.json['detail']['otpkey']['value']
        _, _, _seed1 = seed_value.partition('//')

        # 2. token

        serial2 = 'token_2'

        params = {'type': 'hmac', 'genkey': '1', 'serial': serial2}
        response = self.make_userselfservice_request(
            'enroll', params=params, auth_user=auth_user, new_auth_cookie=True)

        assert '"img": "<img ' in response, response

        seed_value = response.json['detail']['otpkey']['value']
        _, _, seed2 = seed_value.partition('//')

        # ------------------------------------------------------------------ --

        # verification with multiple tokens by wildcard 'token_*'

        otp = get_otp(seed2, counter=1,  digits=6)

        params = {'serial': 'token_*', 'otp': otp}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'false' in response
        assert 'multiple tokens found!' in response

        # ------------------------------------------------------------------ --

        # verification with no token 'nokto_*'

        otp = get_otp(seed2, counter=1,  digits=6)

        params = {'serial': 'nokto_*', 'otp': otp}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'false' in response
        assert 'no token found!' in response

        # ------------------------------------------------------------------ --

        # verification with wrong parameters

        otp = get_otp(seed2, counter=1,  digits=6)

        params = {'serial': 'token_1', 'oktop': otp}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'false' in response
        assert 'unsupported parameters' in response

        # ------------------------------------------------------------------ --

        # verification with additional, not specified, parameters

        otp = get_otp(seed2, counter=1,  digits=6)

        params = {'serial': 'token_1', 'otp': otp, 'no': 'doubt'}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'false' in response
        assert 'unsupported parameters' in response

        # ------------------------------------------------------------------ --

        # check for execption if selfservice 'verify' policy is not defined

        response = self.make_system_request('delPolicy', params={'name': 'T1'})
        assert 'false' not in response

        otp = get_otp(seed2, counter=1,  digits=6)

        params = {'serial': 'nokto_*', 'otp': otp, 'no': 'doubt'}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'false' in response
        assert 'not allow' in response

    def test_verify_cr_hmac_token(self):

        policy = {
            'name': 'T1',
            'action': 'enrollHMAC, delete, history, verify,',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response, response

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        serial = 'hmac123'

        params = {'type': 'hmac', 'genkey': '1', 'serial': serial}
        response = self.make_userselfservice_request(
            'enroll', params=params, auth_user=auth_user, new_auth_cookie=True)

        assert '"img": "<img ' in response, response

        seed_value = response.json['detail']['otpkey']['value']
        _, _, seed = seed_value.partition('//')

        params = {'serial': serial}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        jresp = response.json
        assert jresp['result']['value'] == False
        assert jresp['detail']['reply_mode'] == ['offline']

        otp = get_otp(seed, 1, digits=6)

        params = {'serial': serial, 'otp': otp}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'false' not in response

    @patch.object(linotp.provider.smsprovider.FileSMSProvider.FileSMSProvider,
                  'submitMessage', mocked_submitMessage)
    def test_verify_cr_sms_token(self):
        """ verify challenge response for sms token """

        # setup policies

        policy = {
            'name': 'T1',
            'action': 'enrollSMS, delete, history, verify,',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response, response

        # define the sms provider - we use a mocked file provider

        response = self.define_provider({'name': 'simple_provider'})
        assert '"value": true' in response, response

        # define provider as default

        params = {'name': 'simple_provider_policy',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'sms_provider=simple_provider',
                  'user': '*',
                  }

        response = self.make_system_request(action='setPolicy',
                                            params=params)
        assert 'false' not in response, response

        # ------------------------------------------------------------------ --

        # enroll sms token

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        serial = 'sms123'

        params = {'type': 'sms', 'serial': serial, 'phone': '049 123 452 4543'}
        response = self.make_userselfservice_request(
            'enroll', params=params, auth_user=auth_user, new_auth_cookie=True)

        assert 'detail' in response, response

        # ------------------------------------------------------------------ --

        # trigger the challenge

        params = {'serial': serial}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'detail' in response

        jresp = response.json
        transaction_id = jresp['detail']['transactionid']
        assert transaction_id
        assert 'false' in response

        # ------------------------------------------------------------------ --

        # reply with the transaction and otp

        (_phone, otp) = SMS_MESSAGE_OTP

        params = {
            'serial': serial,
            'otp': otp,
            'transactionid': transaction_id
        }

        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'false' not in response

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


from linotp.tests import TestController
from linotp.lib.HMAC import HmacOtp

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

    def test_verify_sms_token(self):
        """ verify that currently no challenge response token are supported """

        policy = {
            'name': 'T1',
            'action': 'enrollSMS, delete, history, verify,',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response, response

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        serial = 'sms123'

        params = {'type': 'sms', 'serial': serial, 'phone': '049 123 452 4543'}
        response = self.make_userselfservice_request(
            'enroll', params=params, auth_user=auth_user, new_auth_cookie=True)

        assert 'detail' in response, response

        seed = response.json['detail']['otpkey']
        otp = get_otp(seed, counter=2,  digits=6)

        params = {'serial': serial, 'otp': otp}
        response = self.make_userselfservice_request(
            'verify', params=params, auth_user=auth_user)

        assert 'false' in response
        assert 'not supported by now' in response


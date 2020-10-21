# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2020 arxes-tolina GmbH
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


from mock import patch

from . import TestUserserviceController
from linotp.tests import url

import linotp.provider.smsprovider.FileSMSProvider
from .qr_token_validation import QR_Token_Validation as QR


SMS_MESSAGE_OTP = None
SMS_MESSAGE_CONFIG = None

def mocked_submitMessage(FileSMS_Object, *argparams, **kwparams):

    # this hook is defined to grep the otp and make it globally available
    global SMS_MESSAGE_OTP
    SMS_MESSAGE_OTP = argparams

    # we call here the original sms submitter - as we are a functional test
    global SMS_MESSAGE_CONFIG
    SMS_MESSAGE_CONFIG = FileSMS_Object.config

    return True

class TestUserserviceLogin(TestUserserviceController):
    '''
    Selfservice Authorization: test for user authentication with otp
    '''

    def setUp(self):

        # clean setup
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        response = self.make_system_request(
                        'setConfig', params={'splitAtSign': 'true'})
        assert 'false' not in response.body

        TestUserserviceController.setUp(self)

        # create the common resolvers and realm
        self.create_common_resolvers()
        self.create_common_realms()


    def tearDown(self):

        TestUserserviceController.tearDown(self)


    def test_no_mfa_login(self):
        """test with no mfa authentication.
        """

        self.delete_all_policies()

        policy = {
            'name': 'no_mfa',
            'action': 'history',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'}

        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response

        auth_data = {
            'username': 'passthru_user1@myDefRealm',
            'password': 'geheim1'
        }

        response = self.client.post('userservice/login', data=auth_data)
        response.body = response.data.decode("utf-8")

        assert 'false' not in response

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        params = {
            'session': auth_cookie,
            }

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)
        response = self.client.post('userservice/history', data=params)
        response.body = response.data.decode("utf-8")

        assert 'page' in response

    def test_login_wrong_cookie(self):
        """verify login with wrong cookie will drop cookie in response."""

        # ------------------------------------------------------------------ --

        # verify that the authentication was successfull by quering history

        wrong_cookie = 'wHzUPEnpEEZDQvSjKitKtPi4bgX9mM5R2M8cJDGf5Sg'
        self.client.set_cookie('.localhost', 'user_selfservice', wrong_cookie)

        auth_data = {
            'username': 'passthru_user1@myDefRealm',
            'password': 'geheim1',
        }

        response = self.client.post('userservice/login', data=auth_data)

        auth_cookie = self.get_cookies(response).get('user_selfservice')
        assert not auth_cookie

        jresp = response.json
        assert jresp['result']['value'] is True

    def test_mfa_login_one_step(self):
        """test with one step mfa authentication."""

        # ------------------------------------------------------------------ --

        # setup:
        # delete all policies, enroll token and define mfa policy

        self.delete_all_policies()

        otps = ['870581', '793334', '088491', '013126', '818771',
                '454594', '217219', '250710', '478893', '517407']

        otps = otps[::-1]

        params = {
            'user': 'passthru_user1@myDefRealm',
            'pin': 'Test123!',
            'serial': 'LoginToken',
            'otpkey': 'AD8EABE235FC57C815B26CEF3709075580B44738',
        }

        response = self.make_admin_request('init', params=params)
        assert '"img": "<img ' in response, response

        # define the selfservice policies

        policy = {
            'name': 'mfa_login',
            'action': 'mfa_login, history',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'}

        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response

        # ------------------------------------------------------------------ --

        # run the authentication

        auth_data = {
            'username': 'passthru_user1@myDefRealm',
            'password': 'geheim1',
            'otp': otps.pop(),
        }

        response = self.client.post('userservice/login', data=auth_data)
        response.body = response.data.decode("utf-8")

        assert 'false' not in response

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        # verify that the authentication was successfull by quering history

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)
        response = self.client.post(
            'userservice/history', data={'session': auth_cookie})

        response.body = response.data.decode("utf-8")

        assert 'page' in response


    def test_mfa_login_two_step(self):
        """test with multiple step mfa authentication."""

        # ------------------------------------------------------------------ --

        # setup:
        # delete all policies, enroll token and define mfa policy

        self.delete_all_policies()

        otps = ['870581', '793334', '088491', '013126', '818771',
                '454594', '217219', '250710', '478893', '517407']

        otps = otps[::-1]

        params = {
            'user': 'passthru_user1@myDefRealm',
            'pin': 'Test123!',
            'serial': 'LoginToken',
            'otpkey': 'AD8EABE235FC57C815B26CEF3709075580B44738',
        }

        response = self.make_admin_request('init', params=params)
        assert '"img": "<img ' in response, response

        # define the selfservice policies

        policy = {
            'name': 'mfa_login',
            'action': 'mfa_login, history',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'}

        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response

        # ------------------------------------------------------------------ --

        # run the authentication
        # 1. step - get informed, that we require an additional factor
        #           and *new* provide the token list

        auth_data = {
            'username': 'passthru_user1',
            'realm': 'myDefRealm',
            'password': 'geheim1',
        }

        response = self.client.post('userservice/login', data=auth_data)
        response.body = response.data.decode("utf-8")

        jresp = response.json
        assert jresp['result']['status']
        assert not jresp['result']['value']
        assert jresp['detail']['tokenList']
        assert jresp[
            'detail'][
                'tokenList'][0]['LinOtp.TokenSerialnumber'] == 'LoginToken'

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        # ------------------------------------------------------------------ --

        # 2. step in authentication:
        # - we provide the former sessiom, so we don't need to
        #   submit user and password again
        # - and the requested second factor

        auth_data = {
            'session': auth_cookie,
            'serial': 'LoginToken',
            'otp': otps.pop()
            }

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)
        response = self.client.post('userservice/login', data=auth_data)
        response.body = response.data.decode("utf-8")

        assert 'false' not in response

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        # ------------------------------------------------------------------ --

        # verify that the authentication was successfull by quering history

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)
        response = self.client.post(
            'userservice/history', data={'session': auth_cookie})

        response.body = response.data.decode("utf-8")

        assert 'page' in response


    @patch.object(linotp.provider.smsprovider.FileSMSProvider.FileSMSProvider,
                  'submitMessage', mocked_submitMessage)
    def test_mfa_login_two_step_challenge(self):
        """test with multiple step mfa authentication."""

        # ------------------------------------------------------------------ --

        # setup:
        # delete all policies, enroll token, provider and define mfa policy

        self.delete_all_policies()

        params = {
            'user': 'passthru_user1@myDefRealm',
            'pin': 'Test123!',
            'serial': 'LoginToken',
            'type': 'sms',
            'phone': '1234567890',
        }

        response = self.make_admin_request('init', params=params)
        assert 'false' not in response, response

        # define the selfservice policies

        policy = {
            'name': 'mfa_login',
            'action': 'mfa_login, history',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'}

        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response

        # define the sms provider - we use a mocked file provider

        response = self.define_sms_provider({'name': 'simple_provider'})
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

        # run the authentication
        # 1. step - get informed, that we require an additional factor
        #           and *new* provide the token list

        auth_data = {
            'username': 'passthru_user1',
            'realm': 'myDefRealm',
            'password': 'geheim1',
        }

        response = self.client.post('userservice/login', data=auth_data)
        response.body = response.data.decode("utf-8")

        jresp = response.json
        assert jresp['result']['status']
        assert not jresp['result']['value']
        assert jresp['detail']['tokenList']
        assert jresp[
            'detail'][
                'tokenList'][0]['LinOtp.TokenSerialnumber'] == 'LoginToken'

        # ------------------------------------------------------------------ --

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        # 2. step in authentication:
        # - we provide the former sessiom, so we don't need to
        #   submit user and password again
        # - and the requested second factor

        auth_data = {
            'session': auth_cookie,
            'serial': 'LoginToken',
            }

        response = self.client.post('userservice/login', data=auth_data)

        jresp = response.json
        assert jresp['result']['status']
        assert not jresp['result']['value']
        assert jresp['detail']['replyMode'] == ["offline"]

        transactionid = jresp['detail']['transactionId']

        _phone, otp = SMS_MESSAGE_OTP
        otp.split()[0].strip()

        # ------------------------------------------------------------------ --

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        # ------------------------------------------------------------------ --

        # 3.a step in authentication: provide a wrong otp

        auth_data = {
            'session': auth_cookie,
            'serial': 'LoginToken',
            'otp': otp[::-1],
            'transactionid': transactionid
            }

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)
        response = self.client.post('userservice/login', data=auth_data)

        jresp = response.json
        assert not jresp['result']['value']
        assert jresp['result']['status']

        # ------------------------------------------------------------------ --

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        # 4a. step in authentication: reestablish authentication

        auth_data = {
            'username': 'passthru_user1',
            'realm': 'myDefRealm',
            'password': 'geheim1',
        }
        response = self.client.post('userservice/login', data=auth_data)

        jresp = response.json
        assert not jresp['result']['value']
        msg = 'additional authentication parameter required'
        assert msg in jresp['detail']['message']

        # ------------------------------------------------------------------ --

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        # 4b. trigger new challenge

        auth_data = {
            'session': auth_cookie,
            'serial': 'LoginToken',
            }

        response = self.client.post('userservice/login', data=auth_data)

        jresp = response.json
        assert jresp['result']['status']
        assert not jresp['result']['value']
        assert jresp['detail']['replyMode'] == ["offline"]

        transactionid = jresp['detail']['transactionId']

        _phone, otp = SMS_MESSAGE_OTP
        otp = otp.split()[0].strip()

        # ------------------------------------------------------------------ --

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        # 4c. verify second factor

        auth_data = {
            'session': auth_cookie,
            'serial': 'LoginToken',
            'otp': otp,
            'transactionid': transactionid,
            }
        response = self.client.post('userservice/login', data=auth_data)

        jresp = response.json
        assert jresp['result']['value']

        # ------------------------------------------------------------------ --

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        # verify that the authentication was successfull by quering history

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)
        response = self.client.post(
            'userservice/history', data={'session': auth_cookie})

        response.body = response.data.decode("utf-8")

        assert 'page' in response

    def enroll_qr_token(self, serial='myQrToken'):
        """Helper to enroll an qr token done in the following steps

        * define the callback url
        * define the selfservice policies to verify the token
        * enroll the qr token
        * pair the qr token
        * run first challenge & challenge verification against /validate/check*

        :return: token info and the pub / priv key
        """

        # set pairing callback policies

        cb_url='/foo/bar/url'

        params = {'name': 'dummy1',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'qrtoken_pairing_callback_url=%s' % cb_url,
                  'user': '*'}

        response = self.make_system_request(action='setPolicy', params=params)
        assert 'false' not in response, response

        # ----------------------------------------------------------------- --

        # set challenge callback policies

        params = {
            'name': 'dummy3',
            'scope': 'authentication',
            'realm': '*',
            'action': 'qrtoken_challenge_callback_url=%s' % cb_url,
            'user': '*'
        }

        response = self.make_system_request(action='setPolicy', params=params)
        assert 'false' not in response, response

        params = {
            'name': 'enroll_policy',
            'scope': 'selfservice',
            'realm': '*',
            'action': 'activate_QRToken, enrollQR, verify',
            'user': '*'
        }

        response = self.make_system_request(action='setPolicy', params=params)
        assert 'false' not in response, response

        # ----------------------------------------------------------------- --

        # enroll the qr token:

        # response should contain pairing url, check if it was sent and validate

        user = 'passthru_user1@myDefRealm'
        serial = serial
        pin = '1234'

        secret_key, public_key = QR.create_keys()

        params = {'type': 'qr', 'pin': pin, 'user': user, 'serial': serial}
        response = self.make_admin_request('init', params)

        pairing_url = QR.get_pairing_url_from_response(response)

        # ------------------------------------------------------------------- --

        # do the pairing

        token_info = QR.create_user_token_by_pairing_url(pairing_url, pin)

        pairing_response = QR.create_pairing_response(
            public_key, token_info, token_id=1)

        params = {'pairing_response': pairing_response}

        response = self.make_validate_request('pair', params)
        response_dict = response.json

        assert not response_dict.get('result', {}).get('value', True)
        assert response_dict.get('result', {}).get('status', False)

        # ------------------------------------------------------------------- --

        # trigger a challenge

        params = {'serial': serial, 'pass': pin, 'data': serial}

        response = self.make_validate_request('check_s', params)
        response_dict = response.json

        assert 'detail' in response_dict
        detail = response_dict.get('detail')

        assert 'transactionid' in detail
        assert 'message' in detail

        # ------------------------------------------------------------------- --

        # verify the transaction

        # calculate the challenge response from the returned message
        # for verification we can use tan or sig

        message = detail.get('message')
        challenge, _sig, tan = QR.claculate_challenge_response(
                                        message, token_info, secret_key)

        params = {'transactionid': challenge['transaction_id'], 'pass': tan}
        response = self.make_validate_request('check_t', params)
        assert 'false' not in response

        return token_info, secret_key, public_key

    def test_qr_token_login(self):
        """Verify the userservice login with an qr token.

        after the setup by
          * defining the mfa policy and
          * enrolling the qr token

        we use the qrtoken for the login with following steps

        1. submit the login credentials, getting
           - the token list in response and
           - the credential-verified cookie

        2. submit the login with serial and credential-verified cookie
           to trigger a qr token challenge, getting
              - the challenge-started cookie and
              - the challenge response with the qr code data

        3. from the challenge data, we can calculate the tan or signature
            where we use the
            - tan as otp value and
            - the transaction id and
            - the challenge-started cookie

        4. verification is done by accessing the userservice/history

        """

        serial='myQrToken'

        # ----------------------------------------------------------------- --

        # do the setup: enroll token and setup mfa policy

        token_info, secret_key, _public_key = self.enroll_qr_token(serial)

        policy = {
            'name': 'mfa_login',
            'action': 'mfa_login, history',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'}

        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response

        # ----------------------------------------------------------------- --

        # run the first credential verification step

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        response = self.client.post(url(controller='userservice',
                                        action='login'), data=auth_user)

        jresp = response.json
        tokenlist = jresp['detail']["tokenList"]
        assert len(tokenlist) == 1
        assert tokenlist[0]['LinOtp.TokenSerialnumber'] == 'myQrToken'

        # ----------------------------------------------------------------- --

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        assert auth_cookie

        # ----------------------------------------------------------------- --

        # next request is to trigger the login challenge
        # - response should contain the challenge information

        self.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='login'), data=params)

        jresp = response.json
        assert jresp['detail']
        assert 'detail' in jresp
        detail = jresp.get('detail')

        assert 'transactionId' in detail
        assert 'message' in detail
        assert 'transactionData' in detail

        # ----------------------------------------------------------------- --

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        assert auth_cookie

        # ----------------------------------------------------------------- --

        # query the status - the challenge might be answerd already via
        # callback

        self.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='login'), data=params)

        jresp = response.json
        assert jresp['detail']

        # ----------------------------------------------------------------- --

        # verify the transaction

        # calculate the challenge response from the returned message
        # - for verification we can use tan or sig as signature

        message = detail.get('transactionData')
        challenge, _sig, tan = QR.claculate_challenge_response(
                                        message, token_info, secret_key)

        # ----------------------------------------------------------------- --

        self.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {
            'transactionid': challenge['transaction_id'],
            'session': auth_cookie,
            'otp': tan
            }

        response = self.client.post(url(controller='userservice',
                                        action='login'), data=params)

        response.body = response.data.decode("utf-8")
        assert '"value": true' in response, response

        # ----------------------------------------------------------------- --

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        # ----------------------------------------------------------------- --

        # verify that the authentication was successful

        self.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='history'), data=params)

        response.body = response.data.decode("utf-8")
        assert '"rows": [' in response, response

        return

    def test_qr_token_polling_login(self):
        """Verify the userservice login with an qr token.

        after the setup by
          * defining the mfa policy and
          * enrolling the qr token

        we use the qrtoken for the login with following steps

        1. submit the login credentials, getting
           - the token list in response and
           - the credential-verified cookie

        2. submit the login with serial and credential-verified cookie
           to trigger a qr token challenge, getting
              - the challenge-started cookie and
              - the challenge response with the qr code data

        3. from the challenge data, we can calculate the tan or signature
            where we use the
            - tan as otp value and
            - the transaction id and
            - the challenge-started cookie

        4. while the
            - the login status is polled several times
            - the token is verified assyncchronously and
            - the login will succeed after the verification

        5. verification that access is granted is done by accessing the
           userservice/history endpoint
        """

        serial='myQrToken'

        # ----------------------------------------------------------------- --

        # do the setup: enroll token and setup mfa policy

        token_info, secret_key, _public_key = self.enroll_qr_token(serial)

        policy = {
            'name': 'mfa_login',
            'action': 'mfa_login, history',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'}

        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not in response

        # ----------------------------------------------------------------- --

        # run the first credential verification step

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        response = self.client.post(url(controller='userservice',
                                        action='login'), data=auth_user)

        jresp = response.json
        tokenlist = jresp['detail']["tokenList"]
        assert len(tokenlist) == 1
        assert tokenlist[0]['LinOtp.TokenSerialnumber'] == 'myQrToken'

        # ----------------------------------------------------------------- --

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        assert auth_cookie

        # ----------------------------------------------------------------- --

        # next request is to trigger the login challenge
        # - response should contain the challenge information

        self.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='login'), data=params)

        jresp = response.json
        assert jresp['detail']
        assert 'detail' in jresp
        detail = jresp.get('detail')

        assert 'transactionId' in detail
        assert 'message' in detail
        assert 'transactionData' in detail

        # ----------------------------------------------------------------- --

        # calculate the challenge response from the returned message
        # - for verification we can use tan or sig as signature

        message = detail.get('transactionData')
        challenge, sig, tan = QR.claculate_challenge_response(
                                        message, token_info, secret_key)

        # ----------------------------------------------------------------- --

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        assert auth_cookie

        # ----------------------------------------------------------------- --

        # query the status - the challenge might be answerd already via
        # callback

        self.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='login'), data=params)

        jresp = response.json
        assert not jresp['result']['value']

        # ----------------------------------------------------------------- --
        # verify the transaction

        params = {
            'transactionid': challenge['transaction_id'], 'pass': sig
            }
        response = self.client.post(url(controller='validate',
                                        action='check_t'), data=params)

        jresp = response.json
        assert jresp['result']['value']['value']
        # ----------------------------------------------------------------- --

        # query the status - the challenge might be answerd already via
        # callback

        self.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='login'), data=params)

        jresp = response.json
        assert jresp['result']['value']

        # ----------------------------------------------------------------- --

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        # ----------------------------------------------------------------- --

        # verify that the authentication was successful

        self.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='history'), data=params)

        response.body = response.data.decode("utf-8")
        assert '"rows": [' in response, response

        return

# eof #

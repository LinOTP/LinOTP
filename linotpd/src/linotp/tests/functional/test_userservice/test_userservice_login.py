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

import linotp.provider.smsprovider.FileSMSProvider


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
            }

        self.client.set_cookie('.localhost', 'user_selfservice', auth_cookie)
        response = self.client.post('userservice/login', data=auth_data)
        response.body = response.data.decode("utf-8")
        jresp = response.json

        assert jresp['result']['status']
        assert not jresp['result']['value']
        assert jresp['detail']['reply_mode'] == ["offline"]

        cookies = self.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        transactionid, otp = SMS_MESSAGE_OTP

        # ------------------------------------------------------------------ --

        # 3. step in authentication:
        #   provide the recieved otp

        auth_data = {
            'session': auth_cookie,
            'serial': 'LoginToken',
            'otp': otp,
            'transactionid': transactionid
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

# eof #

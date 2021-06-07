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


import pytest

import logging
import json

from linotp.tests import TestController, url

log = logging.getLogger(__name__)


class TestUserserviceAuthController(TestController):
    '''
    Selfservice Authorization: test for user authetication with otp

    the selfservice authetication could be switched on to require an OTP
    by the mfa_login policy. The test runs the authentication request and
    enrolles an hmac token, which is deleted in the second request

    run the selfservice action to create and delete the token

    the auth user then requires 3 entries, where in the testing framework
    the concatinated b64(otp) + ':' + b64(password) is provided toward
    the userservice api

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
        self.local_setup()

    def tearDown(self):
        TestController.tearDown(self)

    def createPolicy(self, param):
        policy = {'name': 'self01',
                  'scope': 'selfservice',
                  'realm': 'myDefRealm',
                  'user': None,
                  'action': 'history', }

        # overwrite the default defintion
        if not param:
            param = {}
        policy.update(param)
        name = policy['name']

        response = self.make_system_request('setPolicy', params=policy)
        assert '"status": true' in response, response
        assert ('"setPolicy %s": {' % name) in response, response

        return

    def local_setup(self):
        """ run the local test setup """

        otps = ['870581', '793334', '088491', '013126', '818771',
                '454594', '217219', '250710', '478893', '517407']

        self.otps = otps[::-1]

        self.pin = 'Test123!'

        params = {
            'user': 'passthru_user1@myDefRealm',
            'pin': self.pin,
            'serial': 'LoginToken',
            'otpkey': 'AD8EABE235FC57C815B26CEF3709075580B44738',
        }

        response = self.make_admin_request('init', params=params)
        assert '"img": "<img ' in response, response

        policy = {
            'name': 'T1',
            'action': 'enrollHMAC, mfa_login, delete, history',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'selfservice'}

        self.createPolicy(policy)

        policy = {
            'name': 'auth_challenge',
            'action': 'challenge_response=hmac, ',
            'user': ' passthru.*.myDefRes:',
            'realm': '*',
            'scope': 'authentication'}

        self.createPolicy(policy)

    def get_audit_entries(self, num=3, page=1):
        '''
        query the last audit entry
        # audit/search?sortorder=desc&rp=1

        Be aware: this method could not be moved into the parent class !!!
                  it wont be found :(
        '''
        params = {'sortorder': 'desc',
                  'rp': num,
                  'page': page,
                  }
        response = self.make_audit_request(action="search",
                                           params=params)

        jresp = json.loads(response.body)
        for row in jresp.get('rows',[]):
            cell_info = row.get('cell',[])
            yield cell_info

    # ---------------------------------------------------------------------- --

    def test_login_with_token(self):
        """
        check that the login generate a cookie, which does not require
        to reenter credentials while login session is valid
        """

        auth_user = {'login': 'passthru_user1@myDefRealm',
                     'password': 'geheim1'}

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userselfservice_request('enroll',
                                                     params=params,
                                                     auth_user=auth_user,
                                                     new_auth_cookie=True)

        assert 'additional authentication parameter required' \
                        in response

        auth_user['otp'] = self.otps.pop()

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userselfservice_request('enroll',
                                                     params=params,
                                                     auth_user=auth_user,
                                                     new_auth_cookie=True)

        assert '"img": "<img ' in response, response

        params = {'serial': 'hmac123'}
        response = self.make_userselfservice_request('delete',
                                                     params=params,
                                                     auth_user=auth_user)

        assert '"delete token": 1' in response, response

        return

    # ---------------------------------------------------------------------- --

    def test_login_without_token(self):
        """
        check if mfa_passOnNoToken will allow user to login with u/p and no otp
        """

        # prove that user has no tokens

        self.delete_all_token()

        auth_user = {'login': 'passthru_user1@myDefRealm',
                     'password': 'geheim1'}

        params = {}
        response = self.make_userselfservice_request('history',
                                                     params=params,
                                                     auth_user=auth_user,
                                                     new_auth_cookie=True)

        assert 'additional authentication parameter required' in response

        # after switching on the policy mfa_passOnNoToken the user can login

        params = {
            'name': 'mfa_noToken',
            'active': True,
            'scope': 'selfservice',
            'action': 'mfa_login, mfa_passOnNoToken',
            'user': '*',
            'realm': '*',
            }
        response = self.make_system_request('setPolicy', params=params)
        assert 'false' not in response

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userselfservice_request('enroll',
                                                     params=params,
                                                     auth_user=auth_user,
                                                     new_auth_cookie=True)

        assert '"img": "<img ' in response, response

        # after the user has enrolled a tokan and has logged out,
        # the login with u/p is not possible anymore

        params = {}
        response = self.make_userselfservice_request('logout',
                                                     params=params,
                                                     auth_user=auth_user)
        assert "true" in response

        with self.assertRaises(Exception) as exx:
            params = {'serial': 'hmac123'}
            response = self.make_userselfservice_request('delete',
                                                         params=params,
                                                         auth_user=auth_user)

        msg = "%s" % exx.exception
        assert 'Server Error 401' in msg

        self.delete_all_token()
        self.delete_policy(name='mfa_noToken')

        return

    @pytest.mark.exclude_sqlite
    def test_login_with_false_password(self):
        """
        check that the login generate a cookie, which does not require
        to reenter credentials while login session is valid
        """

        auth_user = {'login': 'passthru_user1@myDefRealm',
                     'password': 'WRONGPASS'}

        auth_user['otp'] = self.otps.pop()

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userselfservice_request('enroll',
                                                     params=params,
                                                     auth_user=auth_user,
                                                     new_auth_cookie=True)

        assert '"value": false' in response, response

        # ----------------------------------------------------------------- ---

        # now we verify that the faild login is in the audit log and
        # the exception does not appear anymore

        unbound_msg = ('UnboundLocalError("local variable \'reply\' '
                       'referenced before assignment",)')

        failed_auth_msg1 = "User(login='passthru_user1'"
        failed_auth_msg2 = "failed to authenticate!"

        unbound_not_found = True
        failed_auth_found = False

        entries = self.get_audit_entries(num=5, page=1)
        for entry in entries:

            if unbound_msg in entry:
                unbound_not_found = False

            if failed_auth_msg1 in entry[11] and failed_auth_msg2 in entry[11]:
                failed_auth_found = True

        assert unbound_not_found, entries
        assert failed_auth_found, entries

        return


    def test_login_with_challenge_response(self):
        """
        test authentication with challenge response
        with a single token

        the authentication is running in multiple steps:

            1. get the credentials_verified step

            2. by calling the login with the 'credentials_verified' cookie
               and no otp, we trigger a challenge

            3a. reply with the previous cookie 'challenge_triggered'
               and an wrong otp should increment the token fail count

            3b. reply with the previous cookie 'challenge_triggered'
               and the otp should return the final 'authenticated' cookie

        After the 3 step any operation could be made, like history

        """

        # ------------------------------------------------------------------ --

        # run the credential verification step

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        response = self.client.post(url(controller='userservice',
                                        action='login'), data=auth_user)

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        jresp = response.json
        tokenlist = jresp['detail']["tokenList"]
        assert len(tokenlist) == 1
        assert tokenlist[0]['LinOtp.TokenSerialnumber'] == 'LoginToken'

        # ------------------------------------------------------------------ --

        # verify that 'history' could not be called in this status

        params = {}
        params['session'] = 'void'

        response = self.client.post(url(controller='userservice',
                                        action='history'), data=params)

        assert response.status_code == 401
        assert "No valid session" in response.data.decode()

        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='usertokenlist'), data=params)

        response.body = response.data.decode("utf-8")
        assert 'LoginToken' in response, response

        # ------------------------------------------------------------------ --

        # next request is to trigger the login challenge response

        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='login'), data=params)

        response.body = response.data.decode("utf-8")
        assert '"Please enter your otp value: "' in response, \
                        response

        # response should contain the challenge information

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        # next request replies to the challenge response with a wrong otp
        # and check if the fail counter is incremented

        params = {
            'serial': 'LoginToken'
            }
        response = self.make_admin_request('show', params)
        token_data = json.loads(response.body)['result']['value']['data'][0]
        failcount = token_data["LinOtp.FailCount"]

        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        otp = self.otps.pop()
        params['otp'] = otp[::-1]

        response = self.client.post(url(controller='userservice',
                                    action='login'), data=params)
        response.body = response.data.decode("utf-8")

        assert '"value": false' in response, response

        params = {
            'serial': 'LoginToken'
            }
        response = self.make_admin_request('show', params)
        token_data = json.loads(response.body)['result']['value']['data'][0]
        new_failcount = token_data["LinOtp.FailCount"]

        assert new_failcount > failcount

        # ------------------------------------------------------------------ --

        # next request replies to the challenge response with an emptyotp
        # and check if the fail counter is incremented

        params = {
            'serial': 'LoginToken'
            }
        response = self.make_admin_request('show', params)
        token_data = json.loads(response.body)['result']['value']['data'][0]
        failcount = token_data["LinOtp.FailCount"]

        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        otp = self.otps.pop()
        params['otp'] = ''

        response = self.client.post(url(controller='userservice',
                                    action='login'), data=params)

        response.body = response.data.decode("utf-8")

        assert '"value": false' in response, response

        params = {
            'serial': 'LoginToken'
            }
        response = self.make_admin_request('show', params)
        token_data = json.loads(response.body)['result']['value']['data'][0]
        new_failcount = token_data["LinOtp.FailCount"]

        assert new_failcount > failcount

        # ------------------------------------------------------------------ --

        # next request replies to the challenge response and
        # finishes the authorisation

        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        params['otp'] = self.otps.pop()

        response = self.client.post(url(controller='userservice',
                                        action='login'), data=params)

        response.body = response.data.decode("utf-8")
        assert '"value": true' in response, response

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='history'), data=params)

        response.body = response.data.decode("utf-8")
        assert '"rows": [' in response, response

        return


    def test_login_with_challenge_response_simple(self):
        """
        test authentication with challenge response
        with a single token

        the authentication is running in multiple steps:

        * calling login with a valid password will return
            * the token list and
            * the 'credentials_verified' cookie

        * calling the login with
            * the 'credentials_verified' cookie and
            * no otp
            will trigger a challenge
            - the serial is not required as the user has only one token

        * calling loggin with
            * the previous cookie 'challenge_triggered' and
            * the otp returns the final 'authenticated' cookie

        * the completness of the login is verified by quering the history

        """

        # ------------------------------------------------------------------ --

        # run the credential verification step

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        response = self.client.post(url(controller='userservice',
                                        action='login'), data=auth_user)

        jresp = response.json
        tokenlist = jresp['detail']["tokenList"]
        assert len(tokenlist) == 1
        assert tokenlist[0]['LinOtp.TokenSerialnumber'] == 'LoginToken'


        # ------------------------------------------------------------------ --

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        assert auth_cookie

        # ------------------------------------------------------------------ --

        # next request is to trigger the login challenge response
        # response should contain the challenge information

        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='login'), data=params)

        jresp = response.json
        assert jresp['detail']
        assert jresp['detail']['message'] == "Please enter your otp value: "

        # ------------------------------------------------------------------ --

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        # ------------------------------------------------------------------ --

        # replies to the challenge response which finishes the authorisation

        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        params['otp'] = self.otps.pop()

        response = self.client.post(url(controller='userservice',
                                        action='login'), data=params)

        response.body = response.data.decode("utf-8")
        assert '"value": true' in response, response

        # ------------------------------------------------------------------ --

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')

        # ------------------------------------------------------------------ --

        # verify that the authentication was successful

        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.post(url(controller='userservice',
                                        action='history'), data=params)

        response.body = response.data.decode("utf-8")
        assert '"rows": [' in response, response

        return

    def test_login_with_assync_challenge_response(self):
        """Test authentication with challenge response with a single token.

        the authentication is running in multiple steps:

            1. get the credentials_verified step

            2. by calling the login with the 'credentials_verified' cookie
               and no otp, we trigger a challenge

            3a. reply with the previous cookie 'challenge_triggered'
                and an wrong otp should increment the token fail count

            3b. reply with the previous cookie 'challenge_triggered'
                and no otp should increment check the status

            4. validate/check with otp should validate the challenge

            5. login request cookie 'challenge_triggered' should return the
               final 'authenticated' cookie

        After the 5 step any operation could be made, like history

        """

        # ------------------------------------------------------------------ --

        # run the credential verification step

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        response = self.client.get(url(controller='userservice',
                                    action='login'), data=auth_user)
        response.body = response.data.decode("utf-8")

        assert '"value": false' in response, response
        assert 'additional authentication parameter' in response, response

        # ------------------------------------------------------------------ --

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        # next request is to trigger the login challenge response

        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.client.get(url(controller='userservice',
                                    action='login'), data=params)
        response.body = response.data.decode("utf-8")

        assert '"Please enter your otp value: "' in response, response

        # response should contain the challenge information

        jresp = response.json
        transactionid = jresp['detail']['transactionId']

        # ------------------------------------------------------------------ --

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        # next request queries the challeng status

        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {'session': auth_cookie}
        response = self.client.get(url(controller='userservice',
                                    action='login'), data=params)
        response.body = response.data.decode("utf-8")

        assert '"value": false' in response, response

        # ------------------------------------------------------------------ --

        # make a /validate/check to verify the challenge

        params = {
            'pass': self.otps.pop(),
            'transactionid': transactionid,
            }
        response = self.client.get(url(controller='validate',
                                    action='check_t'), data=params)
        response.body = response.data.decode("utf-8")

        assert '"value": true' in response, response

        # ------------------------------------------------------------------ --

        # verify that transaction is verified

        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie

        response = self.client.get(url(controller='userservice',
                                    action='login'), data=params)
        response.body = response.data.decode("utf-8")

        assert '"value": true' in response, response

        # ------------------------------------------------------------------ --

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        TestController.set_cookie(self.client, 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        params = {}
        params['session'] = auth_cookie
        response = self.client.get(url(controller='userservice',
                                    action='history'), data=params)
        response.body = response.data.decode("utf-8")

        assert '"rows": [' in response, response


# eof #

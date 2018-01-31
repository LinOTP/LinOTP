# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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

# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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

import os
import webtest

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
        self.assertTrue('"status": true' in response, response)
        self.assertTrue(('"setPolicy %s": {' % name) in response, response)

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
        self.assertTrue('"img": "<img ' in response, response)

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

        self.assertTrue('additional authentication parameter required'
                        in response)

        auth_user['otp'] = self.otps.pop()

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userselfservice_request('enroll',
                                                     params=params,
                                                     auth_user=auth_user,
                                                     new_auth_cookie=True)

        self.assertTrue('"img": "<img ' in response, response)

        params = {'serial': 'hmac123'}
        response = self.make_userselfservice_request('delete',
                                                     params=params,
                                                     auth_user=auth_user)

        self.assertTrue('"delete token": 1' in response, response)

        return

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

        self.assertTrue('"value": false' in response, response)

        # ----------------------------------------------------------------- ---

        # now we verify that the faild login is in the audit log and
        # the exception does not appear anymore

        unbound_msg = ('UnboundLocalError("local variable \'reply\' '
                       'referenced before assignment",)')

        failed_auth_msg = ("User User(login=u'passthru_user1', "
                           "realm=u'mydefrealm', conf='' ::resolverUid:{}, "
                           "resolverConf:{}) failed to authenticate!")

        unbound_not_found = True
        failed_auth_found = False

        entries = self.get_audit_entries(num=5, page=1)
        for entry in entries:

            if unbound_msg in entry:
                unbound_not_found = False

            if failed_auth_msg in entry:
                failed_auth_found = True

        self.assertTrue(unbound_not_found, entries)
        self.assertTrue(failed_auth_found, entries)

        return

    def test_login_with_challenge_response(self):
        """
        test authentication with challenge response
        with a single token

        the authentication is running in multiple steps:

            1. get the credentials_verified step

            2. by calling the login with the 'credentials_verified' cookie
               and no otp, we trigger a challenge

            3. reply with the previous cookie 'challenge_triggered'
               and the otp should return the final 'authenticated' cookie

        After the 3 step any operation could be made, like history

        """

        # ------------------------------------------------------------------ --

        # run the credential verification step

        auth_user = {
            'login': 'passthru_user1@myDefRealm',
            'password': 'geheim1'}

        response = self.app.get(url(controller='userservice',
                                    action='login'), params=auth_user)

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        TestController.set_cookie(self.app, 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        # verify that 'history' could not be called in this status

        params = {}
        params['session'] = auth_cookie

        with self.assertRaises(webtest.app.AppError) as app_error:

            response = self.app.get(url(controller='userservice',
                                        action='history'), params=params)

        self.assertTrue("403 Forbidden" in app_error.exception.message)

        TestController.set_cookie(self.app, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.app.get(url(controller='userservice',
                                    action='usertokenlist'), params=params)

        self.assertTrue('LoginToken' in response, response)

        # ------------------------------------------------------------------ --

        # next request is to trigger the login challenge response

        TestController.set_cookie(self.app, 'user_selfservice', auth_cookie)

        params = {}
        params['session'] = auth_cookie
        response = self.app.get(url(controller='userservice',
                                    action='login'), params=params)

        self.assertTrue('"Please enter your otp value: "' in response,
                        response)

        # response should contain the challenge information

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        TestController.set_cookie(self.app, 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        # next request replies to the challenge response and
        # finishes the authorisation

        params = {}
        params['session'] = auth_cookie
        params['otp'] = self.otps.pop()

        response = self.app.get(url(controller='userservice',
                                    action='login'), params=params)

        self.assertTrue('"value": true' in response, response)

        cookies = TestController.get_cookies(response)
        auth_cookie = cookies.get('user_selfservice')
        TestController.set_cookie(self.app, 'user_selfservice', auth_cookie)

        # ------------------------------------------------------------------ --

        params = {}
        params['session'] = auth_cookie
        response = self.app.get(url(controller='userservice',
                                    action='history'), params=params)

        self.assertTrue('"rows": [' in response, response)

        return

# eof #

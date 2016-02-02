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
Test the otp_pin_random policy
"""

from collections import deque
from copy import deepcopy

import logging
log = logging.getLogger(__name__)

from linotp.tests import TestController

from distutils.version import LooseVersion

class TestRandompinController(TestController):
    """
    Test the otp_pin_random policy
    """

    # Don't mutate this data in test functions because it will be shared by all
    # tests. Instead copy it and then use it.
    tokens = [
        {
            'key': '3132333435363738393031323334353637383930',
            'type': 'hmac',
            'serial': None,
            'otplen': 6,
            'otps': deque(['755224', '287082', '359152', '969429', '338314',
                           '254676', '287922', '162583', '399871', '520489']),
            }
        ]
    # set up in setUp
    policies_for_deletion = None
    token_for_deletion = None

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()
        self.token_for_deletion = set()
        self.policies_for_deletion = set()
        return

    def tearDown(self):
        # Delete policies
        for policy in self.policies_for_deletion:
            self.delete_policy(policy)
        # Delete token
        for token in self.token_for_deletion:
            self.delete_token(token)

        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)
        return

    def test_simple_enroll(self):
        """
        After normal enroll just OTP is enough. With otp_pin_random policy not.

        After a normal enroll you can authenticate successfully with only OTP
        (because no PIN is set). If otp_pin_random is set this is no longer the
        case (because PIN has been set to an unknown value).
        """
        # Enroll token
        user = u'aἰσχύλος'  # realm myDefRealm
        token = deepcopy(self.tokens[0])
        self._enroll_token(token, user=user)

        # Login with only OTP succeeds
        self._validate(
            user,
            token['otps'].popleft(),
            )

        self._create_randompin_policy('myDefRealm')

        # Enroll new token
        token2 = deepcopy(self.tokens[0])
        self._enroll_token(token2, user=user)

        # Login with only OTP fails
        self._validate(
            user,
            token2['otps'].popleft(),
            expected='value-false'
            )
        return

    def test_simple_assign(self):
        """
        Same as 'test_simple_enroll' but with assign after enroll

        Verify the behaviour is the same if the token is first enrolled and then
        assigned to a user, instead of directly enrolling for the user as in
        test_simple_enroll.
        """
        # Enroll token
        user = u'aἰσχύλος'  # realm myDefRealm
        token = deepcopy(self.tokens[0])
        self._enroll_token(token)

        # Login with only OTP succeeds
        self._validate_check_s(
            token['serial'],
            token['otps'].popleft(),
            )

        self._assign(token['serial'], user)

        # Login with only OTP succeeds
        self._validate(
            user,
            token['otps'].popleft(),
            )

        self._create_randompin_policy('myDefRealm')

        # Enroll token
        user = u'aἰσχύλος'  # realm myDefRealm
        token2 = deepcopy(self.tokens[0])
        self._enroll_token(token2)

        # Login with only OTP fails (PIN unknown)
        self._validate_check_s(
            token2['serial'],
            token2['otps'].popleft(),
            expected='value-false'
            )

        self._assign(token2['serial'], user)

        # Login with only OTP fails (PIN unknown)
        self._validate(
            user,
            token2['otps'].popleft(),
            expected='value-false'
            )
        return

    def test_selfservice(self):
        """
        User logs into selfservice and sets PIN then authenticates with PIN+OTP

        After enrolling the PIN is unknown and the token can't be used. The user
        can log into the selfservice and set a PIN for his token. Then he can
        authenticate with PIN+OTP.

        This test will fail with WebTest 1.2.1 (Debian Squeeze) because of a
        bug that caused cookies to be quoted twice. The bug is fixed in 1.2.2.
        https://github.com/Pylons/webtest/commit/8471db1c2dc505c633bca2d39d5713dba0c51a42
        """

        # selfservice authentication does a redirect
        if self._version_['pylons'] <= LooseVersion('0.10'):
            self.skipTest("Pylons lower 0.10 does not support redirect!")

        self._create_randompin_policy('myDefRealm')
        self._create_selfservice_policy('myDefRealm')

        # Enroll token
        user = u'aἰσχύλος'  # realm myDefRealm
        token = deepcopy(self.tokens[0])
        self._enroll_token(token, user=user)

        # Login with only OTP fails (because PIN is unknown)
        self._validate(
            user,
            token['otps'].popleft(),
            expected='value-false'
            )

        # User logs into selfservice and sets PIN
        pwd = u'Πέρσαι'
        pin = 'mytokenpin'
        self._set_pin_in_selfservice(user, pwd, token['serial'], pin)

        # authenticate successfully with PIN+OTP
        self._validate(
            user,
            pin + token['otps'].popleft(),
            )
        return

    def test_admin_setpin(self):
        """
        Admin can set PIN, even after the user set it in selfservice

        This test will fail with WebTest 1.2.1 (Debian Squeeze) because of a
        bug that caused cookies to be quoted twice. The bug is fixed in 1.2.2.
        https://github.com/Pylons/webtest/commit/8471db1c2dc505c633bca2d39d5713dba0c51a42
        """

        # selfservice authentication does a redirect
        if self._version_['pylons'] <= LooseVersion('0.10'):
            self.skipTest("Pylons lower 0.10 does not support redirect!")

        self._create_randompin_policy('myDefRealm')
        self._create_selfservice_policy('myDefRealm')

        # Enroll token
        user = u'aἰσχύλος'  # realm myDefRealm
        token = deepcopy(self.tokens[0])
        self._enroll_token(token, user=user)

        # Login with only OTP fails (because PIN is unknown)
        self._validate(
            user,
            token['otps'].popleft(),
            expected='value-false'
            )

        # Admin sets PIN
        self._set_pin(token['serial'], 'admin-set-pin')
        # authenticate successfully with PIN+OTP
        self._validate(
            user,
            'admin-set-pin' + token['otps'].popleft(),
            )

        # User logs into selfservice and sets PIN
        pwd = u'Πέρσαι'
        pin = 'mytokenpin'
        self._set_pin_in_selfservice(user, pwd, token['serial'], pin)
        # authenticate successfully with PIN+OTP
        self._validate(
            user,
            pin + token['otps'].popleft(),
            )

        # Admin sets PIN again
        self._set_pin(token['serial'], 'second-admin-set-pin')
        # authenticate successfully with PIN+OTP
        self._validate(
            user,
            'second-admin-set-pin' + token['otps'].popleft(),
            )
        return

    def test_assign_other_user(self):
        """
        Verify PIN is overwritten when assigning token to a different user

        Test both the case where the user is in the same realm (where the policy
        is defined) and in another realm without opt_pin_random policy.

        This test will fail with WebTest 1.2.1 (Debian Squeeze) because of a
        bug that caused cookies to be quoted twice. The bug is fixed in 1.2.2.
        https://github.com/Pylons/webtest/commit/8471db1c2dc505c633bca2d39d5713dba0c51a42
        """
        # selfservice authentication does a redirect
        if self._version_['pylons'] <= LooseVersion('0.10'):
            self.skipTest("Pylons lower 0.10 does not support redirect!")

        self._create_randompin_policy('myDefRealm')
        self._create_selfservice_policy('myDefRealm')

        # Enroll token
        user = u'aἰσχύλος'  # realm myDefRealm
        token = deepcopy(self.tokens[0])
        self._enroll_token(token, user=user)

        # Login with only OTP fails (because PIN is unknown)
        self._validate(
            user,
            token['otps'].popleft(),
            expected='value-false'
            )

        # User logs into selfservice and sets PIN
        pwd = u'Πέρσαι'
        pin = 'mytokenpin'
        self._set_pin_in_selfservice(user, pwd, token['serial'], pin)
        # authenticate successfully with PIN+OTP
        self._validate(
            user,
            pin + token['otps'].popleft(),
            )

        # Assign token to new user
        new_user = 'beckett'
        self._assign(token['serial'], new_user)

        # authenticate fails because old PIN is no longer valid (i.e. was
        # overwritten with a random value during assign)
        self._validate(
            new_user,
            pin + token['otps'].popleft(),
            expected='value-false',
            )

        # Admin sets the PIN
        self._set_pin(token['serial'], 'admin-set-pin')

        # Now assign the token to a user in a realm without otp_pin_random
        # policy
        user3 = 'shakespeare@mymixrealm'
        self._assign(token['serial'], user3)

        # authenticate succeeds because PIN is NOT overwritten (in a real
        # scenario it is assumed the new user does not know the PIN of the
        # previous one)
        self._validate(
            user3,
            'admin-set-pin' + token['otps'].popleft(),
            )
        return

    def test_randompin_with_autoassignment(self):
        """
        Enroll with randompin and then autoassign token -> PIN is user password
        """
        self._create_randompin_policy('myDefRealm')

        token = deepcopy(self.tokens[0])
        self._enroll_token(token)

        # Login with only OTP fails (because PIN is unknown)
        self._validate_check_s(
            token['serial'],
            token['otps'].popleft(),
            expected='value-false'
            )

        # Create autoassignment policy
        self._create_autoassignment_policy('myDefRealm')
        # Set token realm for autoassignment to work
        self._set_token_realm(token['serial'], 'myDefRealm')

        # autoassign the token
        user = u'aἰσχύλος'
        pwd = u'Πέρσαι'
        self._validate(
            user,
            pwd + token['otps'].popleft(),
            )

        # The user password is set as PIN
        for _ in range(3):
            self._validate(
                user,
                pwd + token['otps'].popleft(),
                )
        return


    # -------- Private helper methods --------

    def _create_randompin_policy(self, realm):
        """
        Creates an otp_pin_random policy for 'realm'. Schedules the policy for
        deletion on tearDown.
        """
        policy_name = 'randompin'
        params = {
            'name': policy_name,
            'scope': 'enrollment',
            'action': 'otp_pin_random=12',
            'realm': realm,
            }
        self.create_policy(params)
        self.policies_for_deletion.add(policy_name)
        return

    def _create_selfservice_policy(self, realm):
        """
        Creates a selfservice policy for 'realm'. Schedules the policy for
        deletion on tearDown.
        """
        policy_name = 'selfservice'
        params = {
            'name': policy_name,
            'scope': 'selfservice',
            'action': 'setOTPPIN',
            'realm': realm,
            }
        self.create_policy(params)
        self.policies_for_deletion.add(policy_name)
        return

    def _create_autoassignment_policy(self, realm):
        """
        Creates an autoassignment policy for 'realm'. Schedules the policy for
        deletion on tearDown.
        """
        policy_name = 'autoassignment'
        params = {
            'name': policy_name,
            'scope': 'enrollment',
            'action': 'autoassignment',
            'realm': realm,
            }
        self.create_policy(params)
        self.policies_for_deletion.add(policy_name)
        return

    def _enroll_token(self, token, user=None):
        """
        Enroll token for 'user'.

        :param token: A dictionary with token information. This dictionary is
            augmented with 'serial' after enrolling the token.
        :param user: The name of the user to assign the token to. If None then
            the token is not assigned.
        """
        # enroll token
        params = {
            "otpkey": token['key'],
            "type": token['type'],
            "otplen": token['otplen'],
            }
        if user:
            params['user'] = user.encode('utf-8')
        response = self.make_admin_request('init', params=params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue(content['result']['value'])
        token['serial'] = content['detail']['serial']
        self.token_for_deletion.add(token['serial'])
        return

    def _validate(self, user, pwd, expected='success', err_msg=None):
        """
        Makes a validate/check request and verifies the response is as 'expected'

        :param user: Username or username@realm
        :param pwd: Password (e.g. PIN+OTP)
        :param expected: One of 'success', 'value-false', 'status-false' or 'both-false'
        :param err_msg: An error message to display if assert fails
        :return: The content (JSON object)
        """
        params = {
            'user': user.encode('utf-8'),
            'pass': pwd.encode('utf-8')
            }
        return self._validate_base(
            params,
            action='check',
            expected=expected,
            err_msg=err_msg,
            )

    def _validate_check_s(self, serial, pwd, expected='success', err_msg=None):
        """
        Makes a validate/check_s request and verifies the response is as
        'expected'

        :param serial: Token serial
        :param pwd: Password (e.g. PIN+OTP)
        :param expected: One of 'success', 'value-false', 'status-false' or
            'both-false'
        :param err_msg: An error message to display if assert fails
        :return: The content (JSON object)
        """
        params = {
            'serial': serial,
            'pass': pwd.encode('utf-8')
            }
        return self._validate_base(
            params,
            action='check_s',
            expected=expected,
            err_msg=err_msg,
            )

    def _validate_base(self, params, action='check', expected='success', err_msg=None):
        """
        Base method for /validate/<action> requests

        Don't call this method directly but use _validate() or
        _validate_check_s() instead.

        :param params: Request parameters
        :param expected: One of 'success', 'value-false', 'status-false' or
            'both-false'
        :param err_msg: An error message to display if assert fails
        :return: The content (JSON object)
        """
        response = self.make_validate_request(action, params=params)
        content = TestController.get_json_body(response)
        if not err_msg:
            err_msg = "validate/%s failed for %r. Response: %r" % (
                action,
                params,
                content
                )
        if expected == 'success':
            self.assertTrue(content['result']['status'], err_msg)
            self.assertTrue(content['result']['value'], err_msg)
        elif expected == 'value-false':
            self.assertTrue(content['result']['status'], err_msg)
            self.assertFalse(content['result']['value'], err_msg)
        elif expected == 'status-false':
            self.assertFalse(content['result']['status'], err_msg)
            self.assertTrue(content['result']['value'], err_msg)
        elif expected == 'both-false':
            self.assertFalse(content['result']['status'], err_msg)
            self.assertFalse(content['result']['value'], err_msg)
        else:
            self.fail("Unknown 'expected' %s" % expected)
        return content

    def _assign(self, serial, user):
        """
        Assign token defined by 'serial' to 'user'

        :param serial: Token serial number
        :param user: User (e.g. username@realm)
        :return: None
        """
        params = {
            'serial': serial,
            'user': user.encode('utf-8'),
            }
        response = self.make_admin_request('assign', params=params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue(content['result']['value'])
        return

    def _set_pin_in_selfservice(self, user, pwd, serial, pin):
        """
        Log into selfservice and set PIN

        :param user: username or username@realm
        :param pwd: User password
        :param serial: Token serial
        :param pin: The PIN to be set
        """
        params = {
            'login': user.encode('utf-8'),
            'password': pwd.encode('utf-8'),
            'defaultRealm': 'myDefRealm',
            'realm': '',
            'realmbox': False,
            }
        response = self.make_request('account', 'dologin', params=params)
        err_msg = "Unexpected response %r" % response
        self.assertEqual(302, response.status_int, err_msg)
        self.assertEqual('/', response.headers['location'])
        self.assertRegexpMatches(
            response.headers['Set-Cookie'],
            r"^linotp_selfservice=.*",
            err_msg,
            )

        session = self.app.cookies['linotp_selfservice']
        session = session.strip('"')
        self.assertGreater(len(session), 0, err_msg)
        params = {
            'serial': serial,
            'session': session,
            'userpin': pin,
            }
        cookies = {
            'linotp_selfservice': '"%s"' % session,
            }
        response = self.make_request(
            'userservice',
            'setpin',
            params=params,
            cookies=cookies,
            method='POST'
            )

        session_info = "cookie %r : session %r" % (cookies, session)
        try:
            content = TestController.get_json_body(response)
        except ValueError as err:
            log.error("%r: %s", err, session_info)
            raise Exception(err)

        self.assertTrue(content['result']['status'])
        expected = {"set userpin": 1}

        self.assertDictEqual(expected, content['result']['value'])
        return

    def _set_pin(self, serial, pin):
        """
        Set the token PIN 'pin' for the token identified by 'serial'
        """
        params = {
            'serial': serial,
            'pin': pin,
            }
        response = self.make_admin_request('set', params=params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue(content['result']['value'])
        return

    def _set_token_realm(self, serial, realm):
        """
        Set the token realm 'realm' for the token identified by 'serial'
        """
        assert serial and realm, "Both 'serial' and 'realm' required"
        params = {
            'serial': serial,
            'realms': realm,
        }
        response = self.make_admin_request('tokenrealm', params=params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertEqual(1, content['result']['value'])
        return

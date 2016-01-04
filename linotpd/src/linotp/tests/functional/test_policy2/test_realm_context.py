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
Test when policies defined for certain realms apply and when not. This depends
on the 'realm context' during the request.
"""

import unittest2
from collections import deque

from linotp.tests import TestController


class TestRealmContextController(TestController):
    """
    Test when policies defined for certain realms apply and when not. This
    depends on the 'realm context' during the request.
    """

    # set up in setUp
    policies_for_deletion = None
    token_for_deletion = None
    token = None

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self._setup_realms()
        self.token_for_deletion = set()
        self.policies_for_deletion = set()
        self.token = self._enroll_token_set_pin()

    def tearDown(self):
        # Delete policies
        for policy in self.policies_for_deletion:
            self.delete_policy(policy)
        # Delete token
        for token in self.token_for_deletion:
            self.delete_token(token)

        self._delete_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def test_realm_policy_applies_to_token_in_realm(self):
        """
        Verify policies for realms apply to token in that token realm

        If an otppin=2 policy (e.g. don't check PIN) is set for
        realm_no_default, then a token in that realm will only authenticate
        correctly without PIN.
        If the policy is set for realm_default, then a token in that realm will
        only authenticate correctly without PIN.
        """
        self._set_token_realm(self.token['serial'], 'realm_no_default')

        self._create_or_update_otppin2_policy('realm_no_default')

        # validate PIN+OTP -> fails
        self._validate(
            self.token['serial'],
            'mypin' + self.token['otps'].popleft(),
            action='check_s',
            expected='value-false',
            )
        # validate OTP -> succeeds
        self._validate(
            self.token['serial'],
            self.token['otps'].popleft(),
            action='check_s',
            )

        # Modify the policy so it is valid for realm_default
        self._create_or_update_otppin2_policy('realm_default')

        # validate PIN+OTP -> succeeds
        self._validate(
            self.token['serial'],
            'mypin' + self.token['otps'].popleft(),
            action='check_s',
            )

        # validate OTP -> fails
        self._validate(
            self.token['serial'],
            self.token['otps'].popleft(),
            action='check_s',
            expected='value-false',
            )

    def test_default_realm_policies_apply_to_token_without_realm(self):
        """
        Verify policies for the default realm apply to token without realm

        If an otppin=2 policy (e.g. don't check PIN) is set for
        realm_default, then a token without a token realm will only authenticate
        correctly without PIN.
        If the policy is set for realm_no_default, then a token without a token realm will
        only authenticate correctly with PIN.
        """
        # don't set token realm

        self._create_or_update_otppin2_policy('realm_default')

        # validate PIN+OTP -> fails
        self._validate(
            self.token['serial'],
            'mypin' + self.token['otps'].popleft(),
            action='check_s',
            expected='value-false',
            )
        # validate OTP -> succeeds
        self._validate(
            self.token['serial'],
            self.token['otps'].popleft(),
            action='check_s',
            )

        # Modify the policy so it is valid for realm_no_default
        self._create_or_update_otppin2_policy('realm_no_default')

        # validate PIN+OTP -> succeeds
        self._validate(
            self.token['serial'],
            'mypin' + self.token['otps'].popleft(),
            action='check_s',
            )

        # validate OTP -> fails
        self._validate(
            self.token['serial'],
            self.token['otps'].popleft(),
            action='check_s',
            expected='value-false',
            )

    def test_realm_policy_applies_to_token_assigned_to_user(self):
        """
        Verify policies for realms apply to token assigned to users in that realm
        """
        self._create_or_update_otppin2_policy('realm_no_default')

        # Assign to user in 'realm_no_default'
        self._assign(
            self.token['serial'],
            u'molière@realm_no_default',
            )

        # validate PIN+OTP -> fails
        self._validate(
            self.token['serial'],
            'mypin' + self.token['otps'].popleft(),
            action='check_s',
            expected='value-false',
            )
        # validate OTP -> succeeds
        self._validate(
            self.token['serial'],
            self.token['otps'].popleft(),
            action='check_s',
            )

        # Modify the policy so it is valid for realm_default
        self._create_or_update_otppin2_policy('realm_default')

        # validate PIN+OTP -> succeeds
        self._validate(
            self.token['serial'],
            'mypin' + self.token['otps'].popleft(),
            action='check_s',
            )

        # validate OTP -> fails
        self._validate(
            self.token['serial'],
            self.token['otps'].popleft(),
            action='check_s',
            expected='value-false',
            )

    def test_assign_then_settokenrealm(self):
        """
        Test: the token is assigned to a user and then to a different token realm

        This leads to some curious behaviour and it should probably not be
        allowed. Probably it would be best to enforce a match between user
        realm and token realm in the future.
        """
        self._create_or_update_otppin2_policy('realm_no_default')

        # Assign to user in 'realm_no_default'
        self._assign(
            self.token['serial'],
            u'molière@realm_no_default',
        )

        # Set token realm 'realm_default' (user is in 'realm_no_default')
        self._set_token_realm(self.token['serial'], 'realm_default')

        # validate/check_s PIN+OTP -> succeeds (because when using check_s the token
        # realm is relevant and for 'realm_default' no policy is set)
        self._validate(
            self.token['serial'],
            'mypin' + self.token['otps'].popleft(),
            action='check_s',
            )
        # validate/check_s OTP -> fails
        self._validate(
            self.token['serial'],
            self.token['otps'].popleft(),
            action='check_s',
            expected='value-false',
        )

        # validate/check PIN+OTP -> fails (because when using check the user
        # realm is relevant and for 'realm_no_default' the policy is set)
        self._validate(
            u'molière@realm_no_default',
            'mypin' + self.token['otps'].popleft(),
            action='check',
            expected='value-false',
            )
        # validate/check OTP -> should succeed but fails
        # This means that for this particular setup it is not possible to
        # successfully authenticate with /validate/check
        # As mentioned in the docstring of this method the solution is probably
        # to disallow the token realm to be different from the user realm.
        # That is: A token either has 0-N token realms or a user (including his
        # realm).
        self._validate(
            u'molière@realm_no_default',
            self.token['otps'].popleft(),
            action='check',
            expected='value-false',
        )

        # Update policy so it is valid for the default realm
        self._create_or_update_otppin2_policy('realm_default')

        # Set no token realm (empty)
        self._set_token_realm(self.token['serial'], '')

        # validate/check_s PIN+OTP -> fails (because when using check_s the
        # token realm is relevant. Since the token realm is emtpy the default
        # realm is used and the otppin=2 policy is valid for the default realm)
        self._validate(
            self.token['serial'],
            'mypin' + self.token['otps'].popleft(),
            action='check_s',
            expected='value-false',
            )
        # validate/check_s OTP -> succeeds
        self._validate(
            self.token['serial'],
            self.token['otps'].popleft(),
            action='check_s',
        )

        # validate/check PIN+OTP -> succeeds (because when using check the
        # user realm is relevant. Since the user realm is 'realm_no_default'
        # and for that realm no policy is set, it succeeds)
        self._validate(
            u'molière@realm_no_default',
            'mypin' + self.token['otps'].popleft(),
            action='check',
            )
        # validate/check_s OTP -> succeeds
        self._validate(
            u'molière@realm_no_default',
            self.token['otps'].popleft(),
            action='check',
            expected='value-false',
        )

    # -------- Private helper methods --------

    def _create_or_update_otppin2_policy(self, realm):
        """
        Create or update an otppin=2 policy for realm 'realm'
        :param realm: Realm the policy should be valid for
        :return: None
        """
        policy_name = 'otppin2'
        params = {
            'name': policy_name,
            'scope': 'authentication',
            'action': 'otppin=2',
            'realm': realm,
        }
        self.create_policy(params)
        # Since policies_for_deletion is a set() it does not matter if a
        # policy is re-added (during an update)
        self.policies_for_deletion.add(policy_name)

    def _enroll_token_set_pin(self):
        """
        Enroll token and set PIN 'mypin'

        :return: Dictionary with token information
        """
        token = {
            'key': '3132333435363738393031323334353637383930',
            'type': 'hmac',
            'serial': None,
            'otplen': 6,
            'otps': deque(['755224', '287082', '359152', '969429', '338314',
                           '254676', '287922', '162583', '399871', '520489']),
            }
        # enroll token
        params = {
            "otpkey": token['key'],
            "type": token['type'],
            "otplen": token['otplen'],
            }
        response = self.make_admin_request('init', params=params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue(content['result']['value'])
        token['serial'] = content['detail']['serial']
        self.token_for_deletion.add(token['serial'])

        # set PIN
        params = {
            'serial': token['serial'],
            'pin': 'mypin',
            }
        response = self.make_admin_request('set', params=params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue(content['result']['value'])
        return token

    def _set_token_realm(self, serial, realm):
        """
        Set the token realm 'realm' for token defined by 'serial'
        """
        params = {
            'serial': serial,
            'realms': realm,
            }
        response = self.make_admin_request('tokenrealm', params=params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertTrue(content['result']['value'])

    def _setup_realms(self):
        """
        Setup 2 realms 'realm_default' and 'realm_no_default' with resolver
        myDefRes.
        """
        for realm in ('realm_default', 'realm_no_default'):
            response = self.create_realm(
                realm=realm,
                resolvers=self.resolvers['myDefRes'],
                )
            content = TestController.get_json_body(response)
            self.assertTrue(content['result']['status'])
            self.assertTrue(content['result']['value'])

        # Assert 'realm_default' is default
        response = self.make_system_request('getRealms', {})
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        realms = content['result']['value']
        self.assertEqual(len(realms), 2)
        self.assertIn('realm_default', realms)
        self.assertIn('default', realms['realm_default'])
        self.assertTrue(realms['realm_default']['default'])

    def _delete_realms(self):
        """
        Delete the realms set up in _setup_realms.
        """
        for realm in ('realm_default', 'realm_no_default'):
            params = {
                "realm": realm,
                }
            response = self.make_system_request('delRealm', params)
            content = TestController.get_json_body(response)
            self.assertTrue(content['result']['status'])
            expected_value = {u'delRealm': {u'result': True}}
            self.assertDictEqual(expected_value, content['result']['value'])

    def _validate(self, user_or_serial, pwd, expected='success', err_msg=None, action='check'):
        """
        Makes a validate/check request and verifies the response is as 'expected'

        :param user_or_serial: Username or username@realm or token serial number
        :param pwd: Password (e.g. PIN+OTP)
        :param expected: One of 'success', 'value-false', 'status-false' or 'both-false'
        :param err_msg: An error message to display if assert fails
        :param action: The validate action (typically check or check_s)
        :return: The content (JSON object)
        """
        params = {
            'pass': pwd.encode('utf-8')
            }
        if action == 'check':
            params['user'] = user_or_serial.encode('utf-8')
        elif action == 'check_s':
            params['serial'] = user_or_serial
        else:
            self.fail("Action %s not implemented" % action)

        response = self.make_validate_request(action, params=params)
        content = TestController.get_json_body(response)
        if not err_msg:
            err_msg = "validate/%s failed for %r. Response: %r" % (
                action,
                user_or_serial,
                content,
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


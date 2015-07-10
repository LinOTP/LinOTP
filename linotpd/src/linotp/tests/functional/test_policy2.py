# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
Policy tests.

This module tries to have fewer dependencies/requirements than test_policy.py
and to avoid the fixed test order in test_policy.py but it tests similar
things. If test_policy.py is cleaned up they can be merged.
"""

import unittest2
from collections import deque

from linotp.tests import TestController


class TestAutoassignmentController(TestController):
    """
    Test the autoassignment Policy.
    """

    # Define a list of 5 token with known OTP values. The 'serial' is set
    # during enrollment to the value chosen by LinOTP
    token_list = [
        {
            'key': '3132333435363738393031323334353637383930',
            'type': 'hmac',
            'serial': None,
            'otplen': 6,
            'otps': ['755224', '287082', '359152'],
        },
        {
            'key': '4132333435363738393031323334353637383930',
            'type': 'hmac',
            'serial': None,
            'otplen': 6,
            'otps': ['297991', '212756', '338869'],
        },
        {
            'key': '5132333435363738393031323334353637383930',
            'type': 'hmac',
            'serial': None,
            'otplen': 6,
            'otps': ['841650', '850446', '352919'],
        },
        {
            'key': '6132333435363738393031323334353637383930',
            'type': 'hmac',
            'serial': None,
            'otplen': 6,
            'otps': ['425323', '141798', '123782'],
        },
        {
            'key': '9163508031b20d2fbb1868954e041729',
            'type': 'yubikey',
            'serial': None,
            'otplen': 48,
            'otps': [
                "ecebeeejedecebeg" + "fcniufvgvjturjgvinhebbbertjnihit",
                "ecebeeejedecebeg" + "tbkfkdhnfjbjnkcbtbcckklhvgkljifu",
                "ecebeeejedecebeg" + "ktvkekfgufndgbfvctgfrrkinergbtdj",
                ],
            },
        ]

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()
        self._enroll_token(self.token_list)

    def tearDown(self):
        self._delete_token(self.token_list)
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def test_autoassign_mixed_token(self):
        """
        Autoassignment with 4 HMAC and 1 Yubikey token to 5 different users

        5 Token (4 HMAC + 1 Yubikey) are enrolled and put together in the same
        token realm.  An autoenrollment policy for that realm is created.  5
        different users from that realm autoassign themselves one token each by
        authenticating with their user-store password and an OTP value
        corresponding to that token.
        """

        token_list = self.token_list

        self._create_autoassignment_policy('my_autoassign_policy', 'mydefrealm')
        self._set_token_realm(token_list, 'mydefrealm')

        # 5 (user, password) pairs from myDefRealm
        users = [
            (u'molière', u'molière'),
            (u'shakespeare', u'shakespeare1'),
            (u'lorca', u'lorca1'),
            (u'aἰσχύλος', u'Πέρσαι'),
            (u'beckett', u'beckett1'),
            ]

        # autoassign token to users
        for i in range(5):
            user_name, user_pwd = users[i]
            token = token_list[i]
            self._validate(
                user_name,
                user_pwd + token['otps'][0],
                )

        for i in range(5):
            # Assert the token was assigned to the correct user
            user_name, user_pwd = users[i]
            token = token_list[i]
            response = self.make_admin_request('getTokenOwner', {'serial': token['serial']})
            content = TestController.get_json_body(response)
            self.assertTrue(content['result']['status'])
            self.assertEqual(user_name, content['result']['value']['username'])

            # Validate the remaining OTP values
            for j in range(1, 3):
                self._validate(
                    user_name,
                    user_pwd + token['otps'][j],
                    )
        self.delete_policy('my_autoassign_policy')

    def test_cant_autoassign_assigned_token(self):
        """
        It is not possible to autoassign a token that has already been assigned.
        """
        # Only one token required for this test
        token_list = self.token_list[0:1]

        # Put all token in the same realm
        self._create_autoassignment_policy('my_autoassign_policy', 'mydefrealm')
        self._set_token_realm(token_list, 'mydefrealm')

        # (user, password) pairs from myDefRealm
        users = [
            (u'molière', u'molière'),
            (u'shakespeare', u'shakespeare1'),
        ]

        # Assign token[0] to users[0]
        user_name, user_pwd = users[0]
        token = token_list[0]
        params = {
            'user': user_name.encode('utf-8'),
            'serial': token['serial'],
            }
        response = self.make_admin_request('assign', params=params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertEqual(1, content['result']['value'])

        # Try to autoassign token[0] to users[1] -> should fail because it is
        # already assigned to users[0]
        user_name, user_pwd = users[1]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token['otps'][0],
            expected='value-false',
            )

        # molière can authenticate...
        user_name, user_pwd = users[0]
        token = token_list[0]
        # No PIN was set
        self._validate(
            user_name,
            token['otps'][1],
            )
        # ... and shakespeare can't
        user_name, user_pwd = users[1]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token['otps'][2],
            expected='value-false',
            )

        self.delete_policy('my_autoassign_policy')

    def test_only_autoassign_with_no_other_token(self):
        """
        A user can only autoassign himself a token if he has no token.
        """
        self._create_autoassignment_policy('my_autoassign_policy', 'mydefrealm')
        # Only two token required for this test
        token_list = self.token_list[0:2]

        # Put all token in the same realm
        self._set_token_realm(token_list, 'mydefrealm')

        # (user, password) pairs from myDefRealm
        users = [
            (u'molière', u'molière'),
        ]

        # Assign token[0] to users[0]
        user_name, user_pwd = users[0]
        token = token_list[0]
        params = {
            'user': user_name.encode('utf-8'),
            'serial': token['serial'],
        }
        response = self.make_admin_request('assign', params=params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertEqual(1, content['result']['value'])

        # Try to autoassign token[1] to users[0] -> should fail because the
        # user already has a token
        user_name, user_pwd = users[0]
        token = token_list[1]
        self._validate(
            user_name,
            user_pwd + token['otps'][0],
            expected='value-false',
            )

        # molière can only authenticate with token_list[0] ...
        user_name, user_pwd = users[0]
        token = token_list[0]
        # No PIN was set
        self._validate(
            user_name,
            token['otps'][1],
            )
        # ... not token_list[1]
        user_name, user_pwd = users[0]
        token = token_list[1]
        self._validate(
            user_name,
            user_pwd + token['otps'][2],
            expected='value-false',
            )

        self.delete_policy('my_autoassign_policy')

    def test_no_policy_no_autoassign(self):
        """
        Without the autoassign policy autoassignment does not work.
        """
        # Only one token required for this test
        token_list = self.token_list[0:1]

        # (user, password) pairs from myDefRealm
        users = [
            (u'molière', u'molière'),
        ]

        self._set_token_realm(token_list, 'mydefrealm')

        user_name, user_pwd = users[0]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token['otps'][0],
            expected='value-false',
            )

    def test_policy_int_action(self):
        """
        If autoassigment=<int> the policy will work.

        This is due to backwards compatibility because once upon a time that
        value was used to determine the token length of the token. In order not
        to break older system on upgrade we still support this syntax. The
        'value' of the <int> is ignored (unless it is -1, see
        test_policy_negative_action).
        """
        # Only one token required for this test
        token_list = self.token_list[0:1]

        # (user, password) pairs from myDefRealm
        users = [
            (u'molière', u'molière'),
        ]

        # Policy with <int> action
        params = {
            'name': 'int_autoassignment',
            'scope': 'enrollment',
            'action': 'autoassignment=99',
            'user': '*',
            'realm': 'mydefrealm',
        }
        self.create_policy(params)

        self._set_token_realm(token_list, 'mydefrealm')

        user_name, user_pwd = users[0]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token['otps'][0],
            )

        self.delete_policy('int_autoassignment')

    def test_policy_negative_action(self):
        """
        If autoassigment=-1 the policy will not be active.

        This is due to backwards compatibility.
        """
        # Only one token required for this test
        token_list = self.token_list[0:1]

        # (user, password) pairs from myDefRealm
        users = [
            (u'molière', u'molière'),
        ]

        # Policy with action -1
        params = {
            'name': 'negative_autoassignment',
            'scope': 'enrollment',
            'action': 'autoassignment=-1',
            'user': '*',
            'realm': 'mydefrealm',
        }
        self.create_policy(params)

        self._set_token_realm(token_list, 'mydefrealm')

        user_name, user_pwd = users[0]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token['otps'][0],
            expected='value-false',
            )

        self.delete_policy('negative_autoassignment')

    @unittest2.skip(
        "Currently broken because the counter for all matching token is "
        "increased even if autoassignment fails. See issue #13134."
        )
    def test_duplicate_otp(self):
        """
        If the OTP value matches for several token autoassignment fails
        """
        token_list = self.token_list[0:1]
        # Enroll new token with duplicate first OTP
        token = {
            'key': '0f51c51a55a3c2736ecd0c022913d541b25734b5',
            'type': 'hmac',
            'serial': None,
            'otplen': 6,
            'otps': ['755224', '657344', '672823'],
            }
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
        token_list.append(token)

        # (user, password) pairs from myDefRealm
        users = [
            (u'molière', u'molière'),
            (u'shakespeare', u'shakespeare1'),
        ]

        self._create_autoassignment_policy('my_autoassign_policy', 'mydefrealm')
        self._set_token_realm(token_list, 'mydefrealm')

        # autoassign token_list[0] to users[0] -> should fail because the OTP
        # value is valid for several token and therefore it can't be
        # determined which one to use
        user_name, user_pwd = users[0]
        token = token_list[0]
        self._validate(
            user_name,
            user_pwd + token['otps'][0],
            expected='value-false',
            )

        # This only happens if several unassigned token have a common OTP
        # value. To verify this we assign one of the token, then the other
        # one can be assigned with autoassigment.

        # Assign token_list[0] to users[0]
        user_name, user_pwd = users[0]
        token = token_list[0]
        params = {
            'user': user_name.encode('utf-8'),
            'serial': token['serial'],
        }
        response = self.make_admin_request('assign', params=params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertEqual(1, content['result']['value'])
        # No PIN was set
        self._validate(
            user_name,
            token['otps'][0],
            )

        # autoassign token_list[1] to users[1]
        user_name, user_pwd = users[1]
        token = token_list[1]
        self._validate(
            user_name,
            user_pwd + token['otps'][0],
            )

        # Cleanup
        # Delete token
        token = token_list[1]
        params = {
            'serial': token['serial'],
        }
        response = self.make_admin_request('remove', params=params)
        content = TestController.get_json_body(response)
        self.assertTrue(content['result']['status'])
        self.assertEqual(1, content['result']['value'])

        self.delete_policy('my_autoassign_policy')


    # -------- Private helper methods --------

    def _enroll_token(self, token_list):
        """
        Enroll all token in token_list. Update the list with the serial number
        returned by LinOTP.
        """
        for token in token_list:
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

    def _delete_token(self, token_list):
        """
        Delete all token in token_list
        """
        for token in token_list:
            self.assertIsNotNone(token['serial'])
            params = {
                'serial': token['serial'],
            }
            response = self.make_admin_request('remove', params=params)
            content = TestController.get_json_body(response)
            self.assertTrue(content['result']['status'])
            self.assertEqual(1, content['result']['value'])

    def _set_token_realm(self, token_list, realm_name):
        """
        Set the token realm 'realm_name' for all token in 'token_list'.
        """
        for token in token_list:
            self.assertIsNotNone(token['serial'])
            params = {
                'serial': token['serial'],
                'realms': realm_name
            }
            response = self.make_admin_request('tokenrealm', params=params)
            content = TestController.get_json_body(response)
            self.assertTrue(content['result']['status'])
            self.assertEqual(1, content['result']['value'])

    def _create_autoassignment_policy(self, name, realm):
        """
        Create an autoassignment policy with name 'name' for realm 'realm'.
        """
        params = {
            'name': name,
            'scope': 'enrollment',
            'action': 'autoassignment',
            'user': '*',
            'realm': realm,
        }
        self.create_policy(params)

    def _validate(self, user, pwd, expected='success', err_msg=None):
        """
        Makes a validate/check requests and verifies the response is as 'expected'
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
        response = self.make_validate_request('check', params=params)
        content = TestController.get_json_body(response)
        if not err_msg:
            err_msg = "validate/check failed for %r. Response: %r" % (user, content)
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

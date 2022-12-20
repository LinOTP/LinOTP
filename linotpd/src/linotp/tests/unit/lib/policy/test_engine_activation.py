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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

""" unit test for the engine activation """

import unittest
import copy

from mock import patch

from linotp.lib.policy.processing import _getAuthorization
from linotp.lib.policy.processing import has_client_policy
from linotp.lib.policy.processing import get_client_policy
from linotp.lib.policy.processing import getPolicy
from linotp.lib.policy.processing import search_policy
from linotp.lib.user import User


class TestEngineActivation(unittest.TestCase):
    """
    unit tests for the new policy engine vs the old policy engine
    """

    @patch('linotp.lib.policy.processing.LOG.error')
    @patch('linotp.lib.policy.processing.legacy_getAuthorization')
    @patch('linotp.lib.policy.processing.new_getAuthorization')
    @patch('linotp.lib.policy.processing.context')
    def test__getAuthorization(self,
                               mock_context,
                               mocked_new_getAuthorization,
                               mocked_legacy_getAuthorization,
                               mocked_LOG_error):

        """
        test the _getAuthorization
        """

        scope = 'system'
        action = 'write'

        # ----------------------------------------------------------------- --

        # switch to the new one

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'True',
                            'NewPolicyEvaluation.compare': 'False'}

        mocked_new_getAuthorization.return_value = {'active': False,
                                                    'admin': 'admin',
                                                    'auth': True, }

        # run the call

        _return_value = _getAuthorization(scope=scope, action=action)

        # check the calling

        mocked_new_getAuthorization.assert_called_once_with(scope, action)
        mocked_legacy_getAuthorization.assert_not_called()

        mocked_new_getAuthorization.reset_mock()
        mocked_legacy_getAuthorization.reset_mock()

        # ----------------------------------------------------------------- --

        # switch to the old one

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'False'}

        mocked_new_getAuthorization.return_value = {'active': False,
                                                    'admin': 'admin',
                                                    'auth': True}

        mocked_legacy_getAuthorization.return_value = {'active': False,
                                                       'admin': 'admin',
                                                       'auth': True}

        # run the call

        _return_value = _getAuthorization(scope=scope, action=action)

        # check the calling

        mocked_new_getAuthorization.assert_not_called()
        mocked_legacy_getAuthorization.assert_called_once_with(scope,
                                                               action)

        mocked_new_getAuthorization.reset_mock()
        mocked_legacy_getAuthorization.reset_mock()
        mocked_LOG_error.reset_mock()

        # ----------------------------------------------------------------- --

        # switch to old one and compare

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'True'}

        mocked_new_getAuthorization.return_value = {'active': False,
                                                    'admin': 'admin',
                                                    'auth': True}

        mocked_legacy_getAuthorization.return_value = {'active': False,
                                                       'admin': 'admin',
                                                       'auth': True}

        # run the call

        _return_value = _getAuthorization(scope=scope, action=action)

        # check the calling

        mocked_new_getAuthorization.assert_called_once_with(scope, action)
        mocked_legacy_getAuthorization.assert_called_once_with(scope,
                                                               action)

        mocked_LOG_error.assert_not_called()

        mocked_new_getAuthorization.reset_mock()
        mocked_legacy_getAuthorization.reset_mock()
        mocked_LOG_error.reset_mock()
        # ----------------------------------------------------------------- --

        # switch to old one and compare - with error

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'True'}

        new_pols = {'active': False,
                    'admin': 'admin',
                    'auth': True}
        mocked_new_getAuthorization.return_value = new_pols

        old_pols = {'active': False,
                    'admin': 'nimda',
                    'auth': True,
                    'old': True}

        mocked_legacy_getAuthorization.return_value = old_pols

        # run the call

        return_value = _getAuthorization(scope=scope, action=action)

        # check the calling

        mocked_new_getAuthorization.assert_called_once_with(scope, action)
        mocked_legacy_getAuthorization.assert_called_once_with(scope,
                                                               action)

        call1 = ('PolicyEvaluation is not the same for params %r,%r',
                 scope, action)
        call2 = ('old: new %r <> %r', old_pols, new_pols)
        mocked_LOG_error.assert_any_call(*call1)
        mocked_LOG_error.assert_any_call(*call2)

        self.assertTrue('old' in return_value)

        mocked_new_getAuthorization.reset_mock()
        mocked_legacy_getAuthorization.reset_mock()
        mocked_LOG_error.reset_mock()

        return

    @patch('linotp.lib.policy.processing.LOG.error')
    @patch('linotp.lib.policy.processing.legacy_get_client_policy')
    @patch('linotp.lib.policy.processing.new_has_client_policy')
    @patch('linotp.lib.policy.processing.context')
    def test_has_client_policy(
                                    self,
                                    mock_context,
                                    mocked_new_has_client_policy,
                                    mocked_legacy_get_client_policy,
                                    mocked_LOG_error):

        """
        test for 'has_client_policy'
        """
        scope = 'enrollment'
        action = 'otp_pin_random'

        largs = [None]

        kwargs = {
            'action': action,
            'scope': scope,
            'realm': 'mydefrealm',
            'user': '',
            'find_resolver': True,
            'userObj': User(login='', realm='mydefrealm')}

        ret_policy = {'self_02': {
                        'realm': 'myotherrealm',
                        'name': 'self_02',
                        'active': 'True',
                        'client': '*',
                        'user': '*',
                        'time': '*',
                        'action': ('enrollMOTP, disable, resync, setOTPPIN,'
                                   ' setMOTPPIN'),
                        'scope': 'selfservice'}}

        # ----------------------------------------------------------------- --

        # switch to the new one

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'True',
                            'NewPolicyEvaluation.compare': 'False'}

        mocked_new_has_client_policy.return_value = ret_policy

        # run the call

        _return_value = has_client_policy(*largs, **kwargs)

        new_kwargs = {'active_only': True}
        new_kwargs.update(kwargs)
        mocked_new_has_client_policy.assert_called_once_with(*largs,
                                                             **new_kwargs)
        mocked_legacy_get_client_policy.assert_not_called()

        mocked_new_has_client_policy.reset_mock()
        mocked_legacy_get_client_policy.reset_mock()

        # ----------------------------------------------------------------- --

        # switch to the old one

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'False'}

        mocked_new_has_client_policy.return_value = ret_policy

        mocked_legacy_get_client_policy.return_value = ret_policy

        # run the call

        _return_value = has_client_policy(*largs, **kwargs)

        mocked_new_has_client_policy.assert_not_called()
        mocked_legacy_get_client_policy.assert_called_once_with(
                                                        *largs, **kwargs)

        mocked_new_has_client_policy.reset_mock()
        mocked_legacy_get_client_policy.reset_mock()
        mocked_LOG_error.reset_mock()

        # ----------------------------------------------------------------- --

        # switch to old one and compare

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'True'}

        mocked_new_has_client_policy.return_value = ret_policy
        mocked_legacy_get_client_policy.return_value = ret_policy

        # run the call

        _return_value = has_client_policy(*largs, **kwargs)

        # check the call

        mocked_new_has_client_policy.assert_called_once_with(*largs,
                                                             **new_kwargs)
        mocked_legacy_get_client_policy.assert_called_once_with(
                                                            *largs, **kwargs)

        mocked_LOG_error.assert_not_called()

        mocked_new_has_client_policy.reset_mock()
        mocked_legacy_get_client_policy.reset_mock()
        mocked_LOG_error.reset_mock()
        # ----------------------------------------------------------------- --

        # switch to old one and compare - with error

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'True'}

        new_pols = ret_policy
        mocked_new_has_client_policy.return_value = new_pols

        old_pols = copy.deepcopy(ret_policy)
        old_pols['old'] = {'oldy': True}

        mocked_legacy_get_client_policy.return_value = old_pols

        # run the call

        return_value = has_client_policy(*largs, **kwargs)

        # check the calling

        mocked_new_has_client_policy.assert_called_once_with(*largs,
                                                             **new_kwargs)
        mocked_legacy_get_client_policy.assert_called_once_with(*largs,
                                                                **kwargs)

        call = ('old: new %r <> %r', old_pols, new_pols)
        mocked_LOG_error.assert_any_call(*call)

        self.assertTrue('old' in return_value)

        mocked_new_has_client_policy.reset_mock()
        mocked_legacy_get_client_policy.reset_mock()
        mocked_LOG_error.reset_mock()

        return

    @patch('linotp.lib.policy.processing.LOG.error')
    @patch('linotp.lib.policy.processing.legacy_get_client_policy')
    @patch('linotp.lib.policy.processing.new_get_client_policy')
    @patch('linotp.lib.policy.processing.context')
    def test_get_client_policy(
                                    self,
                                    mock_context,
                                    mocked_new_get_client_policy,
                                    mocked_legacy_get_client_policy,
                                    mocked_LOG_error):

        """
        test for 'get_client_policy'
        """
        scope = 'enrollment'
        action = 'otp_pin_random'

        largs = [None]

        legacy_kwargs = {
            'action': action,
            'scope': scope,
            'realm': 'mydefrealm',
            'user': '',
            'find_resolver': True,
            'userObj': User(login='', realm='mydefrealm')}

        kwargs = {}
        kwargs.update(legacy_kwargs)
        kwargs['active_only'] = True

        ret_policy = {'self_02': {
                        'realm': 'myotherrealm',
                        'name': 'self_02',
                        'active': 'True',
                        'client': '*',
                        'user': '*',
                        'time': '*',
                        'action': ('enrollMOTP, disable, resync, setOTPPIN,'
                                   ' setMOTPPIN'),
                        'scope': 'selfservice'}}

        # ----------------------------------------------------------------- --

        # switch to the new one

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'True',
                            'NewPolicyEvaluation.compare': 'False'}

        mocked_new_get_client_policy.return_value = ret_policy

        # run the call

        _return_value = get_client_policy(*largs, **kwargs)

        mocked_new_get_client_policy.assert_called_once_with(*largs, **kwargs)
        mocked_legacy_get_client_policy.assert_not_called()

        mocked_new_get_client_policy.reset_mock()
        mocked_legacy_get_client_policy.reset_mock()

        # ----------------------------------------------------------------- --

        # switch to the old one

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'False'}

        mocked_new_get_client_policy.return_value = ret_policy

        mocked_legacy_get_client_policy.return_value = ret_policy

        # run the call

        _return_value = get_client_policy(*largs, **kwargs)

        mocked_new_get_client_policy.assert_not_called()
        mocked_legacy_get_client_policy.assert_called_once_with(
                                                        *largs, 
                                                        **legacy_kwargs)

        mocked_new_get_client_policy.reset_mock()
        mocked_legacy_get_client_policy.reset_mock()
        mocked_LOG_error.reset_mock()

        # ----------------------------------------------------------------- --

        # switch to old one and compare

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'True'}

        mocked_new_get_client_policy.return_value = ret_policy
        mocked_legacy_get_client_policy.return_value = ret_policy

        # run the call

        _return_value = get_client_policy(*largs, **kwargs)

        # check the call

        mocked_new_get_client_policy.assert_called_once_with(*largs, **kwargs)
        mocked_legacy_get_client_policy.assert_called_once_with(
                                                            *largs,
                                                            **legacy_kwargs)

        mocked_LOG_error.assert_not_called()

        mocked_new_get_client_policy.reset_mock()
        mocked_legacy_get_client_policy.reset_mock()
        mocked_LOG_error.reset_mock()
        # ----------------------------------------------------------------- --

        # switch to old one and compare - with error

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'True'}

        new_pols = ret_policy
        mocked_new_get_client_policy.return_value = new_pols

        old_pols = copy.deepcopy(ret_policy)
        old_pols['old'] = {'oldy': True}

        mocked_legacy_get_client_policy.return_value = old_pols

        # run the call

        return_value = get_client_policy(*largs, **kwargs)

        # check the calling

        mocked_new_get_client_policy.assert_called_once_with(*largs, **kwargs)
        mocked_legacy_get_client_policy.assert_called_once_with(
                                                            *largs,
                                                            **legacy_kwargs)

        call = ('old: new %r <> %r', old_pols, new_pols)
        mocked_LOG_error.assert_any_call(*call)

        self.assertTrue('old' in return_value)

        mocked_new_get_client_policy.reset_mock()
        mocked_legacy_get_client_policy.reset_mock()
        mocked_LOG_error.reset_mock()

        return

    @patch('linotp.lib.policy.processing.LOG.error')
    @patch('linotp.lib.policy.processing.legacy_getPolicy')
    @patch('linotp.lib.policy.processing.new_getPolicy')
    @patch('linotp.lib.policy.processing.context')
    def test_getPolicy(
                                    self,
                                    mock_context,
                                    mocked_new_getPolicy,
                                    mocked_legacy_getPolicy,
                                    mocked_LOG_error):

        """
        test for 'getPolicy'
        """

        largs = {'scope': 'admin'}

        kwargs = {'only_active': False}

        ret_policy = {'ManagedAll':
                      {'realm': '*',
                       'name': 'ManageAll',
                       'active': 'True',
                       'client': '*',
                       'user': 'superadmin, Administrator',
                       'time': '*',
                       'action': '*',
                       'scope': 'admin'}}
        # ----------------------------------------------------------------- --

        # switch to the new one

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'True',
                            'NewPolicyEvaluation.compare': 'False'}

        mocked_new_getPolicy.return_value = ret_policy

        # run the call

        _return_value = getPolicy(*largs, **kwargs)

        mocked_new_getPolicy.assert_called_once_with(*largs, **kwargs)
        mocked_legacy_getPolicy.assert_not_called()

        mocked_new_getPolicy.reset_mock()
        mocked_legacy_getPolicy.reset_mock()

        # ----------------------------------------------------------------- --

        # switch to the old one

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'False'}

        mocked_new_getPolicy.return_value = ret_policy

        mocked_legacy_getPolicy.return_value = ret_policy

        # run the call

        _return_value = getPolicy(*largs, **kwargs)

        mocked_new_getPolicy.assert_not_called()
        mocked_legacy_getPolicy.assert_called_once_with(
                                                        *largs, **kwargs)

        mocked_new_getPolicy.reset_mock()
        mocked_legacy_getPolicy.reset_mock()
        mocked_LOG_error.reset_mock()

        # ----------------------------------------------------------------- --

        # switch to old one and compare

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'True'}

        mocked_new_getPolicy.return_value = ret_policy
        mocked_legacy_getPolicy.return_value = ret_policy

        # run the call

        _return_value = getPolicy(*largs, **kwargs)

        # check the call

        mocked_new_getPolicy.assert_called_once_with(*largs, **kwargs)
        mocked_legacy_getPolicy.assert_called_once_with(
                                                            *largs, **kwargs)

        mocked_LOG_error.assert_not_called()

        mocked_new_getPolicy.reset_mock()
        mocked_legacy_getPolicy.reset_mock()
        mocked_LOG_error.reset_mock()
        # ----------------------------------------------------------------- --

        # switch to old one and compare - with error

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'True'}

        new_pols = ret_policy
        mocked_new_getPolicy.return_value = new_pols

        old_pols = copy.deepcopy(ret_policy)
        old_pols['old'] = {'oldy': True}

        mocked_legacy_getPolicy.return_value = old_pols

        # run the call

        return_value = getPolicy(*largs, **kwargs)

        # check the calling

        mocked_new_getPolicy.assert_called_once_with(*largs, **kwargs)
        mocked_legacy_getPolicy.assert_called_once_with(
                                                            *largs, **kwargs)

        call = ('old: new %r <> %r', old_pols, new_pols)
        mocked_LOG_error.assert_any_call(*call)

        self.assertTrue('old' in return_value)

        mocked_new_getPolicy.reset_mock()
        mocked_legacy_getPolicy.reset_mock()
        mocked_LOG_error.reset_mock()

        return

    @patch('linotp.lib.policy.processing.LOG.error')
    @patch('linotp.lib.policy.processing.legacy_getPolicy')
    @patch('linotp.lib.policy.processing.new_search_policy')
    @patch('linotp.lib.policy.processing.context')
    def test_search_policy(
                                    self,
                                    mock_context,
                                    mocked_new_search_policy,
                                    mocked_legacy_getPolicy,
                                    mocked_LOG_error):

        """
        test for 'search_policy'
        """

        largs = {'scope': 'admin'}

        kwargs = {'only_active': False}

        ret_policy = {'ManagedAll':
                      {'realm': '*',
                       'name': 'ManageAll',
                       'active': 'True',
                       'client': '*',
                       'user': 'superadmin, Administrator',
                       'time': '*',
                       'action': '*',
                       'scope': 'admin'}}
        # ----------------------------------------------------------------- --

        # switch to the new one

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'True',
                            'NewPolicyEvaluation.compare': 'False'}

        mocked_new_search_policy.return_value = ret_policy

        # run the call

        _return_value = search_policy(*largs, **kwargs)

        mocked_new_search_policy.assert_called_once_with(*largs, **kwargs)
        mocked_legacy_getPolicy.assert_not_called()

        mocked_new_search_policy.reset_mock()
        mocked_legacy_getPolicy.reset_mock()

        # ----------------------------------------------------------------- --

        # switch to the old one

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'False'}

        mocked_new_search_policy.return_value = ret_policy

        mocked_legacy_getPolicy.return_value = ret_policy

        # run the call

        _return_value = search_policy(*largs, **kwargs)

        mocked_new_search_policy.assert_not_called()
        mocked_legacy_getPolicy.assert_called_once_with(
                                                        *largs, **kwargs)

        mocked_new_search_policy.reset_mock()
        mocked_legacy_getPolicy.reset_mock()
        mocked_LOG_error.reset_mock()

        # ----------------------------------------------------------------- --

        # switch to old one and compare

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'True'}

        mocked_new_search_policy.return_value = ret_policy
        mocked_legacy_getPolicy.return_value = ret_policy

        # run the call

        _return_value = search_policy(*largs, **kwargs)

        # check the call

        mocked_new_search_policy.assert_called_once_with(*largs, **kwargs)
        mocked_legacy_getPolicy.assert_called_once_with(
                                                            *largs, **kwargs)

        mocked_LOG_error.assert_not_called()

        mocked_new_search_policy.reset_mock()
        mocked_legacy_getPolicy.reset_mock()
        mocked_LOG_error.reset_mock()
        # ----------------------------------------------------------------- --

        # switch to old one and compare - with error

        mock_context.__getitem__.return_value = {
                            'NewPolicyEvaluation': 'False',
                            'NewPolicyEvaluation.compare': 'True'}

        new_pols = ret_policy
        mocked_new_search_policy.return_value = new_pols

        old_pols = copy.deepcopy(ret_policy)
        old_pols['old'] = {'oldy': True}

        mocked_legacy_getPolicy.return_value = old_pols

        # run the call

        return_value = search_policy(*largs, **kwargs)

        # check the calling

        mocked_new_search_policy.assert_called_once_with(*largs, **kwargs)
        mocked_legacy_getPolicy.assert_called_once_with(
                                                            *largs, **kwargs)

        call = ('old: new %r <> %r', old_pols, new_pols)
        mocked_LOG_error.assert_any_call(*call)

        self.assertTrue('old' in return_value)

        mocked_new_search_policy.reset_mock()
        mocked_legacy_getPolicy.reset_mock()
        mocked_LOG_error.reset_mock()

        return

# eof #

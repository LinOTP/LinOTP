# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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

""" unit test for complex policy comparisons """

import unittest

from mock import patch

from linotp.lib.user import User
from linotp.lib.policy.legacy import _user_filter


class TestCompare(unittest.TestCase):
    """
    unit tests _user_filter
     - to filter users based on resolver specification
    """

    @patch('linotp.lib.policy.legacy.getResolversOfUser')
    def test_user_filter_negativ(self, mocked_getResolversOfUser):
        """
        test the _user_filter for filtering policies by resolver specification
        """

        Policies = {
            'set_realm_test': {
                'realm': 'mymixrealm',
                'action': 'setrealm=mydefrealm',
                'client': '*',
                'user': 'myDefRes:',
                'time': '*',
                'active': 'True',
                'scope': 'authorization'}}

        userObj = User(login='max1', realm='mymixrealm')
        userObj.resolvers_list = ['myOtherRes']

        mocked_getResolversOfUser.return_value = userObj.resolvers_list

        res = _user_filter(Policies, userObj, scope='authorization')

        self.assertTrue(res == {}, res)

        return

    @patch('linotp.lib.policy.legacy.getResolversOfUser')
    def test_user_filter_positiv(self, mocked_getResolversOfUser):
        """
        test the _user_filter for filtering policies by resolver specification
        """

        Policies = {
            'set_realm_test': {
                'realm': 'mymixrealm',
                'action': 'setrealm=mydefrealm',
                'client': '*',
                'user': 'myDefRes:',
                'time': '*',
                'active': 'True',
                'scope': 'authorization'}}

        userObj = User(login='max1', realm='mymixrealm')
        userObj.resolvers_list = ['myDefRes']

        mocked_getResolversOfUser.return_value = userObj.resolvers_list

        res = _user_filter(Policies, userObj, scope='authorization')

        self.assertTrue('set_realm_test' in res, res)

        return

# eof #

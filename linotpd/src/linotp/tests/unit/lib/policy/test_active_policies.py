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

""" unit test for complex policy comparisons """

import unittest
from copy import deepcopy

from mock import patch

from linotp.lib.user import User
from linotp.lib.policy.legacy import legacy_getPolicy

class TestShowInactivePolicies(unittest.TestCase):
    """
    unit test to show inactive policies
    """

    @patch('linotp.lib.policy.legacy.get_copy_of_policies')
    def test_show_inactive_policies(self,
                                    mocked_get_copy_of_policies):
        """
        test that legacy policy show the inactive policy
        """
        initial_policies = {
            'losttoken_valid_all': {
                'realm': '*',
                'active': 'False',
                'client': '*',
                'user': '*',
                'time': '* * * * * *;',
                'action': 'lostTokenValid=5',
                'scope': 'enrollment'},
            'losttoken_valid_hans': {
                'realm': '*',
                'active': 'True',
                'client': '*',
                'user': 'hans',
                'time': '* * * * * *;',
                'action': 'lostTokenValid=8 d 1m',
                'scope': 'enrollment'}}

        param = {}

        # ------------------------------------------------------------------ --

        # by default select only active policies

        mocked_get_copy_of_policies.return_value = deepcopy(initial_policies)

        policies = legacy_getPolicy(param)
        assert len(policies) == 1

        # select all policies - active and inactive ones

        mocked_get_copy_of_policies.return_value = deepcopy(initial_policies)

        policies = legacy_getPolicy(param, only_active=False)
        assert len(policies) == 2

        # select only active policies

        mocked_get_copy_of_policies.return_value = deepcopy(initial_policies)

        policies = legacy_getPolicy(param, only_active=True)
        assert len(policies) == 1

        return

# eof #

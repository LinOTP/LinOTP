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

""" unit test for complex policy comparisons """

import unittest

from datetime import datetime

from linotp.lib.policy.evaluate import time_list_compare
from linotp.lib.policy.evaluate import user_list_compare
from linotp.lib.policy.evaluate import ip_list_compare

from linotp.lib.user import User


class TestCompare(unittest.TestCase):
    """
    unit tests for some comparison methods
     - will be moved into the unit tests
    """

    def test_time_compare(self):
        """
        test the time comparison method
        """
        time_conditions0 = (
            # allowed all time
            '*   *    * * * *; '
            # not allowed past 17 o clock
            '-* 18-23 * * * *; '
            # not allowed before 7 o clock
            '!*  0-6  * * * *')

        time_conditions1 = (
            # allowed between 7 and 17 o clock
            # same as above but without negation
            '*  7-17  * * * *; ')

        time_conditions_set = []
        time_conditions_set.append(time_conditions0)
        time_conditions_set.append(time_conditions1)

        for time_conditions in time_conditions_set:
            # datetime args
            # datetime(year, month, day[, hour[, minute[, second[, micro ..

            self.assertTrue(
                time_list_compare(time_conditions,
                                  datetime(2016, 12, 14, 15, 30)))  # 15:30

            self.assertFalse(
                time_list_compare(time_conditions,
                                  datetime(2016, 12, 14, 18, 0)))  # 18:00

            self.assertFalse(
                time_list_compare(time_conditions,
                                  datetime(2016, 12, 14, 6, 0)))  # 6:00

        return

    def test_ip_compare(self):
        """
        test the ip comparison method
        """

        ip_conditions = (
            # all of subnet
            '192.168.0.0/16, '
            # but not this one
            '-192.168.17.15, '
            # and subnet is not allowed too
            '!192.168.16.0/24')

        self.assertFalse(
            ip_list_compare(ip_conditions, '127.0.0.1'))

        self.assertTrue(
            ip_list_compare(ip_conditions, '192.168.12.13'))

        self.assertFalse(
            ip_list_compare(ip_conditions, '192.168.17.15'))

        self.assertFalse(
            ip_list_compare(ip_conditions, '192.168.16.152'))

    def test_user_compare(self):
        """
        test the user list comparison method
        """

        user_conditions = (
            # exact name match
            'Hugo, '
            # negative test
            '!Emma, '
            # wildcard realm test
            '*@realm, '
            # wildcard name test
            'a*, '
            # negative wildcad name test
            '!*z')

        hugo = User('Hugo', 'realm')
        self.assertTrue(
            user_list_compare(user_conditions, hugo))
        emma = User('Emma')
        self.assertFalse(
            user_list_compare(user_conditions, emma))

        betonz = User('betonz', 'realm')
        self.assertFalse(
            user_list_compare(user_conditions, betonz))

        wanda = User('wanda', 'realm')
        self.assertTrue(
            user_list_compare(user_conditions, wanda))

        wanda2 = 'wanda@realm'
        self.assertTrue(
            user_list_compare(user_conditions, wanda2))

        return

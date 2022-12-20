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
from nose.tools import raises

from datetime import datetime

from linotp.lib.policy.evaluate import time_list_compare
from linotp.lib.policy.evaluate import user_list_compare
from linotp.lib.policy.evaluate import ip_list_compare
from linotp.lib.policy.evaluate import value_list_compare
from linotp.lib.policy.evaluate import wildcard_list_compare

from linotp.lib.user import User


class TestCompare(unittest.TestCase):
    """
    unit tests for some comparison methods
     - will be moved into the unit tests
    """

    def test_value_list_compare(self):
        """
        test value list comparison
        """

        value_condition = ", , ,, "
        res = value_list_compare(value_condition, "d")
        assert res == False

        value_condition = ", a , b ,,, c"
        res = value_list_compare(value_condition, "d")
        assert res == False

        value_condition = ", a , b ,,, c"
        res = value_list_compare(value_condition, "b")
        assert res == True

        value_condition = ", a , b=x ,,, c"
        res = value_list_compare(value_condition, "b")
        assert res == True

        value_condition = ", a , b=x ,,, c=x"
        res = value_list_compare(value_condition, "b=a")
        assert res == False

        value_condition = ", a , b ,,, c=x, ,"
        res = value_list_compare(value_condition, "b=a")
        assert res == False

    def test_wildcard_list_compare(self):
        """
        test wildcard list compare
        """

        value_condition = "read, write, execute, "
        res = wildcard_list_compare(value_condition, "write")
        assert res == True

        value_condition = " , ,,,,, , ,,     ,,  ,"
        res = wildcard_list_compare(value_condition, "write")
        assert res == False

        value_condition = ""
        res = wildcard_list_compare(value_condition, "write")
        assert res == False

        value_condition = "* , write"
        res = wildcard_list_compare(value_condition, "write")
        assert res == True

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
        match_type, match = user_list_compare(user_conditions, hugo)
        assert match
        assert match_type == 'exact:match'

        emma = User('Emma')
        match_type, match = user_list_compare(user_conditions, emma)
        assert not match
        assert match_type == 'not:match'

        betonz = User('betonz', 'realm')
        match_type, match = user_list_compare(user_conditions, betonz)
        assert not match
        assert match_type == 'not:match'

        wanda = User('wanda', 'realm')
        match_type, match = user_list_compare(user_conditions, wanda)
        assert match
        assert match_type == 'regex:match'

        wanda2 = 'wanda@realm'
        match_type, match = user_list_compare(user_conditions, wanda2)
        assert match
        assert match_type == 'regex:match'

        return

# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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

"""unit test for complex policy comparisons"""

import unittest
from datetime import datetime

from linotp.lib.policy.evaluate import (
    action_compare,
    ip_list_compare,
    time_list_compare,
    user_list_compare,
    value_list_compare,
    wildcard_list_compare,
)
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
        _mtype, res = value_list_compare(value_condition, "d")
        assert res is False

        value_condition = ", a , b ,,, c"
        _mtype, res = value_list_compare(value_condition, "d")
        assert res is False

        value_condition = ", a , b ,,, c"
        _mtype, res = value_list_compare(value_condition, "b")
        assert res is True

        value_condition = ", a , b=x ,,, c"
        _mtype, res = value_list_compare(value_condition, "b")
        assert res is True

        value_condition = ", a , b=x ,,, c=x"
        _mtype, res = value_list_compare(value_condition, "b=a")
        assert res is False

        value_condition = ", a , b ,,, c=x, ,"
        _mtype, res = value_list_compare(value_condition, "b=a")
        assert res is False

    def test_wildcard_list_compare(self):
        """
        test wildcard list compare
        """

        value_condition = "read, write, execute, "
        _mtype, res = wildcard_list_compare(value_condition, "write")
        assert res

        value_condition = " , ,,,,, , ,,     ,,  ,"
        _mtype, res = wildcard_list_compare(value_condition, "write")
        assert res is False

        value_condition = ""
        _mtype, res = wildcard_list_compare(value_condition, "write")
        assert res is False

        value_condition = "* , write"
        _mtype, res = wildcard_list_compare(value_condition, "write")
        assert res is True

    def test_time_compare(self):
        """
        test the time comparison method
        """
        time_conditions0 = (
            # allowed all time
            "*   *    * * * *; "
            # not allowed past 17 o clock
            "-* 18-23 * * * *; "
            # not allowed before 7 o clock
            "!*  0-6  * * * *"
        )

        time_conditions1 = (
            # allowed between 7 and 17 o clock
            # same as above but without negation
            "*  7-17  * * * *; "
        )

        time_conditions_set = []
        time_conditions_set.append(time_conditions0)
        time_conditions_set.append(time_conditions1)

        for time_conditions in time_conditions_set:
            # datetime args
            # datetime(year, month, day[, hour[, minute[, second[, micro ..

            _match_type, match = time_list_compare(
                time_conditions, datetime(2016, 12, 14, 15, 30)
            )  # 15:30
            assert match

            _match_type, match = time_list_compare(
                time_conditions, datetime(2016, 12, 14, 18, 0)
            )  # 18:00
            assert not match

            _match_type, match = time_list_compare(
                time_conditions, datetime(2016, 12, 14, 6, 0)
            )  # 6:00
            assert not match

        return

    def test_ip_compare(self):
        """
        test the ip comparison method
        """

        ip_conditions = (
            # all of subnet
            "192.168.0.0/16, "
            # but not this one
            "-192.168.17.15, "
            # and subnet is not allowed too
            "!192.168.16.0/24"
        )

        _match_type, match = ip_list_compare(ip_conditions, "127.0.0.1")
        assert not match

        _match_type, match = ip_list_compare(ip_conditions, "192.168.12.13")
        assert match

        _match_type, match = ip_list_compare(ip_conditions, "192.168.17.15")
        assert not match

        _match_type, match = ip_list_compare(ip_conditions, "192.168.16.152")
        assert not match

    def test_user_compare(self):
        """
        test the user list comparison method
        """

        user_conditions = (
            # exact name match
            "Hugo, "
            # negative test
            "!Emma, "
            # wildcard realm test
            "*@realm, "
            # wildcard name test
            "a*, "
            # negative wildcad name test
            "!*z"
        )

        hugo = User("Hugo", "realm")

        match_type, match = user_list_compare(user_conditions, hugo)
        assert match
        assert match_type == "exact:match"

        emma = User("Emma")
        match_type, match = user_list_compare(user_conditions, emma)
        assert not match
        assert match_type == "not:match"

        betonz = User("betonz", "realm")
        match_type, match = user_list_compare(user_conditions, betonz)
        assert not match
        assert match_type == "not:match"

        wanda = User("wanda", "realm")
        match_type, match = user_list_compare(user_conditions, wanda)
        assert match
        assert match_type == "regex:match"

        wanda2 = "wanda@realm"
        match_type, match = user_list_compare(user_conditions, wanda2)
        assert match
        assert match_type == "regex:match"

        return

    def test_action_compare(self):
        match_type, res = action_compare(
            'voice_message = "Sir, your otp={otp}" ,'
            " voice_language = ' Sir, your otp is {otp}' , ",
            "voice_message",
        )
        assert res
        assert match_type == "exact:match"

        match_type, res = action_compare(
            'voice_message = "Sir, your otp={otp}" ,'
            " voice_language = ' Sir, your otp is {otp}' , ",
            " your otp",
        )
        assert not res
        assert match_type == "not:match"

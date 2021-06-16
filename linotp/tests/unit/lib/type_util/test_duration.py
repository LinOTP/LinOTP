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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

"""
tests for the type utils
"""

import unittest

import pytest

from linotp.lib.type_utils import DurationParsingException, parse_duration


class DurationTestCase(unittest.TestCase):
    """
    unit test duration parsing
    """

    def test_ISO8601_duration(self):
        """test: parse ISO8601 time delta format"""

        test_vector = {
            "PT45S": 45.0,
            "PT5H10M": 18600.0,
            "P1DT12H": 129600.0,
            "P8W": 4838400.0,
            "P2YT3H10M": 63083400.0,
            "P0D": 0.0,
            "P23DT23H": 2070000.0,
            "P3Y6M4DT12H30M5S": 110550605.0,
            "PT5H": 18000.0,
            "PT36H": 129600.0,
            "P1M": 2592000.0,
            "P3D": 259200.0,
            "P7Y": 220752000.0,
            "PT0S": 0.0,
            "P5Y": 157680000.0,
            "P4Y": 126144000.0,
            "P2Y": 63072000.0,
            "P23M": 59616000.0,
            "PT10M": 600.0,
            "PT1M": 60.0,
        }
        for duration, seconds in list(test_vector.items()):

            timedelta = parse_duration(duration, time_delta_compliant=False)
            assert seconds == timedelta.total_seconds()

    def test_duration(self):
        """test: parse human time delta format"""

        test_vector = {
            "24h 3s": 86403.0,
            "1d 2h 1m": 93660.0,
        }

        for duration, seconds in list(test_vector.items()):
            timedelta = parse_duration(duration)
            assert seconds == timedelta.total_seconds()

    def test_bad_duration(self):
        """test: limits of human time delta format"""

        test_vector = {
            "24h 3m 4m 3s": 0,
            "1k 1h": 0,
        }

        for duration, _seconds in list(test_vector.items()):

            with pytest.raises(DurationParsingException):
                parse_duration(duration)

        return

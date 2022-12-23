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

"""
totp token - timeshift unit tests
"""

import binascii
import json
import logging
import unittest
from datetime import datetime, timedelta

from mock import MagicMock, patch

from linotp.tokens.totptoken import counter2time, time2counter

fake_context = {"Client": "127.0.0.1"}


TOTP_Vectors = """
+-------------+--------------+------------------+----------+--------+
+  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
+-------------+--------------+------------------+----------+--------+
|      59     |  1970-01-01  00:00:59 | 0000000000000001 | 94287082 |  SHA1  |
|      59     |  1970-01-01  00:00:59 | 0000000000000001 | 46119246 | SHA256 |
|      59     |  1970-01-01  00:00:59 | 0000000000000001 | 90693936 | SHA512 |
|  1111111109 |  2005-03-18  01:58:29 | 00000000023523EC | 07081804 |  SHA1  |
|  1111111109 |  2005-03-18  01:58:29| 00000000023523EC | 68084774 | SHA256 |
|  1111111109 |  2005-03-18  01:58:29| 00000000023523EC | 25091201 | SHA512 |
|  1111111111 |  2005-03-18  01:58:31| 00000000023523ED | 14050471 |  SHA1  |
|  1111111111 |  2005-03-18  01:58:31| 00000000023523ED | 67062674 | SHA256 |
|  1111111111 |  2005-03-18  01:58:31| 00000000023523ED | 99943326 | SHA512 |
|  1234567890 |  2009-02-13  23:31:30| 000000000273EF07 | 89005924 |  SHA1  |
|  1234567890 |  2009-02-13  23:31:30| 000000000273EF07 | 91819424 | SHA256 |
|  1234567890 |  2009-02-13  23:31:30| 000000000273EF07 | 93441116 | SHA512 |
|  2000000000 |  2033-05-18  03:33:20| 0000000003F940AA | 69279037 |  SHA1  |
|  2000000000 |  2033-05-18  03:33:20| 0000000003F940AA | 90698825 | SHA256 |
|  2000000000 |  2033-05-18  03:33:20| 0000000003F940AA | 38618901 | SHA512 |
| 20000000000 |  2603-10-11  11:33:20| 0000000027BC86AA | 65353130 |  SHA1  |
| 20000000000 |  2603-10-11  11:33:20| 0000000027BC86AA | 77737706 | SHA256 |
| 20000000000 |  2603-10-11  11:33:20| 0000000027BC86AA | 47863826 | SHA512 |
+-------------+--------------+------------------+----------+--------+
"""

unix_start_time = datetime(1970, 1, 1)


def range_tvector():
    """
    helper, to iterate through the test vectors
    """

    for line in TOTP_Vectors.split("\n"):

        # skip the comments
        if not line or line.strip().startswith("+"):
            continue

        # +  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
        (seconds, utc_time, counter_hex, totp, hash_algo) = [
            x.strip() for x in line.strip("|").split("|")
        ]

        # 1970-01-01  00:00:59
        t_time = datetime.strptime(utc_time, "%Y-%m-%d  %H:%M:%S")
        seconds = (t_time - unix_start_time).total_seconds()

        counter = int(counter_hex, 16)

        yield seconds, t_time, counter, totp, hash_algo

    return


class TotpTestCase(unittest.TestCase):
    """

    unit test for the following functions

    * time2counter( T0, timeStepping):
    * counter2time(counter, timeStepping):

    """

    def test_counter2time(self):

        for t_step in (60, 30):
            for counter in range(0, 10):

                l_seconds = timedelta(
                    seconds=(counter - 1) * t_step
                ).total_seconds()
                h_seconds = timedelta(seconds=counter * t_step).total_seconds()

                t_seconds = counter2time(counter, timeStepping=t_step)

                # we have to be in the range of seconds
                assert l_seconds <= t_seconds <= h_seconds, (
                    l_seconds,
                    t_seconds,
                    h_seconds,
                )

        return

    def test_time2counter(self):

        for t_step in (60, 30):
            for seconds in range(0, 600, t_step):

                # calculate the counter from the seconds
                counter = time2counter(seconds, timeStepping=t_step)

                # create the seconds back from counter
                v_seconds = counter * t_step

                # and check if they match
                assert seconds == v_seconds, (seconds, v_seconds)

        return

    def test_counter_time(self):

        for vector in range_tvector():

            (seconds, token_time, counter, totp, hash_algo) = vector

            t_seconds = counter2time(counter, timeStepping=30)
            t_time = unix_start_time + timedelta(seconds=t_seconds)
            ccounter = time2counter(t_seconds, timeStepping=30)

            assert ccounter == counter

        return

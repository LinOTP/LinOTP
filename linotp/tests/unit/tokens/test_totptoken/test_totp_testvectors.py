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

"""
totp token - linotp hmac compliance test
"""


import binascii
import unittest
from datetime import datetime
from hashlib import sha1, sha256, sha512

from linotp.lib.HMAC import HmacOtp as LinHmacOtp

"""
+-------------+----------------------+------------------+----------+--------+
+  Time (sec) |   UTC Time           | Value of T (hex) |   TOTP   |  Mode  |
+-------------+----------------------+------------------+----------+--------+
|      59     |  1970-01-01  00:00:59| 0000000000000001 | 94287082 |  SHA1  |
|      59     |  1970-01-01  00:00:59| 0000000000000001 | 46119246 | SHA256 |
|      59     |  1970-01-01  00:00:59| 0000000000000001 | 90693936 | SHA512 |
|  1111111109 |  2005-03-18  01:58:29| 00000000023523EC | 07081804 |  SHA1  |
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

seed = "3132333435363738393031323334353637383930"
seed32 = "3132333435363738393031323334353637383930313233343536373839303132"
seed64 = (
    "3132333435363738393031323334353637383930313233343536373839303132"
    "3334353637383930313233343536373839303132333435363738393031323334"
)

TestVectors = [
    {
        "key": seed,
        "timeStep": 30,
        "hash": sha1,
        "shash": "sha1",
        "otps": [
            (59, "94287082", "1970-01-01 00:00:59"),
            (1111111109, "07081804", "2005-03-18 01:58:29"),
            (1111111111, "14050471", "2005-03-18 01:58:31"),
            (1234567890, "89005924", "2009-02-13 23:31:30"),
            (2000000000, "69279037", "2033-05-18 03:33:20"),
            (20000000000, "65353130", "2603-10-11 11:33:20"),
        ],
    },
    {
        "key": seed32,
        "timeStep": 30,
        "hash": sha256,
        "shash": "sha256",
        "otps": [
            (59, "46119246", "1970-01-01 00:00:59"),
            (1111111109, "68084774", "2005-03-18 01:58:29"),
            (1111111111, "67062674", "2005-03-18 01:58:31"),
            (1234567890, "91819424", "2009-02-13 23:31:30"),
            (2000000000, "90698825", "2033-05-18 03:33:20"),
            (20000000000, "77737706", "2603-10-11 11:33:20"),
        ],
    },
    {
        "key": seed64,
        "timeStep": 30,
        "hash": sha512,
        "shash": "sha512",
        "otps": [
            (59, "90693936", "1970-01-01 00:00:59"),
            (1111111109, "25091201", "2005-03-18 01:58:29"),
            (1111111111, "99943326", "2005-03-18 01:58:31"),
            (1234567890, "93441116", "2009-02-13 23:31:30"),
            (2000000000, "38618901", "2033-05-18 03:33:20"),
            (20000000000, "47863826", "2603-10-11 11:33:20"),
        ],
    },
]

unix_start_time = datetime(year=1970, month=1, day=1)


class TotpTestCase(unittest.TestCase):
    """
    unit test to verify that the linotp HmacOTP class is compliant
    """

    def test_compliance(self):
        """assure that the HamcOTP class is compilant"""

        for test_vector in TestVectors:

            key = test_vector["key"]
            hash_func = test_vector["hash"]
            step = test_vector["timeStep"]
            otps = test_vector["otps"]

            for test_set in otps:

                # ---------------------------------------------------------- --

                # tupple (59, '94287082', '1970-01-01 00:00:59')

                seconds, otpvalue, timestr = test_set

                # ---------------------------------------------------------- --

                # read the time format and conert it to seconds

                time = datetime.strptime(timestr, "%Y-%m-%d %H:%M:%S")
                time_delta = time - unix_start_time

                assert seconds == time_delta.total_seconds()

                # ---------------------------------------------------------- --

                # verify the otp for the given seconds / counter

                counter = int(seconds / step)

                hmac = LinHmacOtp(digits=len(otpvalue), hashfunc=hash_func)

                lin_otp = hmac.generate(
                    counter=counter, key=binascii.unhexlify(key)
                )

                assert otpvalue == lin_otp

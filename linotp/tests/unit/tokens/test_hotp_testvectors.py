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
totp token - linotp hmac compliance test
"""


import binascii
from datetime import datetime
from hashlib import sha1, sha256, sha512

from linotp.lib.HMAC import HmacOtp

SEED = "3132333435363738393031323334353637383930"
SEED32 = "3132333435363738393031323334353637383930313233343536373839303132"
SEED64 = (
    "3132333435363738393031323334353637383930313233343536373839303132"
    "3334353637383930313233343536373839303132333435363738393031323334"
)

TEST_VECTORS = [
    {
        "params": {
            "otpkey": SEED,
            "otplen": 8,
            "hashlib": sha1,
            "oath_type": "hmac",
        },
        "otps": {
            "0000000000000001": "94287082",
            "00000000023523EC": "07081804",
            "00000000023523ED": "14050471",
            "000000000273EF07": "89005924",
            "0000000003F940AA": "69279037",
            "0000000027BC86AA": "65353130",
        },
    },
    {
        "params": {
            "otpkey": SEED32,
            "otplen": 8,
            "hashlib": sha256,
            "oath_type": "hmac",
        },
        "otps": {
            "0000000000000001": "46119246",
            "00000000023523EC": "68084774",
            "00000000023523ED": "67062674",
            "000000000273EF07": "91819424",
            "0000000003F940AA": "90698825",
            "0000000027BC86AA": "77737706",
        },
    },
    {
        "params": {
            "otpkey": SEED64,
            "otplen": 8,
            "hashlib": sha512,
            "oath_type": "hmac",
        },
        "otps": {
            "0000000000000001": "90693936",
            "00000000023523EC": "25091201",
            "00000000023523ED": "99943326",
            "000000000273EF07": "93441116",
            "0000000003F940AA": "38618901",
            "0000000027BC86AA": "47863826",
        },
    },
]


class HotpTest:
    def __init__(self, otpkey, otplen, hashlib, oath_type):
        self.otpkey = otpkey
        self.otplen = otplen
        self.hashlib = hashlib
        self.type = oath_type

    def get_otp(self, counter=None):

        hmac = HmacOtp(digits=self.otplen, hashfunc=self.hashlib)
        return hmac.generate(
            counter=counter, key=binascii.unhexlify(self.otpkey)
        )


def test_hmac_oath_otps():
    """
    Iterate through test data for different hashlibs and verify that our
    HMAC token class calculates the correct OTP values in each case.
    """

    for test_vector in TEST_VECTORS:

        params = test_vector["params"]
        hotp_test = HotpTest(**params)

        otps = test_vector["otps"]

        for counter, otp in otps.items():
            ret_otp = hotp_test.get_otp(int(counter, 16))
            assert ret_otp == otp

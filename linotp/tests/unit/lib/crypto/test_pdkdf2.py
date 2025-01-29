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
""" """

import binascii
import unittest
from hashlib import sha1

from linotp.lib.crypto.pbkdf2 import pbkdf2


class TestComparePDKDF(unittest.TestCase):
    """
    verify that the replacement call of the pdkdf2 function is rfc copliant
    """

    def test_vectors(self):
        """
        test the pbkdf2 function agains the rfc test vectors

        from https://www.ietf.org/rfc/rfc6070.txt
        """

        testvectors = [
            {
                "P": "password",  # (8 octets)
                "S": "salt",  # (4 octets)
                "c": 1,
                "dkLen": 20,
                "DK": (
                    "0c"
                    "60"
                    "c8"
                    "0f"
                    "96"
                    "1f"
                    "0e"
                    "71"  # (20 octets)
                    "f3"
                    "a9"
                    "b5"
                    "24"
                    "af"
                    "60"
                    "12"
                    "06"
                    "2f"
                    "e0"
                    "37"
                    "a6"
                ),
            },
            {
                "P": "password",  # (8 octets)
                "S": "salt",  # (4 octets)
                "c": 2,
                "dkLen": 20,
                "DK": (
                    "ea"
                    "6c"
                    "01"
                    "4d"
                    "c7"
                    "2d"
                    "6f"
                    "8c"  # (20 octets)
                    "cd"
                    "1e"
                    "d9"
                    "2a"
                    "ce"
                    "1d"
                    "41"
                    "f0"
                    "d8"
                    "de"
                    "89"
                    "57"
                ),
            },
            {
                "P": "password",  # (8 octets)
                "S": "salt",  # (4 octets)
                "c": 4096,
                "dkLen": 20,
                "DK": (
                    "4b"
                    "00"
                    "79"
                    "01"
                    "b7"
                    "65"
                    "48"
                    "9a"  # (20 octets)
                    "be"
                    "ad"
                    "49"
                    "d9"
                    "26"
                    "f7"
                    "21"
                    "d0"
                    "65"
                    "a4"
                    "29"
                    "c1"
                ),
            },
            #             { # this is a long running test and as we test
            #               # against a std lib, this might not be required
            #             "P": "password", # (8 octets)
            #             "S": "salt", # (4 octets)
            #             "c": 16777216,
            #             "dkLen": 20,
            #             "DK": ( "ee" "fe" "3d" "61" "cd" "4d" "a4" "e4" # (20 octets)
            #                     "e9" "94" "5b" "3d" "6b" "a2" "15" "8c"
            #                     "26" "34" "e9" "84")},
            {
                "P": "passwordPASSWORDpassword",  # (24 octets)
                "S": "saltSALTsaltSALTsaltSALTsaltSALTsalt",  # (36 octets)
                "c": 4096,
                "dkLen": 25,
                "DK": (
                    "3d"
                    "2e"
                    "ec"
                    "4f"
                    "e4"
                    "1c"
                    "84"
                    "9b"  # (25 octets)
                    "80"
                    "c8"
                    "d8"
                    "36"
                    "62"
                    "c0"
                    "e4"
                    "4a"
                    "8b"
                    "29"
                    "1a"
                    "96"
                    "4c"
                    "f2"
                    "f0"
                    "70"
                    "38"
                ),
            },
            {
                "P": "pass\0word",  # (9 octets)
                "S": "sa\0lt",  # (5 octets)
                "c": 4096,
                "dkLen": 16,
                "DK": (
                    "56"
                    "fa"
                    "6a"
                    "a7"
                    "55"
                    "48"
                    "09"
                    "9d"  # (16 octets)
                    "cc"
                    "37"
                    "d7"
                    "f0"
                    "34"
                    "25"
                    "e0"
                    "c3"
                ),
            },
        ]

        hashfunc = sha1

        for testvector in testvectors:
            password = testvector["P"]
            salt = testvector["S"]
            iterations = testvector["c"]
            dk_length = testvector["dkLen"]
            expected_result = testvector["DK"].encode("utf-8")

            rawhash1 = pbkdf2(password, salt, dk_length, iterations, hashfunc)
            assert expected_result == binascii.hexlify(rawhash1)

        return


# eof #

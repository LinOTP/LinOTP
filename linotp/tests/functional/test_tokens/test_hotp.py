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


"""verify gettoken/getmultiotp support for different hash methods"""

import binascii
from hashlib import sha1, sha256, sha512

from linotp.lib.HMAC import HmacOtp
from linotp.tests import TestController

HASH_LOOKUP = {"sha1": sha1, "sha256": sha256, "sha512": sha512}

"""
  +-------------+--------------+------------------+----------+--------+
  |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
  +-------------+--------------+------------------+----------+--------+
  |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
  |             |   00:00:59   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
  |             |   01:58:29   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
  |             |   01:58:31   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
  |             |   23:31:30   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
  |             |   03:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
  |             |   11:33:20   |                  |          |        |

  |      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
  |             |   00:00:59   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
  |             |   01:58:29   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
  |             |   01:58:31   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
  |             |   23:31:30   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
  |             |   03:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
  |             |   11:33:20   |                  |          |        |

  |      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
  |             |   00:00:59   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
  |             |   01:58:29   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
  |             |   01:58:31   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
  |             |   23:31:30   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
  |             |   03:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |
  |             |   11:33:20   |                  |          |        |
  +-------------+--------------+------------------+----------+--------+



"""
SEED = "3132333435363738393031323334353637383930"
SEED32 = "3132333435363738393031323334353637383930313233343536373839303132"
SEED64 = (
    "313233343536373839303132333435363738393031323334353637383930313233"
    "34353637383930313233343536373839303132333435363738393031323334"
)

TEST_VECTORS = [
    {
        "params": {
            "otpkey": SEED,
            "otplen": 8,
            "hashlib": "sha1",
            "oath_type": "hmac",
            "serial": "HOTPsha1",
        },
        "test": {
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
            "hashlib": "sha256",
            "oath_type": "hmac",
            "serial": "HOTPsha256",
        },
        "test": {
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
            "hashlib": "sha512",
            "oath_type": "hmac",
            "serial": "HOTPsha512",
        },
        "test": {
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
    """
    helper class for testing hmac otps with given set of parameters
    """

    def __init__(
        self,
        otpkey: bytes,
        otplen: int,
        hashlib: str,
        oath_type: str,
        serial: str,
    ):
        self.otpkey = otpkey
        self.otplen = otplen
        self.hashlib = HASH_LOOKUP[hashlib]
        self.type = oath_type
        self.serial = serial

    def get_otp(self, counter: int) -> str:
        """
        calculate the otp from a given counter

        :param counter: a given counter
        :return: the otp string
        """
        hmac = HmacOtp(digits=self.otplen, hashfunc=self.hashlib)
        return hmac.generate(counter=counter, key=binascii.unhexlify(self.otpkey))


class TestHotpController(TestController):
    """
    Controller class for testing requests related to the HOTP token type
    """

    def setUp(self):
        """test setup - we require an default realm with an user"""

        TestController.setUp(self)

        self.create_common_resolvers()
        self.create_common_realms()

    def test_hmac_seed_with_seperator(self):
        """
        test support for seperators in otpkey
        """

        test_vector = TEST_VECTORS[0]

        test_params = test_vector["params"]
        hotp_test = HotpTest(**test_params)

        # ------------------------------------------------------------------ --

        # create params for token enrollment

        params = {}
        params.update(test_params)

        # ------------------------------------------------------------------ --

        # create mixed string with '-', ' ' and chars of seed

        params["otpkey"] = " -".join(params["otpkey"])

        assert "-" in params["otpkey"]

        # ------------------------------------------------------------------ --

        params["pin"] = "123"
        params["user"] = "passthru_user1@myDefRealm"

        response = self.make_admin_request("init", params=params)
        assert '"status": true' in response

        for counter in range(1, 3):
            calc_otp = hotp_test.get_otp(counter=counter)

            params = {
                "user": "passthru_user1@myDefRealm",
                "pass": "123" + calc_otp,
            }
            response = self.make_validate_request("check", params=params)
            assert "false" not in response

    def test_gettoken_otps(self):
        """
        Iterate through test data for different hashlibs and verify that our
        HMAC token class generates a valid OTP within a window of 5 OTPS,
        retrieved via gettoken (e.g. in the manage UI).
        """

        # ----------------------------------------------------------------- --

        # first enable the get otp functionality  at all

        params = {"linotpGetotp.active": True}
        response = self.make_system_request("setConfig", params=params)
        assert "false" not in response

        # ----------------------------------------------------------------- --

        # allow the admin to query getotp

        params = {
            "name": "admin_getotp",
            "scope": "admin",
            "active": True,
            "action": "getotp, *",
            "user": "*",
            "realm": "*",
        }
        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response.body

        # ----------------------------------------------------------------- --

        # define how many otps could be retreived

        params = {
            "name": "gettokenmaxcount",
            "scope": "gettoken",
            "active": True,
            "action": "max_count_hotp=5,max_count_totp=5,",
            "user": "*",
            "realm": "mydefrealm",
        }
        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response.body

        # ----------------------------------------------------------------- --

        # finally we check every token with its own hash lib by getting the
        # list of otps and verify these otp with the one calculated by the
        # unit-test-verified hotp.get_otp() method

        for test_vector in TEST_VECTORS:
            test_params = test_vector["params"]
            hotp_test = HotpTest(**test_params)

            # create params for token enrollment

            params = {}
            params.update(test_params)

            params["user"] = "passthru_user1@myDefRealm"
            response = self.make_admin_request("init", params=params)
            assert '"status": true' in response

            getmultiotp_params = {"serial": params["serial"], "count": 5}
            response = self.make_gettoken_request(
                "getmultiotp", params=getmultiotp_params
            )

            assert "false" not in response

            for counter, otp in response.json["result"]["value"]["otp"].items():
                calc_otp = hotp_test.get_otp(counter=int(counter))
                assert otp == calc_otp


# eof

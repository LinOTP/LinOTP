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


""""""

import binascii
import json
from datetime import datetime, timedelta
from hashlib import sha1

from freezegun import freeze_time

from linotp.lib.HMAC import HmacOtp
from linotp.tests import TestController

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
seed = "3132333435363738393031323334353637383930"
seed32 = "3132333435363738393031323334353637383930313233343536373839303132"
seed64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"

unix_start_time = datetime(year=1970, month=1, day=1)


def time2counter(t_time, t_step=60):
    t_delta = (t_time - unix_start_time).total_seconds()
    counts = t_delta / t_step
    import math

    return math.floor(counts)


def get_otp(key, counter=None, digits=8):
    hmac = HmacOtp(digits=digits, hashfunc=sha1)
    return hmac.generate(counter=counter, key=binascii.unhexlify(key))


class TestTotpController(TestController):
    """"""

    def test_get_otp_is_correct(self):
        t_counter = time2counter(
            t_time=unix_start_time + timedelta(seconds=59), t_step=30
        )

        otp = get_otp(key=seed, counter=t_counter)

        assert otp == "94287082"

        utc_time = "2005-03-18  01:58:29"  # 1111111109
        t1_time = datetime.strptime(utc_time, "%Y-%m-%d  %H:%M:%S")

        t_counter = time2counter(t1_time, t_step=30)
        otp = get_otp(key=seed, counter=t_counter)

        assert otp == "07081804"

        utc_time = "2005-03-18  01:58:31"  # 111111111
        t2_time = datetime.strptime(utc_time, "%Y-%m-%d  %H:%M:%S")

        t_counter = time2counter(t2_time, t_step=30)
        otp = get_otp(key=seed, counter=t_counter)

        assert otp == "14050471"

        return

    def test_time_shift(self):
        param = {
            "pin": "pin",
            "serial": "TOTP",
            "type": "totp",
            "otplen": 8,
            "otpkey": seed,
            "timeStep": 30,
        }

        response = self.make_admin_request("init", params=param)
        assert '"status": true,' in response

        utc_time = "2005-03-18  01:58:29"  # 1111111109
        t_time = datetime.strptime(utc_time, "%Y-%m-%d  %H:%M:%S")

        with freeze_time(t_time):
            # -------------------------------------------------------------

            # first verify that an otp corresponding to the freeze time
            # will be matching

            t_count = time2counter(t_time, t_step=30)
            otp = get_otp(key=seed, counter=t_count)

            assert otp == "07081804"

            params = {"serial": "TOTP", "pass": "pin" + otp}

            response = self.make_validate_request("check_s", params=params)
            assert "false" not in response.body

            # -------------------------------------------------------------

            # verify that the next test vector is correct as well

            utc_time = "2005-03-18  01:58:31"  # 1111111111
            t_time = datetime.strptime(utc_time, "%Y-%m-%d  %H:%M:%S")

            t_count = time2counter(t_time, t_step=30)
            otp = get_otp(key=seed, counter=t_count)

            assert otp == "14050471"

            params = {"serial": "TOTP", "pass": "pin" + otp}

            response = self.make_validate_request("check_s", params=params)
            assert "false" not in response.body

            response = self.make_admin_request("show", params=params)
            jresp = json.loads(response.body)

            tokens = jresp.get("result", {}).get("value", {}).get("data", [])
            assert len(tokens) == 1
            t_info = json.loads(tokens[0].get("LinOtp.TokenInfo"))

            assert t_info["timeShift"] == 30.0, response.body

            # -------------------------------------------------------------

            # now we request an otp with an time shift of +90 sec
            # wrt freeze time

            t_count = time2counter(t_time + timedelta(seconds=90), t_step=30)
            otp = get_otp(key=seed, counter=t_count)

            params = {"serial": "TOTP", "pass": "pin" + otp}

            response = self.make_validate_request("check_s", params=params)
            assert '"value": true' in response, response

            params = {"serial": "TOTP"}

            response = self.make_admin_request("show", params=params)
            jresp = json.loads(response.body)

            tokens = jresp.get("result", {}).get("value", {}).get("data", [])
            assert len(tokens) == 1
            t_info = json.loads(tokens[0].get("LinOtp.TokenInfo"))

            assert t_info["timeShift"] == 120.0, response.body

        # -------------------------------------------------------
        # now move ahead in time to see if shift decrements

        t_time = t_time + timedelta(seconds=300)
        with freeze_time(t_time):
            t_count = time2counter(t_time + timedelta(seconds=12), t_step=30)
            otp = get_otp(key=seed, counter=t_count)

            params = {"serial": "TOTP", "pass": "pin" + otp}

            response = self.make_validate_request("check_s", params=params)
            assert '"value": true' in response, response

            params = {"serial": "TOTP"}

            response = self.make_admin_request("show", params=params)
            jresp = json.loads(response.body)

            tokens = jresp.get("result", {}).get("value", {}).get("data", [])
            assert len(tokens) == 1
            t_info = json.loads(tokens[0].get("LinOtp.TokenInfo"))

            assert t_info["timeShift"] == 0.0, response.body

            t_count = time2counter(t_time + timedelta(seconds=32), t_step=30)
            otp = get_otp(key=seed, counter=t_count)

            params = {"serial": "TOTP", "pass": "pin" + otp}

            response = self.make_validate_request("check_s", params=params)
            assert '"value": true' in response, response

            params = {"serial": "TOTP"}

            response = self.make_admin_request("show", params=params)
            jresp = json.loads(response.body)

            tokens = jresp.get("result", {}).get("value", {}).get("data", [])
            assert len(tokens) == 1
            t_info = json.loads(tokens[0].get("LinOtp.TokenInfo"))

            assert t_info["timeShift"] == 30.0, response.body

        return

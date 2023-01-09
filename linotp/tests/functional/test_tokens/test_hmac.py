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


"""Test for HMAC tokens with changing otp len and timeShift."""

import binascii
from datetime import datetime, timedelta
from hashlib import sha1

from freezegun import freeze_time

from linotp.lib.HMAC import HmacOtp
from linotp.tests import TestController

seed = "3132333435363738393031323334353637383930"

unix_start_time = datetime(year=1970, month=1, day=1)


def time2counter(t_time, t_step=60):
    t_delta = (t_time - unix_start_time).total_seconds()
    counts = t_delta / t_step
    import math

    return math.floor(counts)


def get_otp(key, counter=None, digits=8, hashfunc=sha1):

    hmac = HmacOtp(digits=digits, hashfunc=hashfunc)
    return hmac.generate(counter=counter, key=binascii.unhexlify(key))


class TestHmacTokenController(TestController):
    def test_change_otplen_4_hotp(self):
        """Verify that changing the otp len of a hmac token works.

        1. enroll hmac token and verify the next otp
        2. call admin/set to change the otp len and verify the next otp
        """

        serial = "hmac_one"
        pin = "123!"

        params = {
            "type": "hmac",
            "otplen": "6",
            "otpkey": seed,
            "hashlib": "sha1",
            "serial": serial,
            "pin": pin,
        }

        response = self.make_admin_request("init", params=params)
        assert "false" not in response

        otp = get_otp(key=seed, counter=1, digits=6, hashfunc=sha1)

        params = {"serial": serial, "pass": pin + otp}
        response = self.make_validate_request("check_s", params=params)
        assert "false" not in response

        # ----------------------------------------------------------------- --

        # now change the otp len for the hmac token and verify that it still
        # works

        params = {
            "serial": serial,
            "OtpLen": "8",
        }
        response = self.make_admin_request("set", params)
        assert "false" not in response

        otp = get_otp(key=seed, counter=2, digits=8, hashfunc=sha1)

        params = {"serial": serial, "pass": pin + otp}
        response = self.make_validate_request("check_s", params=params)
        assert "false" not in response

    def test_change_otplen_4_totp(self):
        """Verify that changing the otp len of a totp token works.

        1. enroll totp token and verify the next otp
        2. call admin/set to change the otp len and verify the next otp
        """

        serial = "totp_one"
        pin = "123!"

        params = {
            "type": "totp",
            "otplen": "6",
            "otpkey": seed,
            "hashlib": "sha1",
            "serial": serial,
            "pin": pin,
        }

        response = self.make_admin_request("init", params=params)
        assert "false" not in response

        t_now = datetime.utcnow()

        t_time = t_now - timedelta(minutes=2)
        with freeze_time(t_time):

            counter = time2counter(t_time, t_step=30)
            otp = get_otp(key=seed, counter=counter, digits=6, hashfunc=sha1)

            params = {"serial": serial, "pass": pin + otp}
            response = self.make_validate_request("check_s", params=params)
            assert "false" not in response

        # ----------------------------------------------------------------- --

        # now change the otp len for the hmac token and verify that it
        # still works

        params = {
            "serial": serial,
            "OtpLen": "8",
        }
        response = self.make_admin_request("set", params)
        assert "false" not in response

        t_time = t_now
        with freeze_time(t_time):

            counter = time2counter(t_time, t_step=30)
            otp = get_otp(key=seed, counter=counter, digits=8, hashfunc=sha1)

            params = {"serial": serial, "pass": pin + otp}
            response = self.make_validate_request("check_s", params=params)
            assert "false" not in response

    def test_change_timestep_4_totp(self):
        """Verify that changing the timestep of a totp token works.

        1. enroll totp token and verify the next otp
        2. call admin/set to change the timestep and
        3. verify the next otp with timeStep difference ahead
        """

        params = {"totp.timeStep": "60"}
        response = self.make_system_request("setConfig", params=params)
        assert "false" not in response

        serial = "totp_two"
        pin = "123!"

        timeStep = "30"

        params = {
            "type": "totp",
            "otplen": "6",
            "timeStep": timeStep,
            "otpkey": seed,
            "hashlib": "sha1",
            "serial": serial,
            "pin": pin,
        }

        response = self.make_admin_request("init", params=params)
        assert "false" not in response

        t_now = datetime.utcnow()
        t_time = t_now - timedelta(minutes=2)
        with freeze_time(t_time):

            counter = time2counter(t_time, t_step=int(timeStep))
            otp = get_otp(key=seed, counter=counter, digits=6, hashfunc=sha1)

            params = {"serial": serial, "pass": pin + otp}
            response = self.make_validate_request("check_s", params=params)
            assert "false" not in response

        # ----------------------------------------------------------------- --

        # now change the timeStep for the totp token
        # - it did't work as the last otp count rememberd was in 30 sec steps
        #   and jumping over this in seconds since 1970 * 2 which is far ahead

        timeStep = "60"

        params = {
            "serial": serial,
            "timeStep": timeStep,
        }
        response = self.make_admin_request("set", params)
        assert "false" not in response

        t_time = t_now
        with freeze_time(t_time):

            counter = time2counter(t_time, t_step=int(timeStep))
            otp = get_otp(key=seed, counter=counter, digits=6, hashfunc=sha1)

            params = {"serial": serial, "pass": pin + otp}
            response = self.make_validate_request("check_s", params=params)
            assert "false" not in response

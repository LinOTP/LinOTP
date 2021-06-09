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


""" """
import json
import binascii
import datetime
from hashlib import sha1, sha256, sha512
import hmac
import random
import struct
import time

from freezegun import freeze_time

from linotp.lib.crypto.utils import geturandom
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
seed64 = (
    "3132333435363738393031323334353637383930313233343536373839303132"
    "3334353637383930313233343536373839303132333435363738393031323334"
)

testvector = [
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


class HmacOtp:
    def __init__(self, key: bytes, counter=0, digits=6, hashfunc=sha1):
        self.key = key
        self.counter = counter
        self.digits = digits
        self.hashfunc = hashfunc

    def hmac(self, key=None, counter=None):
        key = key or self.key
        counter = counter or self.counter
        digest = hmac.new(key, struct.pack(">Q", counter), self.hashfunc)
        return digest.digest()

    def truncate(self, digest: bytes) -> bytes:
        offset = digest[-1] & 0x0F

        binary = (digest[offset + 0] & 0x7F) << 24
        binary |= (digest[offset + 1] & 0xFF) << 16
        binary |= (digest[offset + 2] & 0xFF) << 8
        binary |= digest[offset + 3] & 0xFF

        return binary % (10 ** self.digits)

    def generate(self, key=None, counter=None):
        key = key or self.key
        counter = counter or self.counter
        otp = str(self.truncate(self.hmac(key, counter)))
        sotp = (self.digits - len(otp)) * "0" + otp
        return sotp


class TotpToken(object):
    def __init__(
        self,
        key=None,
        keylen=20,
        algo=None,
        digits=6,
        offset=0,
        jitter=0,
        timestep=60,
    ):

        # no key given - create one

        if key is None:
            self.key = binascii.hexlify(geturandom(keylen))
        else:
            self.key = bytes.fromhex(key)
            keylen = len(self.key)

        if algo is None:
            if keylen == 20:
                algo = sha1
            elif keylen == 32:
                algo = sha256
            elif keylen == 64:
                algo = sha512

        self.offset = offset
        self.jitter = jitter
        self.timestep = timestep
        self.digits = digits

        self.hmacOtp = HmacOtp(self.key, digits=self.digits, hashfunc=algo)

        return

    def getOtp(self, counter: int = -1, offset=0, jitter=0, seconds=None):
        """
        @note: we require the ability to set the counter directly
            to validate the hmac token against the defined test vectors
        """
        if counter == -1:
            if self.jitter != 0 or jitter != 0:
                jitter = random.uniform(-self.jitter, self.jitter)
            else:
                jitter = 0

            offset = self.offset + offset
            T0 = time.time() + offset + jitter
            counter = int(T0 // self.timestep)
        else:
            counter = int(counter // self.timestep)
        if seconds:
            counter = int(seconds // self.timestep)

        otp = self.hmacOtp.generate(counter=counter)

        return (otp, counter)

    def getKey(self) -> bytes:
        return self.key

    def getTimeStep(self):
        return self.timestep

    def getTimeFromCounter(self, counter):
        idate = int(counter - 0.5) * self.timestep
        ddate = datetime.datetime.utcfromtimestamp(idate / 1.0)
        return ddate


unix_start_time = datetime.datetime(year=1970, month=1, day=1)


def time2seconds(t_time, seconds=0):
    t_delta = datetime.timedelta(seconds=seconds)
    return int((t_time - unix_start_time + t_delta).total_seconds())


class TestTotpController(TestController):
    """"""

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()
        self.serials = []

    def tearDown(self):
        self.removeTokens()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def removeTokens(self):
        for serial in self.serials:
            self.delToken(serial)

    def delToken(self, serial):
        p = {"serial": serial}
        response = self.make_admin_request("remove", params=p)
        return response

    def get_token_info(self, serial):
        params = {"serial": serial}

        response = self.make_admin_request("show", params=params)
        jresp = json.loads(response.body)
        t_info = json.loads(
            jresp["result"]["value"]["data"][0]["LinOtp.TokenInfo"]
        )

        return t_info

    def time2float(self, curTime):
        """
        time2float - convert a datetime object or an datetime sting into a float

        http://bugs.python.org/issue12750
        """
        dt = datetime.datetime.now()
        if isinstance(curTime, datetime.datetime):
            dt = curTime
        elif isinstance(curTime, str):
            if "." in curTime:
                tFormat = "%Y-%m-%d %H:%M:%S.%f"
            else:
                tFormat = "%Y-%m-%d %H:%M:%S"
            try:
                dt = datetime.datetime.strptime(curTime, tFormat)
            except Exception as e:
                raise Exception(e)
        else:
            raise Exception(
                "[time2float] invalid curTime: %s. You need"
                " to specify a datetime.datetime" % type(curTime)
            )

        td = dt - datetime.datetime(1970, 1, 1)
        tCounter = (
            td.microseconds * 1.0
            + (td.seconds + td.days * 24 * 3600) * 10 ** 6
        ) / 10.0 ** 6

        return tCounter

    def addToken(
        self,
        user,
        pin=None,
        serial=None,
        typ=None,
        key=None,
        timeStep=60,
        timeShift=0,
        hashlib="sha1",
        otplen=8,
    ):

        if serial is None:
            serial = "s" + user

        if pin is None:
            pin = user

        if typ is None:
            typ = "totp"

        param = {
            "user": user,
            "pin": pin,
            "serial": serial,
            "type": typ,
            "timeStep": timeStep,
            "otplen": otplen,
            "hashlib": hashlib,
        }

        if key is not None:
            param["otpkey"] = key

        response = self.make_admin_request("init", params=param)
        assert '"status": true,' in response

        return serial

    def createTOTPToken(self, serial, token_seed):
        """
        creates the test tokens
        """
        parameters = {
            "serial": serial,
            "type": "TOTP",
            # 64 byte key
            "otpkey": token_seed,
            "otppin": "1234",
            "pin": "pin",
            "otplen": 8,
            "description": "TOTP testtoken",
        }

        response = self.make_admin_request("init", params=parameters)
        assert '"value": true' in response

    def getTokenInfo(self, serial):
        param = {"serial": serial}
        response = self.make_admin_request("show", params=param)
        assert '"status": true,' in response
        return json.loads(response.body)

    def checkOtp(self, user, otp, pin=None):
        if pin is None:
            pin = user

        param = {"user": user, "pass": pin + otp}
        response = self.make_validate_request("check", params=param)
        assert '"status": true,' in response

        return response

    def test_algo(self):
        """
        totp test: verify that the local totp algorith is correct - test against testvector spec
        """
        for tokData in testvector:
            key = tokData.get("key")
            algo = tokData.get("hash")
            step = tokData.get("timeStep")

            t1 = TotpToken(key, digits=8, algo=algo, timestep=step)
            otps = tokData.get("otps")
            for o in otps:
                counter = o[0]
                otp = o[1]

                (rotp, _count) = t1.getOtp(counter=counter)
                if otp != rotp:
                    (rotp, _count) = t1.getOtp(counter=counter)
                    assert otp == rotp

    def test_increment_timeshift(self):
        """
        totp test: increments the time offset and verify the timeshift increases
        """
        tokData = testvector[0]
        user = "root"

        key = tokData.get("key")
        algo = tokData.get("hash")
        salgo = tokData.get("shash")
        step = tokData.get("timeStep")

        t1 = TotpToken(key, digits=8, algo=algo, timestep=step)
        step = t1.getTimeStep()

        tserial = self.addToken(
            user=user, typ="totp", key=key, timeStep=step, hashlib=salgo
        )
        self.serials.append(tserial)

        otpSet = set()

        # Freeze time to the current system time
        with freeze_time(datetime.datetime.now()) as frozen_datetime:
            for i in range(1, 5):
                offset = i * step
                (otp, _counter) = t1.getOtp(offset=offset)

                res = self.checkOtp(user, otp)

                if otp not in otpSet:
                    assert '"value": true' in res.body
                    resInfo = self.getTokenInfo(tserial)
                    tInfo = json.loads(
                        resInfo.get("result")
                        .get("value")
                        .get("data")[0]
                        .get("LinOtp.TokenInfo")
                    )
                    tShift = tInfo.get("timeShift")
                    assert int(tShift) <= offset + step
                    assert int(tShift) >= offset - step
                else:
                    assert '"value": false' in res.body

                otpSet.add(otp)

                # Jump to the future
                frozen_datetime.tick(
                    delta=datetime.timedelta(seconds=step / 2)
                )

    def test_decrement_timeshift(self):
        """
        totp test: decrements the time offset and verify the timeshift decreases
        """
        tokData = testvector[0]
        user = "root"

        key = tokData.get("key")
        algo = tokData.get("hash")
        salgo = tokData.get("shash")
        step = tokData.get("timeStep")

        t1 = TotpToken(key, digits=8, algo=algo, timestep=step)
        step = t1.getTimeStep()

        tserial = self.addToken(
            user=user, typ="totp", key=key, timeStep=step, hashlib=salgo
        )
        self.serials.append(tserial)

        otpSet = set()

        # Freeze time to the current system time
        with freeze_time(datetime.datetime.now()) as frozen_time:
            for i in range(1):
                offset = i * step * -1
                (otp, _counter) = t1.getOtp(offset=offset)

                res = self.checkOtp(user, otp)

                if otp not in otpSet:
                    if '"value": true' not in res.body:
                        assert '"value": true' in res.body
                    resInfo = self.getTokenInfo(tserial)
                    tInfo = json.loads(
                        resInfo.get("result")
                        .get("value")
                        .get("data")[0]
                        .get("LinOtp.TokenInfo")
                    )
                    tShift = tInfo.get("timeShift")
                    lower_upper_step = tShift <= offset + step
                    greater_lower_step = tShift >= offset - step
                    assert greater_lower_step and lower_upper_step
                else:
                    assert '"value": false' in res.body

                otpSet.add(otp)

                # Jump to the future
                frozen_time.tick(delta=datetime.timedelta(seconds=step))

    def test_autoync_restart(self):
        """
        totp test: verify that auto resync will could be restarted

        * setup auto sync
        * enroll a token and verify that it is working
        * skip ahead out of the validation window (300 sec)
        * trigger an auto sync
        * leave the autosync and skip ahead again
        * try to initate the autosync again
        * verify with a second otp that the otp was successfull
        (* verify that the timeshift reflects the new sync time)
        """

        timeWindow = 300
        step = 30
        user = "root"

        # ------------------------------------------------------------------ --

        # enable auto sync

        params = {"AutoResync": True}

        response = self.make_system_request("setConfig", params=params)
        assert "false" not in response.body

        # ------------------------------------------------------------------ --

        # Freeze time to the current system time

        start_time = datetime.datetime.utcnow()

        with freeze_time(start_time) as _frozen_time:

            # -------------------------------------------------------------- --

            # enroll the token with seed and local
            # TotpToken class to calculate the otps

            t1 = TotpToken(timestep=step)
            key = t1.getKey().hex()

            tserial = self.addToken(
                user=user, otplen=t1.digits, typ="totp", key=key, timeStep=step
            )

            self.serials.append(tserial)

            # -------------------------------------------------------------- --

            # verify that the token is working

            start_seconds = time2seconds(start_time)
            (otp, _) = t1.getOtp(seconds=start_seconds)

            res = self.checkOtp(user, otp)
            assert '"value": true' in res.body

            # -------------------------------------------------------------- --

            # advance to the future: aut of the check window (300 sec)
            # so that we enter the autosync

            autosync_start = time2seconds(
                start_time, seconds=timeWindow + step
            )
            (next_otp, _) = t1.getOtp(seconds=autosync_start)

            res = self.checkOtp(user, next_otp)
            assert '"value": false' in res.body

            # verify that the autosync was started
            # with the otp1c in the token info

            t_info = self.get_token_info(serial=tserial)
            assert "otp1c" in t_info

            # -------------------------------------------------------------- --

            # now we step ahead to a new auto sync start by shifting beyond the
            # resyncDiffLimit (3)

            seconds10 = autosync_start + 10 * step
            (otp10, _c10) = t1.getOtp(seconds=seconds10)

            # the auto sync is pending but we try to start a new one

            res = self.checkOtp(user, otp10)
            assert '"value": false' in res.body

            # verify that the autosync was started with the otp1c
            t_info = self.get_token_info(serial=tserial)
            assert "otp1c" in t_info

            # verify that the auto sync start has been adjusted to the new start
            assert t_info["otp1c"] == int(seconds10 / step)

            # second step of the auto sync

            seconds11 = autosync_start + 11 * step
            (otp11, _c11) = t1.getOtp(seconds=seconds11)

            res = self.checkOtp(user, otp11)
            assert '"value": true' in res.body

            # verfy that otp1c in token info is gone on a successfull auto sync
            t_info = self.get_token_info(serial=tserial)
            assert "otp1c" not in t_info

            # verify that the time shift was calculated correctly
            assert int(t_info["timeShift"]) == (seconds11 - start_seconds)

    def test_use_consecutive(self):
        """
        totp test: test if we can use consecutive OTPs without errors
        """

        user = "root"
        step = 30

        # Freeze time to the current system time
        with freeze_time(datetime.datetime.now()) as frozen_time:
            t1 = TotpToken(timestep=step)
            key = t1.getKey().hex()
            step = t1.getTimeStep()

            tserial = self.addToken(
                user=user, otplen=t1.digits, typ="totp", key=key, timeStep=step
            )

            self.serials.append(tserial)

            (otp, counter) = t1.getOtp()
            res = self.checkOtp(user, otp)
            assert '"value": true' in res.body

            for _i in range(10):
                frozen_time.tick(delta=datetime.timedelta(seconds=step))
                (otp, new_counter) = t1.getOtp()
                assert new_counter - 1 == counter
                assert '"value": true' in res.body
                counter = new_counter

    def test_use_token_twice(self):
        """
        totp test: test if an otp could be used twice
        """
        user = "root"
        step = 30

        # Freeze time to the current system time
        with freeze_time(datetime.datetime.now()) as frozen_time:
            t1 = TotpToken(timestep=step)
            key = t1.getKey().hex()
            step = t1.getTimeStep()

            tserial = self.addToken(
                user=user, otplen=t1.digits, typ="totp", key=key, timeStep=step
            )

            self.serials.append(tserial)

            (otp, _counter) = t1.getOtp()

            res = self.checkOtp(user, otp)
            assert '"value": true' in res.body

            # reusing the otp again will fail

            res = self.checkOtp(user, otp)
            assert '"value": false' in res.body

            # Jump to the future
            frozen_time.tick(delta=datetime.timedelta(seconds=step))

            # -------------------------------------------------------------- --

            # after a while, we could do a check again

            (otp, _counter) = t1.getOtp()

            res = self.checkOtp(user, otp)
            assert '"value": true' in res.body

    def test_resync_no_replay(self):
        """
        totp test: verify that auto resync does not succeed with reused (sync) OTPs

        We will use the same OTP twice. Once for starting the sync
        and then to complete it. Both of those should not yield a
        valid authentication. The user must provide two consecutive
        OTPs to finish the sync. The second OTP must be within a
        small timeframe after the first.
        """
        user = "root"
        step = 30

        params = {"AutoResyncTimeout": "240", "AutoResync": True}

        response = self.make_system_request("setConfig", params=params)
        assert "false" not in response.body

        for offset in range(10 * step, 20 * step, step // 2):
            # Freeze time to the current system time
            with freeze_time(datetime.datetime.now()) as frozen_time:
                t1 = TotpToken(timestep=step)
                key = t1.getKey().hex()
                step = t1.getTimeStep()

                tserial = self.addToken(
                    user=user,
                    otplen=t1.digits,
                    typ="totp",
                    key=key,
                    timeStep=step,
                )

                self.serials.append(tserial)

                (otp, counter) = t1.getOtp()
                _tt1 = t1.getTimeFromCounter(counter)

                res = self.checkOtp(user, otp)
                assert '"value": true' in res.body

                # replay doesn't work
                res = self.checkOtp(user, otp)
                assert '"value": false' in res.body

                # advance to a future time where the old otp is no longer valid
                frozen_time.tick(delta=datetime.timedelta(seconds=offset))

                # start resync
                res = self.checkOtp(user, otp)
                assert '"value": false' in res.body, "%s: %s" % (
                    offset,
                    res.body,
                )

                # finish resync
                res = self.checkOtp(user, otp)
                assert '"value": true' not in res.body, offset

    def test_resync_non_consecutive(self):
        """
        totp test: verify that auto resync does not succeed with non-consecutive OTPs
        """
        user = "root"
        timeWindow = 180
        params = {"AutoResyncTimeout": "240", "AutoResync": True}

        response = self.make_system_request("setConfig", params=params)
        assert "false" not in response.body

        # Freeze time to the current system time
        with freeze_time(datetime.datetime.now()) as frozen_time:
            t1 = TotpToken()
            key = t1.getKey().hex()
            step = t1.getTimeStep()

            tserial = self.addToken(
                user=user, otplen=t1.digits, typ="totp", key=key, timeStep=step
            )

            self.serials.append(tserial)

            (otp, counter) = t1.getOtp()

            res = self.checkOtp(user, otp)
            assert '"value": true' in res.body

            # advance to a future time where the old otp is no longer valid
            frozen_time.tick(delta=datetime.timedelta(seconds=timeWindow))
            res = self.checkOtp(user, otp)
            assert '"value": false' in res.body

            # skip enough OTPs to leave the current window
            counter += 2 * timeWindow

            # get the first token
            (first_otp, _) = t1.getOtp(counter=counter)
            # get the second token
            (second_otp, counter) = t1.getOtp(counter=counter + step)

            # start resync with 2nd otp
            res = self.checkOtp(user, second_otp)
            assert '"value": false' in res.body

            # provide the first OTP for the resync, it should fail
            res = self.checkOtp(user, first_otp)
            assert '"value": true' not in res.body

    def test_resync_consecutive(self):
        """
        totp test: verify that auto resync does succeed with consecutive OTPs and fails if they are outside of the range
        """
        user = "root"
        timeWindow = 180
        syncTimeout = 240
        step = 30
        params = {"AutoResyncTimeout": "%s" % syncTimeout, "AutoResync": True}

        response = self.make_system_request("setConfig", params=params)
        assert "false" not in response.body

        for offset in range(1, 5):
            # Freeze time to the current system time
            with freeze_time(datetime.datetime.now()) as frozen_time:
                t1 = TotpToken(timestep=step)
                key = t1.getKey().hex()

                tserial = self.addToken(
                    user=user,
                    otplen=t1.digits,
                    typ="totp",
                    key=key,
                    timeStep=step,
                )

                self.serials.append(tserial)

                (otp, counter) = t1.getOtp()
                res = self.checkOtp(user, otp)
                assert '"value": true' in res.body

                # advance to a future time where the old otp is no longer valid
                frozen_time.tick(delta=datetime.timedelta(seconds=timeWindow))
                res = self.checkOtp(user, otp)
                assert '"value": false' in res.body

                counter_advance = 40 * timeWindow

                # skip enough OTPs to leave the current window
                counter = (counter * step) + counter_advance

                # get the first token
                (first_otp, first_counter) = t1.getOtp(counter=counter)

                # get the second token that is offset by a few but within range
                (second_otp, second_counter) = t1.getOtp(
                    counter=counter + step * offset
                )

                info = (
                    "First OTP: %s (%s), Second OTP: %s (%s)",
                    first_otp,
                    first_counter,
                    second_otp,
                    second_counter,
                )

                # start resync with a valid OTP
                res = self.checkOtp(user, first_otp)
                assert '"value": false' in res.body, info

                # provide the second otp that follows the previous one
                res = self.checkOtp(user, second_otp)

                if offset <= 3:
                    # as long as the OTP is not out of the sync range
                    # it should be good
                    assert '"value": true' in res.body, offset
                else:
                    # if we are out of the sync range the OTP should
                    # be rejected
                    assert '"value": false' in res.body, offset

    def test_getotp(self):
        """
        totp test: test the getotp - verify that in the list of getotp is the correct start otp of our test vector
        """

        parameters = {
            "name": "getmultitoken",
            "scope": "gettoken",
            "realm": "mydefrealm",
            "action": "max_count_dpw=10, max_count_hotp=10, max_count_totp=10",
            "user": "admin",
        }
        response = self.make_system_request("setPolicy", params=parameters)

        time_format = "%Y-%m-%d %H:%M:%S"

        for tokData in testvector:
            tkey = tokData.get("key")
            salgo = tokData.get("shash")
            step = tokData.get("timeStep")

            tserial = self.addToken(
                user="root", typ="totp", key=tkey, timeStep=step, hashlib=salgo
            )

            self.serials.append(tserial)

            otps = tokData.get("otps")
            for o in otps:
                tCounter = o[0]
                counter = int(((tCounter) / step))
                otp = o[1]
                curTime = o[2]

                current_time = datetime.datetime.strptime(curTime, time_format)
                with freeze_time(current_time):

                    parameters = {
                        "serial": tserial,
                        "count": "20",
                    }
                    response = self.make_gettoken_request(
                        "getmultiotp", params=parameters
                    )

                    resp = json.loads(response.body)

                    otpres = resp.get("result").get("value").get("otp")
                    otp1 = otpres.get(str(counter))
                    assert otp1.get("otpval") == otp, response

                    # verify: the first otp matches the unix start time + timeslice

                    if "1" in otpres:
                        otp_one = otpres.get("1")
                        uTime = otp_one.get("time")
                        assert uTime == "1970-01-01 00:00:30"

            self.removeTokens()

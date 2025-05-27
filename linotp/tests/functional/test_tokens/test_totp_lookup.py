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

from linotp.lib.HMAC import HmacOtp as LinHmacOTP
from linotp.tests import TestController

seed = "3132333435363738393031323334353637383930"
unix_start_time = datetime(year=1970, month=1, day=1)


def time2seconds(timestamp):
    """
    convert a timestamp into a counter

    :param timestamp: datetime time
    :return: seconds
    """
    return int((timestamp - unix_start_time).total_seconds())


def get_otp(key, counter, digits=8, hashfunc=sha1):
    """
    calculate otp from a given counter

    :param key: the token seed in hexlified format
    :param counter: the given counter == time equivalent
    :param digits: number of digits in the otp
    :param hashfunc: the hash method used in the hmac calculation
    :return: otp value
    """
    hmac = LinHmacOTP(digits=digits, hashfunc=hashfunc)
    otp = hmac.generate(counter=counter, key=binascii.unhexlify(key))
    return otp


class TestTotpLookupController(TestController):
    """
    test for the admin/totp_lookup interface

    * verify that the otp is found
        * with time shift
        * with different window format
            * human readable
            * iso8601 time delta format
        * is not found if out of scope of the window
        * is not in the future

    * verify output format
        * token serial
        * otp value
        * otp counter
        * time: otp validity start time utc time in iso8601 format
        * time_sec seconds since epoch
        * time span: number of seconds this otp was valid (step)

    * verify that access policies are evaluated
        * granted if admin and token are in the same realm
        * denied if token is in a realm, where admin is not allowed

    """

    def setUp(self):
        ret = TestController.setUp(self)

        self.create_common_resolvers()
        self.create_common_realms()

        return ret

    def tearDown(self):
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_policies()
        self.delete_all_token()
        return TestController.tearDown(self)

    def test_verify_lookup_otp_and_response_format(self):
        """verify that the otp and the totp_lookup response is correct"""

        serial = "totp_lookup"
        step = 30

        # ------------------------------------------------------------------ --

        # create token with a well known seed

        params = {
            "serial": serial,
            "type": "totp",
            "otpkey": seed,
            "otplen": 8,
        }

        response = self.make_admin_request("init", params=params)
        assert '"value": false' not in response.body, response.body

        # ------------------------------------------------------------------ --

        # run test with multiple test times, where the first is taken from
        # the totp spec test vectors

        time_fmt = "%Y-%m-%d %H:%M:%S"

        otp_times = [
            datetime.strptime("2005-03-18 01:58:29", time_fmt),  # 1111111109
            datetime.strptime("2005-03-18 01:58:39", time_fmt),
            datetime.strptime("2005-03-18 01:58:59", time_fmt),
            datetime.strptime("2005-03-18 01:59:01", time_fmt),
            datetime.now(),
        ]

        for otp_time in otp_times:
            # we look back in time for 23 hours
            with freeze_time(otp_time + timedelta(hours=23)):
                # get a valid otp

                seconds = time2seconds(otp_time)
                counter = int(seconds / step)
                otp = get_otp(key=seed, counter=counter)

                params = {
                    "serial": serial,
                    "otp": otp,
                    "window": "24h",
                }

                response = self.make_admin_request("totp_lookup", params=params)
                assert '"value": true' in response.body, response

                # ---------------------------------------------------------- --

                # verify the response detail

                jresp = json.loads(response.body)
                detail = jresp.get("detail")

                # ---------------------------------------------------------- --

                # verify we have the same otp in the response
                assert otp == detail["otp"]

                # ---------------------------------------------------------- --

                # now verify against the returned time string
                otp_time_str = otp_time.strftime(time_fmt)

                # verify otp value from known test set
                if otp_time_str == "2005-03-18 01:58:29":
                    assert detail["otp"] == "07081804"

                # ---------------------------------------------------------- --

                # verify that the returned time is in iso8601 format
                if otp_time_str == "2005-03-18 01:58:29":
                    assert detail["time"] == "2005-03-18T01:58:00"

                # ---------------------------------------------------------- --

                # verify that the time base is the same - all but the seconds

                assert otp_time_str[:10] == detail["time"][:10]
                assert otp_time_str[-8:-2] == detail["time"][-8:-2]

                # ---------------------------------------------------------- --

                # verify that the validity span matches the time slices
                input_seconds = int(otp_time_str[-2:])  # 29 seconds

                otp_start = int(detail["time"][-2:])
                assert otp_start in (0, 30)

                otp_end = otp_start + step
                assert otp_start <= input_seconds <= otp_end

                # ---------------------------------------------------------- --

                # verify that the counter matches
                assert counter == detail["counter"]

                # ---------------------------------------------------------- --

                # verify that the returned seconds match the given time
                # with the token step offset

                start_time = otp_time.replace(second=otp_start)
                utc_seconds = time2seconds(start_time)

                assert utc_seconds == detail["seconds"]

        return

    def test_policy_bases_access(self):
        """
        verify that admin can only access the policy defined realms

        create 3 tokens with different realm settings

        token1: no realm
        token2: two realms: mymixrealm, myotherrealm
        token3: two realms: mymixrealm, mydefrealm

        now set the policy for authUser=admin so that he has only access to
        mydefrealm - thus he is allowed to query token3 but not
        token1 and token2

        """

        # ------------------------------------------------------------------ --

        # create the tokens and define the token realms

        tokens_realms = {
            "token1": None,
            "token2": "myMixRealm,myOtherRealm",
            "token3": "myMixRealm,myDefRealm",
        }

        for serial, realms in list(tokens_realms.items()):
            params = {
                "serial": serial,
                "type": "totp",
                "otpkey": seed,
                "otplen": 8,
                "hash": "sha1",
                "step": 30,
            }

            response = self.make_admin_request("init", params=params)
            assert '"value": false' not in response.body, response.body

            if realms:
                params = {
                    "serial": serial,
                    "realms": realms,
                }

                response = self.make_admin_request("tokenrealm", params)
                assert '"value": false' not in response.body, response.body

        # ------------------------------------------------------------------ --

        # define the admin policy

        params = {
            "name": "totp_lookup",
            "scope": "admin",
            "active": True,
            "action": "totp_lookup,",
            "user": "admin",
            "realm": "mydefrealm",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response.body, response.body

        # ------------------------------------------------------------------ --

        # get a valid otp of the past

        test_time = datetime.utcnow() - timedelta(hours=1)

        seconds = time2seconds(test_time)
        counter = int(seconds / 30)
        otp = get_otp(key=seed, counter=counter)

        # ------------------------------------------------------------------ --

        # verify: access to token1

        err_msg = "You do not have the administrative right"

        params = {"serial": "token1", "otp": otp}

        response = self.make_admin_request(
            "totp_lookup", params=params, auth_user="admin"
        )
        assert '"status": false' in response.body, response
        assert err_msg in response.body, response

        # verify: no access to token2

        params = {"serial": "token2", "otp": otp}

        response = self.make_admin_request(
            "totp_lookup", params=params, auth_user="admin"
        )
        assert '"status": false' in response.body, response
        assert err_msg in response.body, response

        # verify: access to token3

        params = {"serial": "token3", "otp": otp}

        response = self.make_admin_request(
            "totp_lookup", params=params, auth_user="admin"
        )
        assert '"status": true' in response.body, response
        assert '"value": true' in response.body, response

        return

    def test_verify_window(self):
        """verify that the totp_lookup window is working

        * create an otp for now
        * step into the future by 23 hours
        * lookup window backward for 5 hours fails
        * lookup window backward for one day + 5 hours: success
        """

        serial = "totp_lookup"
        step = 30

        # ------------------------------------------------------------------ --

        # create token with a well known seed

        params = {
            "serial": serial,
            "type": "totp",
            "otpkey": seed,
            "otplen": 8,
        }

        response = self.make_admin_request("init", params=params)
        assert '"value": false' not in response.body, response.body

        # ------------------------------------------------------------------ --

        # we look back in time for 23 hours

        test_time = datetime.utcnow()
        with freeze_time(test_time + timedelta(hours=23)):
            # get a valid otp

            seconds = time2seconds(test_time)
            counter = int(seconds / step)
            otp = get_otp(key=seed, counter=counter)

            # lookup for 5 hours back

            params = {
                "serial": serial,
                "otp": otp,
                "window": "PT5H",
            }

            response = self.make_admin_request("totp_lookup", params=params)
            assert '"value": false' in response.body, response

            # extend the lookup window to one day and 5 hours

            params = {
                "serial": serial,
                "otp": otp,
                "window": "P1DT5H",
            }

            response = self.make_admin_request("totp_lookup", params=params)
            assert '"value": true' in response.body, response

    def test_no_future_otp(self):
        """verify that the totp_lookup does not respond for future otps"""

        serial = "totp_lookup"
        step = 30

        # ------------------------------------------------------------------ --

        # create token with a well known seed

        params = {
            "serial": serial,
            "type": "totp",
            "otpkey": seed,
            "otplen": 8,
        }

        response = self.make_admin_request("init", params=params)
        assert '"value": false' not in response.body, response.body

        # ------------------------------------------------------------------ --

        # we are in the past, while the otp is 2 hours ahead

        otp_time = datetime.utcnow()
        with freeze_time(otp_time - timedelta(hours=2)):
            # get a valid otp

            seconds = time2seconds(otp_time)
            counter = int(seconds / step)
            otp = get_otp(key=seed, counter=counter)

            # lookup for 5 hours back

            params = {
                "serial": serial,
                "otp": otp,
                "window": "24h",
            }

            response = self.make_admin_request("totp_lookup", params=params)
            assert '"value": false' in response.body, response

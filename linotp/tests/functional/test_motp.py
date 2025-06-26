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
Test challenge response functionality for the motp token
"""

import hashlib
import time
from datetime import datetime

import freezegun

from linotp.tests import TestController


def calc_motp(key, pin, digits=6, now=None):
    """
    :param key: the otpkey secret
    :param pin: the motp pin secret
    :param digits: the number of to be returned digits
    :param now: the time (from time.time())

    :return: the otp value as string
    """

    if not now:
        now = time.time()

    counter = int(now) // 10
    input = b"%d%b%b" % (counter, key.encode("utf-8"), pin.encode("utf-8"))

    return hashlib.md5(input).hexdigest()[:digits]


class TestMOTPTokenController(TestController):
    otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"
    user = "passthru_user1"

    def setUp(self):
        """
        This sets up all the resolvers and realms
        """
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_token()

        self.delete_all_realms()
        self.delete_all_resolvers()

    def test_test_motp_token(self):
        """Test motp token.

        scope of the test is:
        - verify that the motp is correctly calculated
        - the fail counter for the motp are incremented and reset correctly
        """

        serial = "M722362"
        motpkey = "1234567890123456"
        motppin = "1234"

        pin = "pin"
        user = "root"

        parameters = {
            "serial": serial,
            "type": "motp",
            "otpkey": motpkey,
            "otppin": motppin,
            "user": user,
            "pin": pin,
            "description": "TestToken1",
        }

        response = self.make_admin_request("init", params=parameters)
        assert response.json["result"]["value"], response

        # we use a fixed date to check if the motp calc is okay

        old_day = datetime(year=2018, month=12, day=12, hour=12, minute=12)
        with freezegun.freeze_time(old_day):
            # 1. wrong motp verification

            motp = "7215e7"

            parameters = {"serial": serial}
            response = self.make_admin_request("show", params=parameters)

            token = response.json["result"]["value"]["data"][0]
            assert token["LinOtp.FailCount"] == 0, response

            parameters = {"user": user, "pass": pin + motp}
            response = self.make_validate_request("check", params=parameters)
            assert not response.json["result"]["value"], response

            parameters = {"serial": "M722362"}
            response = self.make_admin_request("show", params=parameters)

            token = response.json["result"]["value"]["data"][0]
            assert token["LinOtp.FailCount"] == 1, response

            # 2. use a correct motp for verification

            motp = calc_motp(key=motpkey, pin=motppin)

            assert motp == "488ccf"

            parameters = {"user": "root", "pass": pin + motp}
            response = self.make_validate_request("check", params=parameters)
            assert response.json["result"]["value"], response

            # 3. verify that the motp token fail counter is reset

            parameters = {"serial": serial}
            response = self.make_admin_request("show", params=parameters)

            token = response.json["result"]["value"]["data"][0]
            assert token["LinOtp.FailCount"] == 0, response

        self.delete_token(serial)

    def test_motp_token_challenge_response(self):
        """Test motp token with challenge response mode.

        0. enable the challeng_reponse mode for the motp token and
           enroll an motp token for root user
        1. triggers a challenge by providing the linotp pin
        2. extract the transaction id and
           verify the challenge with an calculated motp
        """

        # setup the test

        # 0. enable challenge response mode for motp token

        params = {
            "name": "motp_challenge_response",
            "user": "*",
            "action": "challenge_response=motp",
            "scope": "authentication",
            "realm": "*",
            "time": "",
            "client": "*",
            "active": True,
        }

        response = self.make_system_request("setPolicy", params=params)
        assert isinstance(response.json["result"]["value"], dict), response

        # 0. enroll the motp token for the root user

        serial = "M722362"
        motpkey = "1234567890123456"
        motppin = "1234"

        pin = "pin"
        user = "root"

        parameters = {
            "serial": serial,
            "type": "motp",
            "otpkey": motpkey,
            "otppin": motppin,
            "user": user,
            "pin": pin,
            "description": "TestToken1",
        }

        response = self.make_admin_request("init", params=parameters)
        assert response.json["result"]["value"], response

        # 1. start the challenge

        parameters = {"user": "root", "pass": "pin"}
        response = self.make_validate_request("check", params=parameters)

        transactionid = response.json["detail"]["transactionid"]

        # 2. use the transaction id and calculate the motp for the challenge
        # verification

        motp = calc_motp(key=motpkey, pin=motppin)

        parameters = {
            "user": "root",
            "pass": motp,
            "transactionid": transactionid,
        }
        response = self.make_validate_request("check", params=parameters)

        assert response.json["result"]["value"], response

        self.delete_token(serial)


# eof #

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


"""
Test challenge response functionality for the totp token
"""


import binascii
import datetime
import json
import time

from freezegun import freeze_time

from linotp.lib.HMAC import HmacOtp
from linotp.tests import TestController


def calc_totp_OTP(key, digits=6, timestep=30):
    """

    :param key: the otpkey secret
    :param digits: the number of to be returned digits
    :param timestep: the time stepping 60 or 30 sec

    :return: the otp value as string
    """
    htoken = HmacOtp(digits=digits)
    counter = int((time.time() / timestep) + 0.5)
    otp = htoken.generate(counter=counter, key=binascii.unhexlify(key))

    return otp


class TestChallengeResponseController(TestController):

    otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"
    user = "passthru_user1"

    def setUp(self):
        """
        This sets up all the resolvers and realms
        """
        TestController.setUp(self)

        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):

        self.delete_all_policies()
        self.delete_all_token()

        self.delete_all_realms()
        self.delete_all_resolvers()

        TestController.tearDown(self)

    def create_totp_token(
        self, serial="KITO_2714", pin="pin", description="TestToken1"
    ):

        params = {
            "serial": serial,
            "otpkey": self.otpkey,
            "user": self.user,
            "pin": pin,
            "type": "totp",
            "description": description,
            "session": self.session,
        }
        response = self.make_admin_request(action="init", params=params)
        assert '"value": true' in response, response
        return serial

    def setPolicy(
        self,
        name="otpPin",
        realm="ldap_realm",
        action="otppin=1, ",
        scope="authentication",
        active=True,
    ):

        params = {
            "name": name,
            "user": "*",
            "action": action,
            "scope": scope,
            "realm": realm,
            "time": "",
            "client": "",
            "active": active,
            "session": self.session,
        }

        response = self.make_system_request("setPolicy", params=params)
        assert '"status": true' in response, response

        response = self.make_system_request("getPolicy", params=params)
        assert '"status": true' in response, response

        return response

    def do_auth(self, pin="", otpkey=None):
        """
        run a set of different authentication schemes:
        * std auth with pin+otp
        * challenge + response w. pin+otp
        * challenge + response w. transid+otp

        :param pin: the pin, depending on otppin policy: pin/pass/empty
        :param otpkey: the key to calculate the next otp

        """
        otpkey = self.otpkey
        user = self.user

        timestep = 30

        # Freeze time to the current system time
        with freeze_time(datetime.datetime.now()) as frozen_datetime:

            # jump to next timestep
            frozen_datetime.tick(delta=datetime.timedelta(seconds=timestep))

            otp = calc_totp_OTP(otpkey)
            params = {"user": user, "pass": pin + otp}
            response = self.make_validate_request(
                action="check", params=params
            )
            assert '"value": true' in response, response

            # -------------------------------------------------------------- --

            # 2. challenge response with pin+otp
            # 2.1. create challenge

            params = {
                "user": user,
                "pass": pin,
            }
            response = self.make_validate_request(
                action="check", params=params
            )
            assert '"value": false' in response, response

            # -------------------------------------------------------------- --

            # 2.2 check with pin and otp

            # jump to next timestep
            frozen_datetime.tick(delta=datetime.timedelta(seconds=timestep))
            otp = calc_totp_OTP(otpkey)

            params = {"user": user, "pass": pin + otp}
            response = self.make_validate_request(
                action="check", params=params
            )

            assert '"value": true' in response, response

            # -------------------------------------------------------------- --

            # 3. challenge response with otp+state
            # 3.1 trigger challenge

            params = {"user": user, "pass": pin}
            response = self.make_validate_request(
                action="check", params=params
            )

            assert '"value": false' in response, response

            body = json.loads(response.body)
            state = body.get("detail").get("transactionid")

            # -------------------------------------------------------------- --

            # 3.2 check with transaction id

            # jump to next timestep
            frozen_datetime.tick(delta=datetime.timedelta(seconds=timestep))

            otp = calc_totp_OTP(otpkey)

            params = {"user": user, "pass": otp, "state": state}
            response = self.make_validate_request(
                action="check", params=params
            )

            assert '"value": true' in response, response

            # -------------------------------------------------------------- --

            # 4 std auth with user with pin+otp though outstanding challenge
            # 4.1 trigger challenge

            params = {"user": user, "pass": pin}
            response = self.make_validate_request(
                action="check", params=params
            )

            assert '"value": false' in response, response

            # -------------------------------------------------------------- --

            # 4.2 do std auth

            # jump to mext timestep
            frozen_datetime.tick(delta=datetime.timedelta(seconds=timestep))
            otp = calc_totp_OTP(otpkey)

            params = {"user": user, "pass": pin + otp}
            response = self.make_validate_request(
                action="check", params=params
            )

            assert '"value": true' in response, response

        return

    # ---------------------------------------------------------------------- --

    # running challenge response tests with 3 different pin policies

    def test_totp_auth(self):
        """
        Challenge Response Test: totp token challenge
        """
        serial = self.create_totp_token(pin="shortpin")

        # now switch policy on for challenge_response
        response = self.setPolicy(
            name="ch_resp",
            realm="myDefRealm",
            action="challenge_response=hmac totp,",
        )
        assert '"status": true,' in response, response

        self.do_auth("shortpin")

        self.delete_token(serial)
        self.delete_all_policies()

        return

    def test_totp_auth_otppin_1(self):
        """
        Challenge Response Test: totp token challenge with otppin=1
        """

        serial = self.create_totp_token(pin="shortpin")

        # now switch policy on for challenge_response
        response = self.setPolicy(
            name="ch_resp",
            realm="myDefRealm",
            action="challenge_response=hmac totp,",
        )
        assert '"status": true,' in response, response

        # with otppin==1 the pin should be the same as the password
        response = self.setPolicy(realm="myDefRealm", action="otppin=1, ")
        assert '"status": true,' in response, response

        self.do_auth("geheim1")

        self.delete_token(serial)
        self.delete_all_policies()

        return

    def test_totp_auth_otppin_2(self):
        """
        Challenge Response Test: totp token challenge with otppin=2
        """

        serial = self.create_totp_token(pin="shortpin")

        # now switch policy on for challenge_response
        response = self.setPolicy(
            name="ch_resp",
            realm="myDefRealm",
            action="challenge_response=hmac totp,",
        )
        assert '"status": true,' in response, response

        # with otppin==2 the pin should be the same as the password
        response = self.setPolicy(realm="myDefRealm", action="otppin=2, ")
        assert '"status": true,' in response, response

        self.do_auth("")

        self.delete_token(serial)
        self.delete_all_policies()

        return


# eof #

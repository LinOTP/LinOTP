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
  Test the Yubikey.
"""

import json

from linotp.tests import TestController


class TestYubikeyController(TestController):
    serials = set()

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        for serial in self.serials:
            self.delete_token(serial)
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def init_otps(self, public_uid):
        self.valid_otps = [
            public_uid + "fcniufvgvjturjgvinhebbbertjnihit",
            public_uid + "tbkfkdhnfjbjnkcbtbcckklhvgkljifu",
            public_uid + "ktvkekfgufndgbfvctgfrrkinergbtdj",
            public_uid + "jbefledlhkvjjcibvrdfcfetnjdjitrn",
            public_uid + "druecevifbfufgdegglttghghhvhjcbh",
            public_uid + "nvfnejvhkcililuvhntcrrulrfcrukll",
            public_uid + "kttkktdergcenthdredlvbkiulrkftuk",
            public_uid + "hutbgchjucnjnhlcnfijckbniegbglrt",
            public_uid + "vneienejjnedbfnjnnrfhhjudjgghckl",
            public_uid + "krgevltjnujcnuhtngjndbhbiiufbnki",
            public_uid + "kehbefcrnlfejedfdulubuldfbhdlicc",
            public_uid + "ljlhjbkejkctubnejrhuvljkvglvvlbk",
            public_uid + "eihtnehtetluntirtirrvblfkttbjuih",
        ]
        return

    def init_token(
        self,
        serialnum="01382015",
        yubi_slot=1,
        otpkey="9163508031b20d2fbb1868954e041729",
        public_uid="ecebeeejedecebeg",
        use_public_id=False,
        user=None,
        pin=None,
    ):
        serial = "UBAM%s_%s" % (serialnum, yubi_slot)

        params = {
            "type": "yubikey",
            "serial": serial,
            "otpkey": otpkey,
            "description": "Yubikey enrolled in functional tests",
            "user": "root",
        }

        if user:
            params["user"] = user

        if pin:
            params["pin"] = pin

        if not use_public_id:
            params["otplen"] = 32 + len(public_uid)
        else:
            params["public_uid"] = public_uid

        response = self.make_admin_request("init", params=params)
        assert '"value": true' in response, "Response: %r" % response

        # setup the otp values, that we check against
        self.init_otps(public_uid)

        self.serials.add(serial)
        return serial

    def test_yubico_mode(self):
        """
        Enroll and verify otp for the Yubikey in yubico (AES) mode

        test with public_uid and without public_uid

        """
        public_uids = ["ecebeeejedecebeg", ""]
        for public_uid in public_uids:
            serial = self.init_token(public_uid=public_uid)

            for otp in self.valid_otps:
                params = {"serial": serial, "pass": otp}
                response = self.make_validate_request("check_s", params=params)
                assert '"value": true' in response, "Response: %r" % response

            # Repeat an old (therefore invalid) OTP value
            invalid_otp = public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
            params = {"serial": serial, "pass": invalid_otp}
            response = self.make_validate_request("check_s", params=params)
            assert '"value": false' in response, "Response: %r" % response

        return

    def test_yubico_resync(self):
        """
        Enroll and resync the Yubikey
        """
        public_uid = "ecebeeejedecebeg"

        serial = self.init_token(public_uid=public_uid)

        otp1 = self.valid_otps[-2]
        otp2 = self.valid_otps[-1]

        params = {
            "serial": serial,
            "otp1": otp1,
            "otp2": otp2,
            "session": self.session,
        }
        response = self.make_admin_request("resync", params=params)
        assert '"value": true' in response, "Response: %r" % response

        params = {
            "serial": serial,
            "otp1": otp1,
            "otp2": otp2,
            "session": self.session,
        }
        response = self.make_admin_request("resync", params=params)
        assert '"value": false' in response, "Response: %r" % response

        return

    def test_yubico_getSerialByOtp_false(self):
        """
        getSerialByOtp - false test for yubikey token
        """

        # enroll a yubikey token
        self.init_token(public_uid="", use_public_id=True)

        # first test wrong chars in yubi otp
        false_otp1 = self.valid_otps[0].replace("i", "x")

        # test for longer otp - wrong hex()
        false_otp2 = self.valid_otps[0] + "i"

        # test for longer otp - wrong decrypt
        false_otp3 = self.valid_otps[0] + "ii"

        # test for otp - with undeclared prefix
        false_otp4 = "ecebeeejedecebeg" + self.valid_otps[0] + "ii"

        for otp in [false_otp4, false_otp3, false_otp2, false_otp1]:
            params = {
                "otp": otp,
                "session": self.session,
            }
            response = self.make_admin_request("getSerialByOtp", params=params)

            assert '"status": true' in response, "Response: %r" % response

            # now access the data / serial number
            resp = json.loads(response.body)
            data = resp.get("result", {}).get("value", {})
            get_serial = data.get("serial")
            assert get_serial == "", resp

        return

    def test_yubico_getSerialByOtp(self):
        """
        getSerialByOtp test for yubikey token w. and wo. prefix
        """

        public_uids = ["ecebeeejedecebeg", ""]

        for public_uid in public_uids:
            # preserve the serial number for later check
            serial = self.init_token(public_uid=public_uid, use_public_id=True)

            for otp in self.valid_otps:
                params = {
                    "otp": otp,
                    "session": self.session,
                }
                response = self.make_admin_request(
                    "getSerialByOtp", params=params
                )

                assert '"status": true' in response, "Response: %r" % response

                # now access the data / serial number
                resp = json.loads(response.body)
                data = resp.get("result", {}).get("value", {})
                get_serial = data.get("serial")
                assert serial == get_serial, resp

        return

    def test_yubikey_auth_otppin(self):
        """
        Yubikey with multiple tokens and otppin policies

        check if with multiple tokens the otppin policies the yubikey works
        """

        user = "passthru_user1@myDefRealm"
        orig_pin = "!1234!"

        public_uids = ["ecebeeejedecebeg", ""]

        # ------------------------------------------------------------------ --

        # create alternative yubikey with a different pin

        self.init_token(
            public_uid=public_uids[0], user=user, pin="alternative_pin"
        )

        pw_password = "very secret"
        params = {
            "user": user,
            "pin": orig_pin,
            "type": "pw",
            "otpkey": pw_password,
        }
        response = self.make_admin_request("init", params)
        assert "false" not in response, response

        # ------------------------------------------------------------------ --

        # we iterate over all otppin policies
        # 0,1,2,3 and "token_pin", "password", "only_otp", "ignore_pin"

        pp = {
            "0": orig_pin,
            "1": "geheim1",
            "2": "",
            "3": "this is not the correct pin",
            "token_pin": orig_pin,
            "password": "geheim1",
            "only_otp": "",
            "ignore_pin": "this is not the correct pin",
        }

        for otppin_mode, pin in list(pp.items()):
            # -------------------------------------------------------------- --

            # setup the otppin policy

            params = {
                "name": "otppin_policy",
                "scope": "authentication",
                "active": True,
                "action": "otppin=" + otppin_mode,
                "user": "*",
                "realm": "*",
            }
            response = self.make_system_request("setPolicy", params=params)
            assert "false" not in response, response

            # -------------------------------------------------------------- --

            # setup the token

            self.init_token(public_uid=public_uids[0], user=user, pin=orig_pin)

            # -------------------------------------------------------------- --

            # check the yubikey otp

            otp = self.valid_otps[0]
            params = {"user": user, "pass": pin + otp}
            response = self.make_validate_request("check", params=params)
            assert '"value": true' in response, otppin_mode

            # -------------------------------------------------------------- --

            # and verify that otp has been checked by check against replay

            params = {"user": user, "pass": pin + otp}
            response = self.make_validate_request("check", params=params)
            assert not ('"value": true' in response), response

            # -------------------------------------------------------------- --

            # check that the other token will work as well

            params = {"user": user, "pass": pin + pw_password}
            response = self.make_validate_request("check", params=params)
            assert '"value": true' in response, response

        return


# eof

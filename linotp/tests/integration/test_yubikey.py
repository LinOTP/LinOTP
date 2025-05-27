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

import integration_data as data
import pytest
import requests
from requests.auth import HTTPDigestAuth

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.validate import Validate


class TestYubikey:
    """
    TestCase class that tests the Yubikey (enrollment and use)
    """

    @pytest.fixture(autouse=True)
    def setUp(self, testcase):
        """
        Create a AD UserIdResolver and add it to a realm. Verify that the user
        we want to test with exists.
        """
        self.testcase = testcase
        self.realm_name = "se_yubikey_realm"
        self.user_name = "maxwell"

        self.testcase.reset_resolvers_and_realms(
            data.physics_ldap_resolver, self.realm_name
        )

        self.testcase.manage_ui.user_view.select_realm(self.realm_name)
        assert self.testcase.manage_ui.user_view.user_exists(self.user_name), (
            "User '" + self.user_name + "' should exist."
        )

    @pytest.mark.skip(
        "Since the old data center shutdown no new AD has been configured"
    )
    def test_yubico_mode(self):
        """
        Enrolls a Yubikey in YUBICO mode and verifies OTPs against it
        """
        url = self.testcase.http_host
        if self.testcase.http_port:
            url = "%s:%s" % (self.testcase.http_host, self.testcase.http_port)
        # Enroll Yubikey
        serialnum = "01382015"
        yubi_slot = 1
        serial = "UBAM%s_%s" % (serialnum, yubi_slot)
        otpkey = "9163508031b20d2fbb1868954e041729"
        yubi_otplen = 48
        description = "Enrolled by TestYubikey"
        public_uid = "ecebeeejedecebeg"

        inittoken_response = self.testcase.manage_ui.admin_api_call(
            "admin/init",
            {
                "type": "yubikey",
                "serial": serial,
                "otpkey": otpkey,
                "otplen": yubi_otplen,
                "description": description,
            },
        )
        assert inittoken_response, "Error enrolling Yubikey"

        self.testcase.manage_ui.user_view.select_user(self.user_name)
        pin = "asdf1234"
        self.testcase.manage_ui.token_view.assign_token(serial, pin)

        validate = Validate(
            self.testcase.http_protocol,
            self.testcase.http_host,
            self.testcase.http_port,
            self.testcase.http_username,
            self.testcase.http_password,
        )

        valid_otps = [
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
        ]

        for otp in valid_otps:
            access_granted, _ = validate.validate(
                user=self.user_name + "@" + self.realm_name, password=pin + otp
            )
            assert access_granted, (
                "OTP: "
                + pin
                + otp
                + " for user "
                + self.user_name
                + "@"
                + self.realm_name
                + " returned False"
            )

        # validate/check_yubikey
        password = pin + public_uid + "eihtnehtetluntirtirrvblfkttbjuih"
        cy_auth = HTTPDigestAuth(
            self.testcase.http_username, self.testcase.http_password
        )
        cy_validate_url = (
            self.testcase.http_protocol + "://" + url + "/validate/check_yubikey?"
        )
        response = requests.get(
            cy_validate_url,
            params={"pass": password},
            auth=cy_auth,
            verify=False,
        )
        assert response.status_code == 200, "Invalid response %r" % response
        return_json = response.json()
        assert return_json["result"]["status"], "Invalid return value: %r" % return_json
        assert return_json["result"]["value"], "Invalid return value: %r" % return_json
        assert return_json["detail"]["user"] == self.user_name, (
            "Invalid return value: %r" % return_json
        )
        assert return_json["detail"]["realm"] == self.realm_name, (
            "Invalid return value: %r" % return_json
        )

        # Repeat an old (therefore invalid) OTP value
        invalid_otp = public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
        access_granted, _ = validate.validate(
            user=self.user_name + "@" + self.realm_name,
            password=pin + invalid_otp,
        )
        assert not access_granted, (
            "OTP: "
            + pin
            + invalid_otp
            + " for user "
            + self.user_name
            + "@"
            + self.realm_name
            + " should be rejected."
        )

        # Repeat an old (therefore invalid) OTP value with
        # validate/check_yubikey
        invalid_otp = pin + public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
        response = requests.get(
            cy_validate_url,
            params={"pass": password},
            auth=cy_auth,
            verify=False,
        )
        assert response.status_code == 200, "Invalid response %r" % response
        return_json = response.json()
        assert return_json["result"]["status"], "Invalid return value: %r" % return_json
        assert not return_json["result"]["value"], (
            "Invalid return value: %r" % return_json
        )

        assert "user" not in return_json, (
            "Response should not contain user %r" % return_json
        )
        assert "realm" not in return_json, (
            "Response should not contain realm %r" % return_json
        )

        if "detail" in return_json:
            assert "user" not in return_json["detail"], (
                "Response should not contain detail.user %r" % return_json
            )
            assert "realm" not in return_json["detail"], (
                "Response should not contain detail.realm %r" % return_json
            )

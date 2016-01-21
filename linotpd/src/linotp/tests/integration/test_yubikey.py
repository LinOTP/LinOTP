# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#


import time

import requests
from requests.auth import HTTPDigestAuth

from linotpadminclientcli.clientutils import linotpclient
from linotp_selenium_helper import TestCase, LdapUserIdResolver, Realm
from linotp_selenium_helper.user_view import UserView
from linotp_selenium_helper.token_view import TokenView
from linotp_selenium_helper.validate import Validate


class TestYubikey(TestCase):
    """
    TestCase class that tests the Yubikey (enrollment and use)
    """

    def setUp(self):
        """
        Create a AD UserIdResolver and add it to a realm. Verify that the user we
        want to test with exists.
        """
        TestCase.setUp(self)
        self.realm_name = "se_yubikey_realm"
        self.user_name = "maxwell"

        ad_certificate = \
"""-----BEGIN CERTIFICATE-----
MIIDcjCCAtugAwIBAgIQVSU6NwMTmKNI6t3WcjY6uTANBgkqhkiG9w0BAQUFADBC
MRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFglsc2V4cGVy
dHMxDjAMBgNVBAMTBUNBMDAxMB4XDTA1MDQxMTE2NDgzOVoXDTQwMDQxMTE2NTY1
MFowQjEVMBMGCgmSJomT8ixkARkWBWxvY2FsMRkwFwYKCZImiZPyLGQBGRYJbHNl
eHBlcnRzMQ4wDAYDVQQDEwVDQTAwMTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAqlWLfYK+dExjG+Qa/jpYjSo3EQnweQ7azacosa+xsrTMfDV5wLgMBSclCTX2
i/35VRg282Bh7hKCZifOBnAxjCBIHMpHQmW9c0T/GpeWSOQ1x0KeKrZ4PRj5oHEv
/uDJ7q2HlWXgRQo6NR75yDGLpsAWk64TyQ/I4f2vlC+AtjMCAyPS46OCAWcwggFj
MBMGCSsGAQQBgjcUAgQGHgQAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBTCY8rVNcU/NGvgZxaPmO+Kz8bG4TCB/AYDVR0fBIH0MIHx
MIHuoIHroIHohoGwbGRhcDovLy9DTj1DQTAwMSxDTj1sc2V4czAxLENOPUNEUCxD
Tj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1
cmF0aW9uLERDPWxzZXhwZXJ0cyxEQz1sb2NhbD9jZXJ0aWZpY2F0ZVJldm9jYXRp
b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGM2h0
dHA6Ly9sc2V4czAxLmxzZXhwZXJ0cy5sb2NhbC9DZXJ0RW5yb2xsL0NBMDAxLmNy
bDAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQUFAAOBgQBa+RGoezCgJS5W
PFCPy9BWqZr7iRimfRGBDqHpYDCPDtgec2fKCZ+u4jfwuTisZ7UOoiM1iEvkw0hH
Z7R1pz4Yd6E074kS/fe6u7U+9L3dmSUjFvO3gkLKtHKbhQi0NA+EHMRrPsQQemLm
gYzNiYwtvAu74Q+eTC6R5Uf0hOlFig==
-----END CERTIFICATE-----"""

        # Create physics AD
        physics_ad_name = "SE_yubikey_AD"
        physics_ad_id_resolver = LdapUserIdResolver(
            physics_ad_name,
            self.driver,
            self.base_url,
            uri="ldaps://hottybotty",
            certificate=ad_certificate,
            basedn="dc=hotad,dc=example,dc=net",
            binddn=u'cn="Clark Maxwell",ou=corp,dc=hotad,dc=example,dc=net',
            password="Test123!",
            preset_ldap=False
        )
        time.sleep(1)

        # Create realm
        resolvers_realm1 = [physics_ad_id_resolver]
        realm1 = Realm(self.realm_name, resolvers_realm1)
        realm1.create(self.driver, self.base_url)
        time.sleep(1)

        user_view = UserView(self.driver, self.base_url, self.realm_name)
        self.assertTrue(user_view.user_exists(self.user_name), "User '" + self.user_name +
                                                               "' should exist.")
        time.sleep(1)

    def test_yubico_mode(self):
        """
        Enrolls a Yubikey in YUBICO mode and verifies OTPs against it
        """
        # Enroll Yubikey
        lotpc = linotpclient(self.http_protocol,
                             self.http_host,
                             admin=self.http_username,
                             adminpw=self.http_password)
        serialnum = "01382015"
        yubi_slot = 1
        serial = "UBAM%s_%s" % (serialnum, yubi_slot)
        otpkey = "9163508031b20d2fbb1868954e041729"
        yubi_otplen = 48
        description = "Enrolled by TestYubikey"
        public_uid = "ecebeeejedecebeg"
        r1 = lotpc.inittoken({'type': 'yubikey',
                              'serial': serial,
                              'otpkey': otpkey,
                              'otplen': yubi_otplen,
                              'description': description})
        self.assertTrue(r1['result']['status'], "Error enrolling Yubikey")
        self.assertTrue(r1['result']['value'], "Error enrolling Yubikey")

        driver = self.driver
        driver.get(self.base_url + "/manage")

        user_view = UserView(driver, self.base_url, self.realm_name)
        user_view.select_user(self.user_name)
        token_view = TokenView(driver, self.base_url)
        token_view.select_token(serial)
        driver.find_element_by_id("button_assign").click()
        time.sleep(2)
        pin = "asdf1234"
        driver.find_element_by_id("pin1").clear()
        driver.find_element_by_id("pin1").send_keys(pin)
        driver.find_element_by_id("pin2").clear()
        driver.find_element_by_id("pin2").send_keys(pin)
        driver.find_element_by_id("button_setpin_setpin").click()
        time.sleep(1)

        validate = Validate(self.http_protocol, self.http_host, self.http_username,
                            self.http_password)

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
            access_granted, _ = validate.validate(user=self.user_name + "@" +
                                                self.realm_name, password=pin + otp)
            self.assertTrue(access_granted, "OTP: " + pin + otp + " for user " +
                                         self.user_name + "@" + self.realm_name + " returned False")

        # validate/check_yubikey
        password = pin + public_uid + "eihtnehtetluntirtirrvblfkttbjuih"
        cy_auth = HTTPDigestAuth(self.http_username, self.http_password)
        cy_validate_url = self.http_protocol + "://" + self.http_host + "/validate/check_yubikey?"
        response = requests.get(cy_validate_url,
                                params={'pass': password},
                                auth=cy_auth,
                                verify=False)
        self.assertEqual(response.status_code, 200, "Invalid response %r" % response)
        return_json = response.json()
        self.assertTrue(return_json['result']['status'],
                        "Invalid return value: %r" % return_json)
        self.assertTrue(return_json['result']['value'],
                        "Invalid return value: %r" % return_json)
        self.assertEqual(return_json['detail']['user'],
                         self.user_name,
                         "Invalid return value: %r" % return_json)
        self.assertEqual(return_json['detail']['realm'],
                         self.realm_name,
                         "Invalid return value: %r" % return_json)

        # Repeat an old (therefore invalid) OTP value
        invalid_otp = public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
        access_granted, _ = validate.validate(user=self.user_name + "@" +
                                            self.realm_name, password=pin + invalid_otp)
        self.assertFalse(access_granted,
                         "OTP: " + pin + invalid_otp + " for user " + self.user_name + "@" +
                             self.realm_name + " should be rejected.")

        # Repeat an old (therefore invalid) OTP value with validate/check_yubikey
        invalid_otp = pin + public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
        response = requests.get(cy_validate_url,
                                params={'pass': password},
                                auth=cy_auth,
                                verify=False)
        self.assertEqual(response.status_code, 200, "Invalid response %r" % response)
        return_json = response.json()
        self.assertTrue(return_json['result']['status'],
                        "Invalid return value: %r" % return_json)
        self.assertFalse(return_json['result']['value'],
                         "Invalid return value: %r" % return_json)
        try:
            return_json['detail']['user']
            self.fail("Response should not contain detail.user %r" % return_json)
        except KeyError:
            pass
        try:
            return_json['detail']['realm']
            self.fail("Response should not contain detail.realm %r" % return_json)
        except KeyError:
            pass


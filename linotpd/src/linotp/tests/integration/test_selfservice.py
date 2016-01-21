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
"""LinOTP Selenium Test that tests the selfservice in the WebUI"""

import time

from linotp_selenium_helper import TestCase, Policy, LdapUserIdResolver, \
    Realm

class TestSelfservice(TestCase):
    """TestCase class that tests the selfservice by first creating a policy
       that allows users to access the selfservice and change their OTP Pin
       and then logging in and verifying the text "set PIN" is present.
    """

    def test_selfservice(self):
        """Creates User-Id-Resolvers"""
        driver = self.driver

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

        # Create LDAP resolver
        music_ldap_name = "SE_selfservice"
        music_ldap_id_resolver = LdapUserIdResolver(
            music_ldap_name,
            driver,
            self.base_url,
            uri="ldaps://blackdog",
            certificate=ad_certificate,
            basedn="ou=people,dc=blackdog,dc=office,dc=lsexperts,dc=de",
            binddn=u'cn="Antonín Dvořák",ou=people,dc=blackdog,dc=office,dc=lsexperts,dc=de',
            password="Test123!",
            preset_ldap=True
        )
        time.sleep(1)

        # Create realm
        resolvers_realm = [music_ldap_id_resolver]
        realm_name = "SE_realm_selfservice"
        realm = Realm(realm_name, resolvers_realm)
        realm.create(driver, self.base_url)
        time.sleep(1)

        Policy(driver, self.base_url, "SE_policy_selfservice",
               "selfservice", "setOTPPIN, ", realm_name.lower())
        time.sleep(1)

        login_user = u"郎"
        login_password = "Test123!"

        driver.get(self.base_url + "/account/login")
        driver.find_element_by_id("login").clear()
        driver.find_element_by_id("login").send_keys(login_user + "@" + realm_name.lower())
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys(login_password)
        driver.find_element_by_css_selector("input[type=\"submit\"]").click()
        time.sleep(3)
        try:
            self.assertRegexpMatches(driver.find_element_by_css_selector("BODY").text,
                                     r"^[\s\S]*set PIN[\s\S]*$")
        except AssertionError as assertion_error:
            self.verification_errors.append(str(assertion_error))


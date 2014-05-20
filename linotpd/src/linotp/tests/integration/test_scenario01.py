# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
"""LinOTP Selenium Test for Scenario 01 - General functionality tests"""

import time

from linotp_selenium_helper import TestCase, Policy, LdapUserIdResolver, \
    Realm, SqlUserIdResolver
from linotp_selenium_helper.user_view import UserView
from linotp_selenium_helper.token_view import TokenView
from linotp_selenium_helper.token_import import TokenImport
from linotp_selenium_helper.validate import Validate
from linotp_selenium_helper.remote_token import RemoteToken

from linotp.lib.HMAC import HmacOtp
import binascii


class TestScenario01(TestCase):
    """TestCase class that tests Scenario 01 as defined here:
       https://wally/projects/linotp/wiki/TestingTest_Szenario_01
    """

    def test_scenario01(self):
        """Tests Scenario 01 (https://wally/projects/linotp/wiki/TestingTest_Szenario_01)"""

        driver = self.driver

        ### 1. UserIdResolver anlegen ###
        CA001_cert = \
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

        # Create LDAP UserIdResolver
        ldap_name = "SE_scenario01_ldap"
        ldap_expected_users = ['bach', 'beethoven', 'berlioz', 'brahms', 'debussy', u'dvořák',
                               'haydn', 'mozart', u'حافظ', u'郎']
        ldap_num_expected_users = len(ldap_expected_users)
        ldap_id_resolver = LdapUserIdResolver(
            ldap_name,
            driver,
            self.base_url,
            uri="ldaps://blackdog",
            certificate=CA001_cert,
            basedn="ou=people,dc=blackdog,dc=office,dc=lsexperts,dc=de",
            # You may also use cn="Wolfgang Amadeus Mozart"
            binddn=u'cn="عبد الحليم حافظ",ou=people,dc=blackdog,dc=office,dc=lsexperts,dc=de',
            password="Test123!",
            preset_ldap=True
        )
        time.sleep(1)

        # Create SQL UserIdResolver
        sql_name = "SE_scenario01_sql"
        sql_server = "blackdog"
        sql_database = "userdb"
        sql_user = "resolver_user"
        sql_password = "Test123!"
        sql_table = "user"
        sql_limit = "500"
        sql_encoding = "latin1"
        sql_expected_users = ["corny", "kay", "eric", u"knöt"]
        sql_num_expected_users = len(sql_expected_users)
        sql_id_resolver = SqlUserIdResolver(sql_name, driver, self.base_url,
                                            sql_server, sql_database,
                                            sql_user, sql_password, sql_table,
                                            sql_limit, sql_encoding)
        time.sleep(1)

        # Create realm for all resolvers
        resolvers_realm1 = [ldap_id_resolver]
        realm_name1 = "SE_scenario01_realm1"
        realm1 = Realm(realm_name1, resolvers_realm1)
        realm1.create(driver, self.base_url)
        time.sleep(1)

        resolvers_realm2 = [sql_id_resolver]
        realm_name2 = "SE_scenario01_realm2"
        realm2 = Realm(realm_name2, resolvers_realm2)
        realm2.create(driver, self.base_url)
        time.sleep(1)

        ### 2. Im Management Webinterface testen, dass alle Benutzer sichtbar sind ###

        user_view = UserView(driver, self.base_url, realm_name1)
        self.assertEqual(ldap_num_expected_users, user_view.get_num_users(),
                         "Not the expected number of users")
        for user in ldap_expected_users:
            self.assertTrue(user_view.user_exists(user), "User '" + user +
                            "' should exist.")
        time.sleep(1)

        user_view = UserView(driver, self.base_url, realm_name2)
        self.assertEqual(sql_num_expected_users, user_view.get_num_users(),
                         "Not the expected number of users")
        for user in sql_expected_users:
            self.assertTrue(user_view.user_exists(user), "User '" + user +
                            "' should exist.")

        ### 3. eToken.xml ueber das Webinterface importieren  ###

        seed_oath137332 = "ff06df50017d3b981cfbc4ec4d374040164d8d19"
        seed_oath137332_bin = binascii.unhexlify(seed_oath137332)
        file_content = """<Tokens>
<Token serial="00040008CFA5">
<CaseModel>5</CaseModel>
<Model>101</Model>
<ProductionDate>02/19/2009</ProductionDate>
<ProductName>Safeword Alpine</ProductName>
<Applications>
<Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb9}">
<Seed>123412354</Seed>
<MovingFactor>1</MovingFactor>
</Application>
</Applications>
</Token>
<Token serial="00040008CFA52">
<CaseModel>5</CaseModel>
<Model>101</Model>
<ProductionDate>02/19/2009</ProductionDate>
<ProductName>Safeword Alpine</ProductName>
<Applications>
<Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb9}">
<Seed>123456</Seed>
<MovingFactor>1</MovingFactor>
</Application>
</Applications>
</Token>
<Token serial="oath137332">
<CaseModel>5</CaseModel>
<Model>101</Model>
<ProductionDate>02/19/2009</ProductionDate>
<ProductName>Safeword Alpine</ProductName>
<Applications>
<Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb1}">
<Seed>""" + seed_oath137332 + """</Seed>
<MovingFactor>1</MovingFactor>
</Application>
</Applications>
</Token>
<Token serial="oath12482B">
<CaseModel>5</CaseModel>
<Model>101</Model>
<ProductionDate>02/19/2009</ProductionDate>
<ProductName>Safeword Alpine</ProductName>
<Applications>
<Application ConnectorID="{ab1397d2-ddb6-4705-b66e-9f83f322deb2}">
<Seed>6ec1d0e9915a2bebf84745b318e39e481249c1eb</Seed>
<MovingFactor>1</MovingFactor>
</Application>
</Applications>
</Token>
</Tokens>"""

        TokenImport(driver, self.base_url, "safenet", file_content, None)

        test1_user = "bach"
        test1_token = "oath137332"
        test1_realm = realm_name1.lower()

        ### 4. Im Management Webinterface nun eine Policy anlegen ###

        Policy(driver, self.base_url, "SE_scenario01", "selfservice",
               "enrollMOTP, setOTPPIN, setMOTPPIN, resync, disable ",
               test1_realm)

        ### 5. eToken zuweisen ###

        user_view = UserView(driver, self.base_url, test1_realm)
        user_view.select_user(test1_user)
        token_view = TokenView(driver, self.base_url)
        token_view.select_token(test1_token)
        driver.find_element_by_id("button_assign").click()
        time.sleep(2)
        driver.find_element_by_id("pin1").clear()
        driver.find_element_by_id("pin1").send_keys("1234")
        driver.find_element_by_id("pin2").clear()
        driver.find_element_by_id("pin2").send_keys("1234")
        driver.find_element_by_id("button_setpin_setpin").click()
        time.sleep(1)

        ### 6. Remote Token zuweisen ###

        driver.get(self.base_url + "/manage/")
        time.sleep(2)
        user_view = UserView(driver, self.base_url, test1_realm)
        remote_token_user = "debussy"
        user_view.select_user(remote_token_user)
        remote_token_pin = "1234"
        remote_token = RemoteToken(driver=self.driver,
                                   base_url=self.base_url,
                                   url="https://billybones",
                                   serial="LSSP0002F653",
                                   pin=remote_token_pin)
        remote_token_otp = "666666"

        ### 10. Authentisierung der 4 Benutzer (noch unvollstaendig)  ###

        # Validate HOTP Token
        hotp = HmacOtp()
        validate = Validate(self.http_protocol,
                            self.http_host,
                            self.http_username,
                            self.http_password)
        for counter in range(0, 20):
            otp = "1234" + hotp.generate(counter=counter, key=seed_oath137332_bin)
            access_granted, _ = validate.validate(user=test1_user + "@" +
                                                test1_realm, password=otp)
            self.assertTrue(access_granted, "OTP: " + otp + " for user " +
                            test1_user + "@" + test1_realm + " returned False")
        access_granted, _ = validate.validate(user=test1_user + "@" + test1_realm,
                                            password="1234111111")
        self.assertFalse(access_granted, "OTP: 1234111111 should be False for user " + test1_user)

        # Validate Remote token
        access_granted, _ = validate.validate(user=remote_token_user + "@" + test1_realm,
                                            password=remote_token_pin + remote_token_otp)
        self.assertTrue(access_granted, "OTP: " + remote_token_otp + " for user " +
                        remote_token_user + "@" + test1_realm + " returned False")
        access_granted, _ = validate.validate(user=remote_token_user + "@" + test1_realm,
                                            password="1234111111")
        self.assertFalse(access_granted, "OTP: 1234111111 should be False for user %s" %
                                          remote_token_user)


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
from linotp_selenium_helper.spass_token import SpassToken

from linotp.lib.HMAC import HmacOtp
import binascii


def calculate_motp(epoch, key, pin, digits=6):
    """
    :param epoch: number of seconds since January 1, 1970 (time.time())
    :type epoch: number
    :param key: mOTP key
    :type key: string
    :param pin: mOTP PIN
    :type pin: string
    """
    from hashlib import md5
    vhash = "%d%s%s" % (epoch / 10, key, pin)
    motp = md5(vhash).hexdigest()[:digits]
    return motp


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

        serial_token_bach = "oath137332"
        test1_realm = realm_name1.lower()

        ### 4. Im Management Webinterface nun eine Policy anlegen ###

        Policy(driver, self.base_url, "SE_scenario01", "selfservice",
               "enrollMOTP, setOTPPIN, setMOTPPIN, resync, disable ",
               test1_realm)

        ### 5. eToken zuweisen ###

        user_view = UserView(driver, self.base_url, test1_realm)
        user_view.select_user("bach")
        token_view = TokenView(driver, self.base_url)
        token_view.select_token(serial_token_bach)
        driver.find_element_by_id("button_assign").click()
        time.sleep(2)
        driver.find_element_by_id("pin1").clear()
        driver.find_element_by_id("pin1").send_keys("1234")
        driver.find_element_by_id("pin2").clear()
        driver.find_element_by_id("pin2").send_keys("1234")
        driver.find_element_by_id("button_setpin_setpin").click()
        time.sleep(1)

        ### 6. Remote Token zuweisen ###

        user_view = UserView(driver, self.base_url, test1_realm)
        user_view.select_user("debussy")
        remote_token = RemoteToken(driver=self.driver,
                                   base_url=self.base_url,
                                   url="https://billybones",
                                   remote_serial="LSSP0002F653",
                                   pin="1234")
        serial_token_debussy = remote_token.serial
        remote_token_otp = "666666"
        time.sleep(1)

        ### 7. Spass-Token zuweisen ###

        user_view = UserView(driver, self.base_url, test1_realm)
        user_view.select_user("beethoven")
        spass_token = SpassToken(
            driver=self.driver,
            base_url=self.base_url,
            pin=u"beethovenspass#ñô",
            description="SPass Token enrolled with Selenium"
            )
        serial_token_beethoven = spass_token.serial
        time.sleep(1)

        ### 8. Selfservice mOTP ###

        motp_key = "1234123412341234"
        motp_pin = "1234"
        driver.get(self.base_url + "/account/login")
        driver.find_element_by_id("login").clear()
        driver.find_element_by_id("login").send_keys("mozart@" + test1_realm)
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys("Test123!")
        driver.find_element_by_id("password").submit() # Submits the form
        time.sleep(1)
        driver.find_element_by_id("motp_secret").clear()
        driver.find_element_by_id("motp_secret").send_keys(motp_key)
        driver.find_element_by_id("motp_s_pin1").clear()
        driver.find_element_by_id("motp_s_pin1").send_keys(motp_pin)
        driver.find_element_by_id("motp_s_pin2").clear()
        driver.find_element_by_id("motp_s_pin2").send_keys(motp_pin)
        driver.find_element_by_id("motp_self_desc").clear()
        driver.find_element_by_id("motp_self_desc").send_keys("Selenium self enrolled")
        driver.find_element_by_id("button_register_motp").click()
        time.sleep(1)
        alert_box_text = driver.find_element_by_id("allert_box_text").text
        alert_box_text_list = alert_box_text.split("\n")
        self.assertEqual(
            alert_box_text_list[0],
            "Token enrolled successfully:"
            )
        serial_text = alert_box_text_list[1] # serial: LSMO12345678
        serial_token_mozart = serial_text[8:].strip()
        self.driver.find_element_by_xpath("//button[@type='button' and ancestor::div[@aria-describedby='alert_box']]").click()
        driver.find_element_by_link_text("Logout").click()

        ### 9. Alle 4 Benutzer melden sich im selfservice Portal an und setzen die PIN

        user_token_dict = {
            "bach": serial_token_bach,
            "debussy": serial_token_debussy,
            "mozart": serial_token_mozart,
            "beethoven": serial_token_beethoven
            }
        for user in user_token_dict:
            driver.get(self.base_url + "/account/login")
            driver.find_element_by_id("login").clear()
            driver.find_element_by_id("login").send_keys("%s@%s" % (user, test1_realm))
            driver.find_element_by_id("password").clear()
            driver.find_element_by_id("password").send_keys("Test123!")
            driver.find_element_by_id("password").submit()
            driver.find_element_by_xpath("//div[@id='tabs']/ul/li/a/span[text()='set PIN']").click()
            time.sleep(1)
            # driver.find_element_by_css_selector('#tokenDiv > ul > li > a').click()
            driver.find_element_by_id('tokenDiv').find_element_by_link_text(user_token_dict[user]).click()
            driver.find_element_by_id("pin1").clear()
            driver.find_element_by_id("pin1").send_keys(user + "newpin")
            driver.find_element_by_id("pin2").clear()
            driver.find_element_by_id("pin2").send_keys(user + "newpin")
            driver.find_element_by_id("button_setpin").click()
            time.sleep(1)
            self.assertEqual("PIN set successfully", self.close_alert_and_get_its_text())
            driver.find_element_by_link_text("Logout").click()

        ### 10. Authentisierung der 4 Benutzer ###
        validate = Validate(self.http_protocol,
                            self.http_host,
                            self.http_username,
                            self.http_password)

        # Validate HOTP Token - bach
        hotp = HmacOtp()
        for counter in range(0, 20):
            otp = "bachnewpin" + hotp.generate(counter=counter, key=seed_oath137332_bin)
            access_granted, _ = validate.validate(user="bach@" +
                                                test1_realm, password=otp)
            self.assertTrue(access_granted, "OTP: " + otp + " for user " +
                            "bach@" + test1_realm + " returned False")
        access_granted, _ = validate.validate(user="bach@" + test1_realm,
                                            password="1234111111")
        self.assertFalse(access_granted, "OTP: 1234111111 should be False for user bach")

        # Validate Remote token - debussy
        access_granted, _ = validate.validate(user="debussy@" + test1_realm,
                                            password="debussynewpin" + remote_token_otp)
        self.assertTrue(access_granted, "OTP: " + remote_token_otp + " for user " +
                        "debussy@" + test1_realm + " returned False")
        access_granted, _ = validate.validate(user="debussy@" + test1_realm,
                                            password="1234111111")
        self.assertFalse(access_granted, "OTP: 1234111111 should be False for user debussy")

        # Validate Spass token - beethoven
        access_granted, _ = validate.validate(user="beethoven@" + test1_realm,
                                            password="beethovennewpin")
        self.assertTrue(access_granted, "OTP: " + "beethovennewpin" + " for user " +
                        "beethoven@" + test1_realm + " returned False")
        access_granted, _ = validate.validate(user="beethoven@" + test1_realm,
                                            password="randominvalidpin")
        self.assertFalse(access_granted, "OTP: randominvalidpin should be False for user beethoven")

        # Validate mOTP token - mozart
        current_epoch = time.time()
        motp_otp = calculate_motp(
            epoch=current_epoch,
            key=motp_key,
            pin=motp_pin
            )
        access_granted, _ = validate.validate(user="mozart@" + test1_realm,
                                            password="mozartnewpin" + motp_otp)
        self.assertTrue(access_granted, "OTP: " + motp_otp + " for user " +
                        "mozart@" + test1_realm + " returned False")
        motp_otp = calculate_motp(
            epoch=current_epoch - 4000,
            key=motp_key,
            pin=motp_pin
            )
        access_granted, _ = validate.validate(user="mozart@" + test1_realm,
                                            password="mozartnewpin" + motp_otp)
        self.assertFalse(access_granted, "OTP: mozartnewpin%s should be False for user mozart" % motp_otp)

        ### 11. mOTP Pin im selfservice ändern ###

        driver.get(self.base_url + "/account/login")
        driver.find_element_by_id("login").clear()
        driver.find_element_by_id("login").send_keys("%s@%s" % ("mozart", test1_realm))
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys("Test123!")
        driver.find_element_by_id("password").submit()
        driver.find_element_by_xpath("//div[@id='tabs']/ul/li/a/span[text()='set mOTP PIN']").click()
        time.sleep(1)
        driver.find_element_by_id('tokenDiv').find_element_by_link_text(serial_token_mozart).click()
        driver.find_element_by_id("mpin1").clear()
        new_motp_pin = "5588"
        driver.find_element_by_id("mpin1").send_keys(new_motp_pin)
        driver.find_element_by_id("mpin2").clear()
        driver.find_element_by_id("mpin2").send_keys(new_motp_pin)
        driver.find_element_by_id("button_setmpin").click()
        time.sleep(1)
        self.assertEqual("mOTP PIN set successfully", self.close_alert_and_get_its_text())
        driver.find_element_by_link_text("Logout").click()

        current_epoch = time.time()
        motp_otp = calculate_motp(
            epoch=current_epoch,
            key=motp_key,
            pin=new_motp_pin
            )
        access_granted, _ = validate.validate(user="mozart@" + test1_realm,
                                            password="mozartnewpin" + motp_otp)
        self.assertTrue(access_granted, "OTP: mozartnewpin" + motp_otp + " for user " +
                        "mozart@" + test1_realm + " returned False")

        ### 12. Token Resynchronisierung ###

        # Bach 'presses' his token more than 10 times and fails to authenticate
        counter = 50 # was 19
        hotp = HmacOtp()
        otp = "bachnewpin" + hotp.generate(counter=counter, key=seed_oath137332_bin)
        access_granted, _ = validate.validate(user="bach@" + test1_realm,
                                              password=otp)
        self.assertFalse(access_granted, "OTP: %s should be False for user bach" % otp)

        driver.get(self.base_url + "/account/login")
        driver.find_element_by_id("login").clear()
        driver.find_element_by_id("login").send_keys("%s@%s" % ("bach", test1_realm))
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys("Test123!")
        driver.find_element_by_id("password").submit()
        driver.find_element_by_xpath("//div[@id='tabs']/ul/li/a/span[text()='Resync Token']").click()
        time.sleep(1)
        driver.find_element_by_id('tokenDiv').find_element_by_link_text(serial_token_bach).click()
        otp1 = hotp.generate(counter=counter + 1, key=seed_oath137332_bin)
        otp2 = hotp.generate(counter=counter + 2, key=seed_oath137332_bin)
        driver.find_element_by_id("otp1").clear()
        driver.find_element_by_id("otp1").send_keys(otp1)
        driver.find_element_by_id("otp2").clear()
        driver.find_element_by_id("otp2").send_keys(otp2)
        driver.find_element_by_id("button_resync").click()
        time.sleep(1)
        self.assertEqual("Token resynced successfully", self.close_alert_and_get_its_text())
        driver.find_element_by_link_text("Logout").click()

        # Should be able to authenticate again
        otp = "bachnewpin" + hotp.generate(counter=counter + 3, key=seed_oath137332_bin)
        access_granted, _ = validate.validate(user="bach@" + test1_realm,
                                              password=otp)
        self.assertTrue(access_granted, "OTP: %s should be True for user bach" % otp)

        ### 13. Ein Benutzer debussy deaktiviert seinen Token im Selfservice portal und versucht sich anzumelden. ###

        driver.get(self.base_url + "/account/login")
        driver.find_element_by_id("login").clear()
        driver.find_element_by_id("login").send_keys("%s@%s" % ("debussy", test1_realm))
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys("Test123!")
        driver.find_element_by_id("password").submit()
        driver.find_element_by_xpath("//div[@id='tabs']/ul/li/a/span[text()='Disable Token']").click()
        time.sleep(1)
        driver.find_element_by_id('tokenDiv').find_element_by_link_text(serial_token_debussy).click()
        driver.find_element_by_id("button_disable").click()
        time.sleep(1)
        self.assertEqual("Token disabled successfully", self.close_alert_and_get_its_text())
        driver.find_element_by_link_text("Logout").click()

        # debussy should be unable to authenticate
        access_granted, _ = validate.validate(user="debussy@" + test1_realm,
                                            password="debussynewpin" + remote_token_otp)
        self.assertFalse(access_granted, "OTP: debussynewpin" + remote_token_otp + "should be False for user debussy")

        ### 14. Der Admin entsperrt diesen Token, der Benutzer debussy kann sich wieder anmelden. ###

        driver.get(self.base_url + "/manage")
        time.sleep(1)
        token_view = TokenView(driver, self.base_url)
        token_view.select_token(serial_token_debussy)
        driver.find_element_by_id("button_enable").click()
        time.sleep(1)

        # debussy should be able to authenticate
        access_granted, _ = validate.validate(user="debussy@" + test1_realm,
                                            password="debussynewpin" + remote_token_otp)
        self.assertTrue(access_granted, "OTP: debussynewpin" + remote_token_otp + "should be True for user debussy")

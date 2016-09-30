# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 KeyIdentity GmbH
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
import re
import binascii
import logging

from linotp_selenium_helper import TestCase, Policy
from linotp_selenium_helper.user_view import UserView
from linotp_selenium_helper.token_view import TokenView
from linotp_selenium_helper.token_import import TokenImport
from linotp_selenium_helper.validate import Validate
from linotp_selenium_helper.remote_token import RemoteToken
from linotp_selenium_helper.spass_token import SpassToken

from linotp.lib.HMAC import HmacOtp

import integration_data as data

LOGGER = logging.getLogger(__name__)

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

    def _announce_test(self, testname):
        LOGGER.info("### %s ###" % testname)
    def test_scenario01(self):
        """Tests Scenario 01 (https://wally/projects/linotp/wiki/TestingTest_Szenario_01)"""

        driver = self.driver

        token_view = TokenView(self)

        # reset all views
        self.reset_resolvers_and_realms()
        self.reset_policies()
        token_view.delete_all_tokens()

        self._announce_test("1. UserIdResolver anlegen")
        # Create LDAP UserIdResolver
        ldap_data = data.musicians_ldap_resolver
        ldap_expected_users = ldap_data['users']
        ldap_num_expected_users = ldap_data['expected_users']
        ldap_resolver = self.useridresolver_manager.create_resolver(ldap_data)

        # Create SQL UserIdResolver
        sql_data = data.sql_resolver
        sql_resolver = self.useridresolver_manager.create_resolver(sql_data)
        sql_expected_users = sql_data['users']
        sql_num_expected_users = sql_data['expected_users']

        # Create realm for all resolvers
        realm_name1 = "SE_scenario01_realm1"
        realm_name2 = "SE_scenario01_realm2"
        self.realm_manager.create(realm_name1, [ldap_resolver])
        self.realm_manager.create(realm_name2, [sql_resolver])

        self._announce_test("2. In Management Webinterface, check that all users are visible")

        user_view = UserView(driver, self.base_url, realm_name1)
        time.sleep(2)
        self.assertEqual(ldap_num_expected_users, user_view.get_num_users(),
                         "Not the expected number of users")
        for user in ldap_expected_users:
            self.assertTrue(user_view.user_exists(user), "User '" + user +
                            "' should exist.")

        user_view = UserView(driver, self.base_url, realm_name2)
        time.sleep(2)
        self.assertEqual(sql_num_expected_users, user_view.get_num_users(),
                         "Not the expected number of users")
        for user in sql_expected_users:
            self.assertTrue(user_view.user_exists(user), "User '" + user +
                            "' should exist.")

        self._announce_test("3. eToken.xml ueber das Webinterface importieren")

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

        self._announce_test("4. Im Management Webinterface nun eine Policy anlegen")

        Policy(driver, self.base_url, "SE_scenario01", "selfservice",
               "enrollMOTP, setOTPPIN, setMOTPPIN, resync, disable ",
               test1_realm)

        self._announce_test("5. eToken zuweisen")

        user_view = UserView(driver, self.base_url, test1_realm)
        user_view.select_user("bach")
        token_view = TokenView(self)
        token_view.assign_token(serial_token_bach, "1234")

        self._announce_test("6. Remote Token zuweisen")

        user_view = UserView(driver, self.base_url, test1_realm)
        user_view.select_user("debussy")
        remote_token = RemoteToken(driver=self.driver,
                                   base_url=self.base_url,
                                   url="https://billybones",
                                   remote_serial="LSSP0002F653",
                                   pin="1234",
                                   remote_otp_length=6,
                                   )
        serial_token_debussy = remote_token.serial
        remote_token_otp = "666666"

        self._announce_test("7. Spass-Token zuweisen")

        user_view = UserView(driver, self.base_url, test1_realm)
        user_view.select_user("beethoven")
        spass_token = SpassToken(
            driver=self.driver,
            base_url=self.base_url,
            pin=u"beethovenspass#ñô",
            description="SPass Token enrolled with Selenium"
            )
        serial_token_beethoven = spass_token.serial

        self._announce_test("8. Selfservice mOTP")

        motp_key = "1234123412341234"
        motp_pin = "1234"
        driver.get(self.base_url + "/account/login")
        driver.find_element_by_id("login").clear()
        driver.find_element_by_id("login").send_keys("mozart@" + test1_realm)
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys("Test123!")
        driver.find_element_by_id("password").submit() # Submits the form
        driver.find_element_by_id("motp_secret").clear()
        driver.find_element_by_id("motp_secret").send_keys(motp_key)
        driver.find_element_by_id("motp_s_pin1").clear()
        driver.find_element_by_id("motp_s_pin1").send_keys(motp_pin)
        driver.find_element_by_id("motp_s_pin2").clear()
        driver.find_element_by_id("motp_s_pin2").send_keys(motp_pin)
        driver.find_element_by_id("motp_self_desc").clear()
        driver.find_element_by_id("motp_self_desc").send_keys("Selenium self enrolled")
        driver.find_element_by_id("button_register_motp").click()
        alert_box_text = driver.find_element_by_id("alert_box_text").text
        m = re.match(
            r"""
                .*?
                Token\ enrolled\ successfully
                .*?
                [sS]erial(\ number)?:     # 'serial:' or 'Serial number:'
                \s*
                (?P<serial>\w+)           # For example: LSMO0001222C
                """,
            alert_box_text,
            re.DOTALL | re.VERBOSE
            )
        self.assertTrue(
            m is not None,
            "alert_box_text does not match regex. Possibly the token was not enrolled properly. %r" % alert_box_text
            )
        serial_token_mozart = m.group('serial')
        self.driver.find_element_by_xpath("//button[@type='button' and ancestor::div[@aria-describedby='alert_box']]").click()
        driver.find_element_by_link_text("Logout").click()

        self._announce_test("9. Alle 4 Benutzer melden sich im selfservice Portal an und setzen die PIN")

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
            driver.find_element_by_id('tokenDiv').find_element_by_partial_link_text(user_token_dict[user]).click()
            driver.find_element_by_id("pin1").clear()
            driver.find_element_by_id("pin1").send_keys(user + "newpin")
            driver.find_element_by_id("pin2").clear()
            driver.find_element_by_id("pin2").send_keys(user + "newpin")
            driver.find_element_by_id("button_setpin").click()
            time.sleep(1)
            self.assertEqual("PIN set successfully", self.close_alert_and_get_its_text())
            driver.find_element_by_link_text("Logout").click()

        self._announce_test("10. Authentisierung der 4 Benutzer ###")
        validate = Validate(self.http_protocol,
                            self.http_host,
                            self.http_port,
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

        # deactivated remote token test while no remote linotp integration server is available
        '''
        access_granted, _ = validate.validate(user="debussy@" + test1_realm,
                                            password="debussynewpin" + remote_token_otp)
        self.assertTrue(access_granted, "OTP: " + remote_token_otp + " for user " +
                        "debussy@" + test1_realm + " returned False")
        access_granted, _ = validate.validate(user="debussy@" + test1_realm,
                                            password="1234111111")
        self.assertFalse(access_granted, "OTP: 1234111111 should be False for user debussy")'''

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

        self._announce_test("11. mOTP Pin im selfservice ändern")

        driver.get(self.base_url + "/account/login")
        driver.find_element_by_id("login").clear()
        driver.find_element_by_id("login").send_keys("%s@%s" % ("mozart", test1_realm))
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys("Test123!")
        driver.find_element_by_id("password").submit()
        driver.find_element_by_xpath("//div[@id='tabs']/ul/li/a/span[text()='set mOTP PIN']").click()
        time.sleep(1)
        driver.find_element_by_id('tokenDiv').find_element_by_partial_link_text(serial_token_mozart).click()
        time.sleep(1)
        driver.find_element_by_id("mpin1").clear()
        new_motp_pin = "5588"
        driver.find_element_by_id("mpin1").send_keys(new_motp_pin)
        driver.find_element_by_id("mpin2").clear()
        driver.find_element_by_id("mpin2").send_keys(new_motp_pin)
        driver.find_element_by_id("button_setmpin").click()
        self.assertEqual("mOTP PIN set successfully", self.close_alert_and_get_its_text())
        driver.find_element_by_link_text("Logout").click()

        time.sleep(10) # otherwise next mOTP value might not be valid

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

        self._announce_test("12. Token Resynchronisierung")

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
        driver.find_element_by_id('tokenDiv').find_element_by_partial_link_text(serial_token_bach).click()
        otp1 = hotp.generate(counter=counter + 1, key=seed_oath137332_bin)
        otp2 = hotp.generate(counter=counter + 2, key=seed_oath137332_bin)
        driver.find_element_by_id("otp1").clear()
        driver.find_element_by_id("otp1").send_keys(otp1)
        driver.find_element_by_id("otp2").clear()
        driver.find_element_by_id("otp2").send_keys(otp2)
        driver.find_element_by_id("button_resync").click()
        self.assertEqual("Token resynced successfully", self.close_alert_and_get_its_text())
        driver.find_element_by_link_text("Logout").click()

        # Should be able to authenticate again
        otp = "bachnewpin" + hotp.generate(counter=counter + 3, key=seed_oath137332_bin)
        access_granted, _ = validate.validate(user="bach@" + test1_realm,
                                              password=otp)
        self.assertTrue(access_granted, "OTP: %s should be True for user bach" % otp)

        self._announce_test("13. Benutzer beethoven deaktiviert seinen Token im Selfservice portal und versucht sich anzumelden.")

        driver.get(self.base_url + "/account/login")
        driver.find_element_by_id("login").clear()
        driver.find_element_by_id("login").send_keys("%s@%s" % ("beethoven", test1_realm))
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys("Test123!")
        driver.find_element_by_id("password").submit()
        driver.find_element_by_xpath("//div[@id='tabs']/ul/li/a/span[text()='Disable Token']").click()
        time.sleep(1)
        driver.find_element_by_id('tokenDiv').find_element_by_partial_link_text(serial_token_beethoven).click()
        driver.find_element_by_id("button_disable").click()
        self.assertEqual("Token disabled successfully", self.close_alert_and_get_its_text())
        driver.find_element_by_link_text("Logout").click()

        # beethoven should be unable to authenticate
        access_granted, _ = validate.validate(user="beethoven@" + test1_realm,
                                            password="beethovennewpin")
        self.assertFalse(access_granted, "OTP: beethovennewpin should be False for user beethoven")

        self._announce_test("14. Der Admin entsperrt diesen Token, der Benutzer beethoven kann sich wieder anmelden.")

        driver.get(self.base_url + "/manage")
        token_view.select_token(serial_token_beethoven)
        driver.find_element_by_id("button_enable").click()

        # beethoven should be able to authenticate
        access_granted, _ = validate.validate(user="beethoven@" + test1_realm,
                                            password="beethovennewpin")
        self.assertTrue(access_granted, "OTP: beethovennewpin should be False for user beethoven")

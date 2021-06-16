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
from linotp_selenium_helper.self_service import SelfService

"""LinOTP Selenium Test for Scenario 01 - General functionality tests"""

import binascii
import logging
import os
import re
import time

import integration_data as data
import pytest

from linotp.lib.HMAC import HmacOtp
from linotp_selenium_helper import Policy, TestCase
from linotp_selenium_helper.token_import import TokenImportAladdin
from linotp_selenium_helper.validate import Validate

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
    motp = md5(vhash.encode("utf-8")).hexdigest()[:digits]
    return motp


@pytest.mark.smoketest
class TestScenario01(TestCase):
    """TestCase class that tests Scenario 01 as defined here:
    https://wally/projects/linotp/wiki/TestingTest_Szenario_01
    """

    def _announce_test(self, testname):
        LOGGER.info("### %s ###", testname)

    def test_scenario01(self):
        """
        Scenario01 (https://wally/projects/linotp/wiki/TestingTest_Szenario_01)
        """

        driver = self.driver

        token_view = self.manage_ui.token_view
        user_view = self.manage_ui.user_view
        token_enroll = self.manage_ui.token_enroll

        selfservice = SelfService(self)

        # reset all views
        self.reset_resolvers_and_realms()
        self.manage_ui.policy_view.clear_policies()
        token_view.delete_all_tokens()

        self._announce_test("1. UserIdResolver anlegen")
        # Create LDAP UserIdResolver
        ldap_data = data.musicians_ldap_resolver
        ldap_resolver = self.useridresolver_manager.create_resolver(ldap_data)

        # Create SQL UserIdResolver
        sql_data = data.sql_resolver

        sql_resolver = self.useridresolver_manager.create_resolver(sql_data)
        self.useridresolver_manager.close()

        # Create realm for all resolvers
        realm_name1 = "SE_scenario01_realm1"
        realm_name2 = "SE_scenario01_realm2"

        self.realm_manager.create(realm_name1, [ldap_resolver])
        self.realm_manager.create(realm_name2, [sql_resolver])
        self.realm_manager.close()

        self._announce_test(
            "2. In Management Webinterface, check that all users are visible"
        )

        self.check_users(realm_name1, ldap_data)
        self.check_users(realm_name2, sql_data)

        self._announce_test("3. eToken.xml ueber das Webinterface importieren")

        token_import_aladdin = TokenImportAladdin(self.manage_ui)

        aladdin_xml_path = os.path.join(
            self.manage_ui.test_data_dir, "aladdin.xml"
        )
        token_import_aladdin.do_import(file_path=aladdin_xml_path)

        serial_token_bach = "oath137332"
        test1_realm = realm_name1.lower()

        self._announce_test(
            "4. Im Management Webinterface nun eine Policy anlegen"
        )

        Policy(
            self.manage_ui,
            "SE_scenario01",
            "selfservice",
            "enrollMOTP, setOTPPIN, setMOTPPIN, resync, disable ",
            test1_realm,
        )

        self._announce_test("5. eToken zuweisen")

        user_view.select_realm(test1_realm)
        user_view.select_user("bach")

        token_view.assign_token(serial_token_bach, "1234")

        self._announce_test("6. Remote Token zuweisen")

        user_view.select_user("debussy")
        serial_token_debussy = token_enroll.create_remote_token(
            url="https://billybones",
            remote_serial="LSSP0002F653",
            pin="1234",
            remote_otp_length=6,
        )

        self._announce_test("7. Spass-Token zuweisen")

        user_view.select_user("beethoven")
        beethoven_token_password = "beethovenspass#ñô"
        serial_token_beethoven = token_enroll.create_static_password_token(
            password=beethoven_token_password,
            description="Password Token enrolled with Selenium",
        )

        self._announce_test("8. Selfservice mOTP")

        motp_key = "1234123412341234"
        motp_pin = "1234"
        selfservice.open()
        selfservice.login("mozart", "Test123!", test1_realm)
        driver.find_element_by_id("motp_secret").clear()
        driver.find_element_by_id("motp_secret").send_keys(motp_key)
        driver.find_element_by_id("motp_s_pin1").clear()
        driver.find_element_by_id("motp_s_pin1").send_keys(motp_pin)
        driver.find_element_by_id("motp_s_pin2").clear()
        driver.find_element_by_id("motp_s_pin2").send_keys(motp_pin)
        driver.find_element_by_id("motp_self_desc").clear()
        driver.find_element_by_id("motp_self_desc").send_keys(
            "Selenium self enrolled"
        )
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
            re.DOTALL | re.VERBOSE,
        )
        assert m is not None, (
            "alert_box_text does not match regex. Possibly the token was not enrolled properly. %r"
            % alert_box_text
        )
        serial_token_mozart = m.group("serial")
        self.driver.find_element_by_xpath(
            "//button[@type='button' and ancestor::div[@aria-describedby='alert_box']]"
        ).click()
        selfservice.logout()

        self._announce_test(
            "9. Alle 4 Benutzer melden sich im selfservice Portal an und setzen die PIN"
        )

        user_token_dict = {
            "bach": serial_token_bach,
            "debussy": serial_token_debussy,
            "mozart": serial_token_mozart,
            "beethoven": serial_token_beethoven,
        }

        for user, token in user_token_dict.items():
            selfservice.login(user, "Test123!", test1_realm)
            selfservice.set_pin(token, user + "newpin")
            selfservice.logout()

        self._announce_test("10. Authentisierung der 4 Benutzer ###")
        validate = Validate(
            self.http_protocol,
            self.http_host,
            self.http_port,
            self.http_username,
            self.http_password,
        )

        # seed is also set in testdata/aladdin.xml
        seed_oath137332 = "ff06df50017d3b981cfbc4ec4d374040164d8d19"
        seed_oath137332_bin = binascii.unhexlify(seed_oath137332)

        # Validate HOTP Token - bach
        hotp = HmacOtp()
        for counter in range(0, 4):
            otp = "bachnewpin" + hotp.generate(
                counter=counter, key=seed_oath137332_bin
            )
            access_granted, _ = validate.validate(
                user="bach@" + test1_realm, password=otp
            )
            assert access_granted, (
                "OTP: "
                + otp
                + " for user "
                + "bach@"
                + test1_realm
                + " returned False"
            )
        access_granted, _ = validate.validate(
            user="bach@" + test1_realm, password="1234111111"
        )
        assert (
            not access_granted
        ), "OTP: 1234111111 should be False for user bach"

        # Validate Remote token - debussy

        # deactivated remote token test while no remote linotp integration
        # server is available
        '''
        remote_token_otp = "666666"
        access_granted, _ = validate.validate(user="debussy@" + test1_realm,
                                            password="debussynewpin" + remote_token_otp)
        assert access_granted is True, "OTP: " + remote_token_otp + " for user " +
                        "debussy@" + test1_realm + " returned False"
        access_granted, _ = validate.validate(user="debussy@" + test1_realm,
                                            password="1234111111")
        assert access_granted is False, "OTP: 1234111111 should be False for user debussy"'''

        # Validate Spass token - beethoven

        # Correct PIN + password = success
        access_granted, _ = validate.validate(
            user="beethoven@" + test1_realm,
            password="beethovennewpin" + beethoven_token_password,
        )
        assert access_granted, (
            "OTP: "
            + "beethovennewpin"
            + " for user "
            + "beethoven@"
            + test1_realm
            + " returned False"
        )
        # wrong PIN + empty password = fail
        access_granted, _ = validate.validate(
            user="beethoven@" + test1_realm, password="randominvalidpin"
        )
        assert (
            not access_granted
        ), "OTP: randominvalidpin should be False for user beethoven"
        # correct PIN + wrong password = fail
        access_granted, _ = validate.validate(
            user="beethoven@" + test1_realm,
            password="beethovennewpin" + "wrongpassword",
        )
        assert (
            not access_granted
        ), "beethoven should not auth with wrong token password"
        # Password without pin = fail
        access_granted, _ = validate.validate(
            user="beethoven@" + test1_realm, password=beethoven_token_password
        )
        assert (
            not access_granted
        ), "beethoven should not auth with password and old pin"
        # Correct PIN + password = success (again)
        access_granted, _ = validate.validate(
            user="beethoven@" + test1_realm,
            password="beethovennewpin" + beethoven_token_password,
        )
        assert access_granted, (
            "OTP: "
            + "beethovennewpin"
            + " for user "
            + "beethoven@"
            + test1_realm
            + " returned False"
        )

        time.sleep(2)

        # Validate mOTP token - mozart
        current_epoch = time.time()
        motp_otp = calculate_motp(
            epoch=current_epoch, key=motp_key, pin=motp_pin
        )

        access_granted, _ = validate.validate(
            user="mozart@" + test1_realm, password="mozartnewpin" + motp_otp
        )
        time.sleep(1)
        assert access_granted, (
            "OTP: "
            + motp_otp
            + " for user "
            + "mozart@"
            + test1_realm
            + " returned False"
        )
        motp_otp = calculate_motp(
            epoch=current_epoch - 4000, key=motp_key, pin=motp_pin
        )
        access_granted, _ = validate.validate(
            user="mozart@" + test1_realm, password="mozartnewpin" + motp_otp
        )
        assert not access_granted, (
            "OTP: mozartnewpin%s should be False for user mozart" % motp_otp
        )

        self._announce_test("11. mOTP Pin im selfservice ändern")

        new_motp_pin = "5588"

        selfservice.open()
        selfservice.login("mozart", "Test123!", test1_realm)
        selfservice.set_motp_pin(serial_token_mozart, new_motp_pin)
        selfservice.logout()

        time.sleep(10)  # otherwise next mOTP value might not be valid

        current_epoch = time.time()
        motp_otp = calculate_motp(
            epoch=current_epoch, key=motp_key, pin=new_motp_pin
        )
        access_granted, _ = validate.validate(
            user="mozart@" + test1_realm, password="mozartnewpin" + motp_otp
        )
        assert access_granted, (
            "OTP: mozartnewpin"
            + motp_otp
            + " for user "
            + "mozart@"
            + test1_realm
            + " returned False"
        )

        self._announce_test("12. Token Resynchronisierung")

        # Bach 'presses' his token more than 10 times and fails to authenticate
        counter = 50  # was 19
        hotp = HmacOtp()
        otp = "bachnewpin" + hotp.generate(
            counter=counter, key=seed_oath137332_bin
        )
        access_granted, _ = validate.validate(
            user="bach@" + test1_realm, password=otp
        )
        assert not access_granted, (
            "OTP: %s should be False for user bach" % otp
        )

        selfservice.login("bach", "Test123!", test1_realm)

        otp1 = hotp.generate(counter=counter + 1, key=seed_oath137332_bin)
        otp2 = hotp.generate(counter=counter + 2, key=seed_oath137332_bin)

        selfservice.resync_token(serial_token_bach, otp1, otp2)
        selfservice.logout()

        # Should be able to authenticate again
        otp = "bachnewpin" + hotp.generate(
            counter=counter + 3, key=seed_oath137332_bin
        )
        access_granted, _ = validate.validate(
            user="bach@" + test1_realm, password=otp
        )
        assert access_granted, "OTP: %s should be True for user bach" % otp

        self._announce_test(
            "13. Benutzer beethoven deaktiviert seinen Token im Selfservice portal und versucht sich anzumelden."
        )

        selfservice.login("beethoven", "Test123!", test1_realm)
        selfservice.disable_token(serial_token_beethoven)
        selfservice.logout()

        # beethoven should be unable to authenticate
        access_granted, _ = validate.validate(
            user="beethoven@" + test1_realm,
            password="beethovennewpin" + beethoven_token_password,
        )
        assert (
            not access_granted
        ), "OTP: beethovennewpin should be False for user beethoven"

        self._announce_test(
            "14. Der Admin entsperrt diesen Token, der Benutzer beethoven kann sich wieder anmelden."
        )

        token_view.open()
        token_view.enable_token(serial_token_beethoven)

        # beethoven should be able to authenticate
        access_granted, _ = validate.validate(
            user="beethoven@" + test1_realm,
            password="beethovennewpin" + beethoven_token_password,
        )
        assert (
            access_granted
        ), "OTP: beethovennewpin should be able to authenticate after re-enabled token."

    def check_users(self, realm, data):
        expected_users = data["expected_users"]
        users = data["users"]

        found_users = self.manage_ui.user_view.get_num_users(realm)

        assert expected_users == found_users, (
            "Not the expected number of users in realm %s: Expecting %s but found %s"
            % (realm, expected_users, found_users)
        )

        for user in users:
            assert self.manage_ui.user_view.user_exists(
                user
            ), "User '%s' should exist in realm %s" % (user, realm)
            break

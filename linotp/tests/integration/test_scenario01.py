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

"""LinOTP Selenium Test for Scenario 01 - General functionality tests"""

import binascii
import logging
import os
import time

import integration_data as data
import pytest
import requests
from linotp_selenium_helper import Policy, TestCase
from linotp_selenium_helper.token_import import TokenImportAladdin
from linotp_selenium_helper.validate import Validate

from linotp.lib.HMAC import HmacOtp

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
class TestScenario01:
    """TestCase class that tests Scenario 01 as defined here:
    https://wiki.corp.linotp.de/pages/viewpage.action?pageId=119867175
    """

    @pytest.fixture(autouse=True)
    def setUp(self, testcase: TestCase):
        self.testcase = testcase

    def _announce_test(self, testname):
        LOGGER.info("### %s ###", testname)

    def test_scenario01(self):
        """
        Scenario01 (https://wiki.corp.linotp.de/pages/viewpage.action?pageId=119867175)
        """
        token_view = self.testcase.manage_ui.token_view
        user_view = self.testcase.manage_ui.user_view
        token_enroll = self.testcase.manage_ui.token_enroll

        selfservice = UserServiceApi(
            self.testcase.http_protocol,
            self.testcase.http_host,
            self.testcase.http_port,
        )

        # reset all views
        self.testcase.reset_resolvers_and_realms()
        self.testcase.manage_ui.policy_view.clear_policies()
        token_view.delete_all_tokens()

        self._announce_test("1. UserIdResolver anlegen")
        # Create LDAP UserIdResolver
        ldap_data = data.musicians_ldap_resolver
        ldap_resolver = self.testcase.useridresolver_manager.create_resolver(ldap_data)

        # Create SQL UserIdResolver
        sql_data = data.sql_resolver

        sql_resolver = self.testcase.useridresolver_manager.create_resolver(sql_data)
        self.testcase.useridresolver_manager.close()

        # Create realm for all resolvers
        realm_name1 = "SE_scenario01_realm1"
        realm_name2 = "SE_scenario01_realm2"

        self.testcase.realm_manager.create(realm_name1, [ldap_resolver])
        self.testcase.realm_manager.create(realm_name2, [sql_resolver])
        self.testcase.realm_manager.close()

        self._announce_test(
            "2. In Management Webinterface, check that all users are visible"
        )

        self.check_users(realm_name1, ldap_data)
        self.check_users(realm_name2, sql_data)

        self._announce_test("3. eToken.xml ueber das Webinterface importieren")

        token_import_aladdin = TokenImportAladdin(self.testcase.manage_ui)

        aladdin_xml_path = os.path.join(
            self.testcase.manage_ui.test_data_dir, "aladdin.xml"
        )
        token_import_aladdin.do_import(file_path=aladdin_xml_path)

        serial_token_bach = "oath137332"
        test1_realm = realm_name1.lower()

        self._announce_test("4. Im Management Webinterface nun eine Policy anlegen")

        Policy(
            self.testcase.manage_ui,
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
        selfservice.login("mozart", "Test123!", test1_realm)
        otp_pin = 666
        result = selfservice.enroll_motp(
            motp_key=motp_key,
            motp_pin=motp_pin,
            pin=otp_pin,
            description="Selenium self enrolled",
        )
        selfservice.clear_session()
        serial_token_mozart = result["detail"]["serial"]
        assert serial_token_mozart, (
            "Failed to enroll mOTP token for user mozart: %s" % result["detail"]
        )

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
            selfservice.clear_session()

        self._announce_test("10. Authentisierung der 4 Benutzer ###")
        validate = Validate(
            self.testcase.http_protocol,
            self.testcase.http_host,
            self.testcase.http_port,
            self.testcase.http_username,
            self.testcase.http_password,
        )

        # seed is also set in testdata/aladdin.xml
        seed_oath137332 = "ff06df50017d3b981cfbc4ec4d374040164d8d19"
        seed_oath137332_bin = binascii.unhexlify(seed_oath137332)

        # Validate HOTP Token - bach
        hotp = HmacOtp()
        for counter in range(0, 4):
            otp = "bachnewpin" + hotp.generate(counter=counter, key=seed_oath137332_bin)
            access_granted, _ = validate.validate(
                user="bach@" + test1_realm, password=otp
            )
            assert access_granted, (
                "OTP: " + otp + " for user " + "bach@" + test1_realm + " returned False"
            )
        access_granted, _ = validate.validate(
            user="bach@" + test1_realm, password="1234111111"
        )
        assert not access_granted, "OTP: 1234111111 should be False for user bach"

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
        assert not access_granted, (
            "OTP: randominvalidpin should be False for user beethoven"
        )
        # correct PIN + wrong password = fail
        access_granted, _ = validate.validate(
            user="beethoven@" + test1_realm,
            password="beethovennewpin" + "wrongpassword",
        )
        assert not access_granted, "beethoven should not auth with wrong token password"
        # Password without pin = fail
        access_granted, _ = validate.validate(
            user="beethoven@" + test1_realm, password=beethoven_token_password
        )
        assert not access_granted, "beethoven should not auth with password and old pin"
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
        motp_otp = calculate_motp(epoch=current_epoch, key=motp_key, pin=motp_pin)

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

        selfservice.login("mozart", "Test123!", test1_realm)
        selfservice.set_motp_pin(serial_token_mozart, new_motp_pin)
        selfservice.clear_session()

        time.sleep(10)  # otherwise next mOTP value might not be valid

        current_epoch = time.time()
        motp_otp = calculate_motp(epoch=current_epoch, key=motp_key, pin=new_motp_pin)
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
        otp = "bachnewpin" + hotp.generate(counter=counter, key=seed_oath137332_bin)
        access_granted, _ = validate.validate(user="bach@" + test1_realm, password=otp)
        assert not access_granted, "OTP: %s should be False for user bach" % otp

        selfservice.login("bach", "Test123!", test1_realm)

        otp1 = hotp.generate(counter=counter + 1, key=seed_oath137332_bin)
        otp2 = hotp.generate(counter=counter + 2, key=seed_oath137332_bin)

        selfservice.resync_token(serial_token_bach, otp1, otp2)
        selfservice.clear_session()

        # Should be able to authenticate again
        otp = "bachnewpin" + hotp.generate(counter=counter + 3, key=seed_oath137332_bin)
        access_granted, _ = validate.validate(user="bach@" + test1_realm, password=otp)
        assert access_granted, "OTP: %s should be True for user bach" % otp

        self._announce_test(
            "13. Benutzer beethoven deaktiviert seinen Token im Selfservice portal und versucht sich anzumelden."
        )

        selfservice.login("beethoven", "Test123!", test1_realm)
        selfservice.disable_token(serial_token_beethoven)
        selfservice.clear_session()

        # beethoven should be unable to authenticate
        access_granted, _ = validate.validate(
            user="beethoven@" + test1_realm,
            password="beethovennewpin" + beethoven_token_password,
        )
        assert not access_granted, (
            "OTP: beethovennewpin should be False for user beethoven"
        )

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
        assert access_granted, (
            "OTP: beethovennewpin should be able to authenticate after re-enabled token."
        )

    def check_users(self, realm, data):
        expected_users = data["expected_users"]
        users = data["users"]

        found_users = self.testcase.manage_ui.user_view.get_num_users(realm)

        assert expected_users == found_users, (
            "Not the expected number of users in realm %s: Expecting %s but found %s"
            % (realm, expected_users, found_users)
        )

        for user in users:
            assert self.testcase.manage_ui.user_view.user_exists(user), (
                "User '%s' should exist in realm %s" % (user, realm)
            )
            break


class UserServiceApi:
    """This class is used by test_scenario01 to make http requests to the
    userservice API.
    """

    def __init__(self, http_protocol, http_host, http_port):
        """Initializes the class with the required values to call"""
        self.base_url = http_protocol + "://" + http_host
        if http_port:
            self.base_url += ":" + http_port
        self._login_response: requests.Response | None = None

    def login(self, user, password, realm=None):
        """Login to the suserservice API with user and password"""
        if realm:
            login_user = "%s@%s" % (user, realm)
        else:
            login_user = user
        url = self.base_url + "/userservice/login"
        params = {"username": login_user, "password": password}
        r = requests.post(url, params=params, verify=False)

        assert r.status_code == 200, (
            "Failed to login to self service, status code: %s, response: %s"
            % (r.status_code, r.text)
        )

        assert r.cookies.get("user_selfservice") is not None, (
            "No session cookie found in login response, response: %s" % r.text
        )

        self._login_response = r

    def clear_session(self):
        self._login_response = None

    def set_pin(self, serial, pin):
        """Set the pin for token"""
        params = {
            "userpin": pin,
            "serial": serial,
        }
        r = self._make_userservice_request("setpin", params)
        assert r.json()["result"]["value"]["set userpin"] == 1, (
            "Failed to set pin for token, params: %s, response: %s" % (params, r.text)
        )

    def enroll_motp(self, motp_key, motp_pin, pin, description):
        """Enroll a MOTP token for the logged in user"""
        params = {
            "type": "motp",
            "otpkey": motp_key,
            "otppin": motp_pin,
            "pin": pin,
            "description": description,
        }
        r = self._make_userservice_request("enroll", params)
        assert r.json()["result"]["value"] is True, (
            "Failed to enroll mOTP token, params: %s, response: %s" % (params, r.text)
        )

        return r.json()

    def set_motp_pin(self, serial, motp_pin):
        """Set the motp pin for a MOTP token"""
        params = {
            "pin": motp_pin,
            "serial": serial,
        }
        r = self._make_userservice_request("setmpin", params)
        assert r.json()["result"]["value"]["set userpin"] == 1, (
            "Failed to set mOTP pin for token, params: %s, response: %s"
            % (params, r.text)
        )

    def resync_token(self, serial, otp1, otp2):
        """Resync a token"""
        params = {
            "serial": serial,
            "otp1": otp1,
            "otp2": otp2,
        }
        r = self._make_userservice_request("resync", params)
        assert r.json()["result"]["value"]["resync Token"] is True, (
            "Failed to resync token, params: %s, response: %s" % (params, r.text)
        )

    def disable_token(self, serial):
        """Disable a token"""
        params = {
            "serial": serial,
        }
        r = self._make_userservice_request("disable", params)
        assert r.json()["result"]["value"]["disable token"] == 1, (
            "Failed to disable token %s, response: %s" % (serial, r.text)
        )

    def _make_userservice_request(self, endpoint, params):
        """Make a request to the userservice endpoint with the given params"""
        assert self._login_response is not None, (
            "No login response found, did you call login() before making a request?"
        )
        params["session"] = self._login_response.cookies.get("user_selfservice")

        url = self.base_url + "/userservice/" + endpoint

        items = self._login_response.cookies.items()
        cookies_string = "; ".join([f"{name}={value}" for name, value in items])
        headers: dict[str, str] = {"Cookie": cookies_string}

        r = requests.post(url, params=params, headers=headers, verify=False)
        assert r.status_code == 200, (
            "Failed to make request to userservice endpoint %s, params: %s, status code: %s, response: %s"
            % (endpoint, params, r.status_code, r.text)
        )

        assert r.json()["result"]["status"] is True, (
            "Request to userservice endpoint %s, params %s, response: %s did not return status True"
            % (endpoint, params, r.text)
        )

        return r

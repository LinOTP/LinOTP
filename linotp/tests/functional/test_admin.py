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


""" """

import json
import logging
from unittest.mock import Mock, patch

from flask.testing import FlaskClient

from linotp.model.local_admin_user import LocalAdminResolver
from linotp.model.reporting import Reporting
from linotp.tests import TestController
from linotp.tests.functional.test_reporting import DBSession

log = logging.getLogger(__name__)


class TestAdminController(TestController):
    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        """
        Reset the LinOTP server by deleting all tokens/realms/resolvers
        """

        # Ensure that our session cookie is reset
        cookie_jar = []
        for cookie in self.client._cookies.values():
            cookie_jar.append(cookie)

        for cookie in cookie_jar:
            self.client.delete_cookie(
                cookie.key, path=cookie.path, domain=cookie.domain
            )

        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_policies()
        TestController.tearDown(self)

    def init_token(self, params: dict):
        """Creates the token

        Args:
            params (dict): parameters to init the token with

        Returns:
            str: token serial
        """
        response = self.make_admin_request("init", params=params)
        response_json = response.json
        assert response_json["result"]["value"], response_json
        serial = response_json["detail"]["serial"]
        return serial

    def createToken3(self):
        parameters = {
            "serial": "003e808e",
            "otpkey": "e56eb2bcbafb2eea9bce9463f550f86d587d6c71",
            "description": "my EToken",
        }
        return self.init_token(parameters)

    def createToken2(self, serial="F722362"):
        parameters = {
            "serial": serial,
            "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
            "description": "TestToken" + serial,
        }
        return self.init_token(parameters)

    def createTokenSHA256(self, serial="SHA256"):
        parameters = {
            "serial": serial,
            "otpkey": "47F6EE05C06FA1CDB8B9AADF520FCF86221DB0A107731452AE140EED0EB518B0",
            "type": "hmac",
            "hashlib": "sha256",
        }
        return self.init_token(parameters)

    def createSPASS(self, serial="LSSP0001", pin="1test@pin!42"):
        parameters = {"serial": serial, "type": "spass", "pin": pin}
        return self.init_token(parameters)

    def createToken(self):
        parameters = {
            "serial": "F722362",
            "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
            "user": "root",
            "pin": "pin",
            "description": "TestToken1",
        }
        self.init_token(parameters)

        parameters = {
            "serial": "F722363",
            "otpkey": "AD8EABE235FC57C815B26CEF3709075580B4473880B44738",
            "user": "root",
            "pin": "pin",
            "description": "TestToken2",
        }
        self.init_token(parameters)

        parameters = {
            "serial": "F722364",
            "otpkey": "AD8EABE235FC57C815B26CEF37090755",
            "user": "root",
            "pin": "pin",
            "description": "TestToken3",
        }
        self.init_token(parameters)

        # test the update
        parameters = {
            "serial": "F722364",
            "otpkey": "AD8EABE235FC57C815B26CEF37090755",
            "user": "root",
            "pin": "Pin3",
            "description": "TestToken3",
        }
        self.init_token(parameters)

    def removeTokenByUser(self, user):
        # final delete all tokens of user root
        parameters = {
            "user": user,
        }

        response = self.make_admin_request("remove", params=parameters)
        return response

    def showToken(self):
        response = self.make_admin_request("show")
        return response

    def test_0000_000(self):
        self.delete_all_token()

    def test_show(self):
        """test the admin show interface for json and csv response"""

        self.createToken()

        # ------------------------------------------------------------------ --

        # verify the json response

        params = {
            "serial": "F722362",
        }

        response = self.make_admin_request("show", params=params)

        jresp = response.json

        tokens = jresp["result"]["value"]["data"]
        assert len(tokens) == 1

        token = tokens[0]
        assert token["LinOtp.TokenSerialnumber"] == "F722362"

        # ------------------------------------------------------------------ --

        # verify the csv response

        params = {"serial": "F722362", "outform": "csv"}
        response = self.make_admin_request("show", params=params)

        counter = 0
        serial_column = 0
        for line in response.body.split("\n"):
            if not line:
                continue

            entries = line.split(";")

            # cvs has a header line
            if counter == 0:
                assert "'LinOtp.TokenSerialnumber'" in line

                for entry in entries:
                    if entry.strip() == "'LinOtp.TokenSerialnumber'":
                        break
                    serial_column += 1

            # and one data line
            if counter == 1:
                assert entries[serial_column].strip() == "'F722362'"

            # but no more than one line
            assert counter < 2

            counter += 1

    def test_set(self):
        self.createToken()

        parameters = {
            "serial": "F722364",
            "pin": "pin",
            "MaxFailCount": "20",
            "SyncWindow": "400",
            "OtpLen": "6",
            "hashlib": "sha256",
        }

        response = self.make_admin_request("set", params=parameters)
        # log.debug("response %s",response)
        assert '"set pin": 1' in response, response
        assert '"set SyncWindow": 1' in response, response
        assert '"set OtpLen": 1' in response, response
        assert '"set MaxFailCount": 1' in response, response
        assert '"set hashlib": 1' in response, response

        parameters = {
            "user": "root",
            "pin": "pin",
            "MaxFailCount": "20",
            "SyncWindow": "400",
            "OtpLen": "6",
        }

        response = self.make_admin_request("set", params=parameters)
        # log.error("response %s",response)
        assert '"set pin": 3' in response, response
        assert '"set SyncWindow": 3' in response, response
        assert '"set OtpLen": 3' in response, response
        assert '"set MaxFailCount": 3' in response, response

        self.delete_token("F722362")
        response = self.removeTokenByUser("root")

        assert response.json["result"]["status"], response
        assert response.json["result"]["value"] == 2, response

    def test_remove(self):
        self.createToken()
        response = self.removeTokenByUser("root")
        log.debug(response)

    def test_userlist(self):
        """
        test the admin/userlist for iteration reply

        scope of test:
        - stabilty of the userlist api
        """
        # first standard query for users
        parameters = {"username": "*"}
        response = self.make_admin_request("userlist", params=parameters)
        assert '"status": true,' in response, response
        resp = json.loads(response.body)
        values = resp.get("result", {}).get("value", [])
        assert len(values) > 15, "not enough users returned %r" % resp

    def test_userlist_paged(self):
        """
        test the admin/userlist for iteration paging

        This test is expected to fail because paging is not yet implemented in
        the flask port4

        scope of test:
        - support of result paging

        """

        # paged query
        parameters = {"username": "*", "rp": 5, "page": 2}
        response = self.make_admin_request("userlist", params=parameters)
        assert '"status": true,' in response, response
        resp = json.loads(response.body)

        values = resp.get("result", {}).get("value", [])
        assert len(values) == parameters["rp"], resp

        num = parameters["rp"] * (parameters["page"] + 1)
        queried = resp.get("result", {}).get("queried", 0)
        assert queried == num, resp

        # test for optional pagesize, which falls back to the pagesize of 16
        parameters = {"username": "*", "page": 0}
        response = self.make_admin_request("userlist", params=parameters)
        assert '"status": true,' in response, response
        resp = json.loads(response.body)
        values = resp.get("result", {}).get("value", [])
        assert len(values) == 16, resp

        # test for ValueError Exception if page or rp is not of int
        # though the returned data is a json response
        parameters = {"username": "*", "page": "page"}
        response = self.make_admin_request("userlist", params=parameters)
        # check that status is false
        assert '"status": false,' in response, response
        # check for valid json
        resp = json.loads(response.body)
        value = resp.get("result", {}).get("error", {}).get("code", 0)
        assert value == 9876, resp

        return

    def test_db_for_default_realm_and_resolver(self):
        """
        Tests, after db initialiazation,
        that default admin_realm and default resolver are existing
        """

        response = self.make_system_request("getResolvers")
        assert response.json["result"]["status"]
        assert "LinOTP_local_admins" in response.json["result"]["value"]

        response = self.make_system_request("getRealms")
        assert response.json["result"]["status"]
        assert "linotp_admins" in response.json["result"]["value"]

    def test_enable(self):
        self.createToken()
        parameters = {"serial": "F722364"}
        response = self.make_admin_request("disable", params=parameters)
        assert '"value": 1' in response, response

        parameters = {"serial": "F722364"}
        response = self.make_admin_request("show", params=parameters)

        assert "false" in response, response
        assert "F722364" in response, response

        parameters = {"serial": "F722364"}
        response = self.make_admin_request("enable", params=parameters)
        assert '"value": 1' in response, response

        parameters = {"serial": "F722364"}
        response = self.make_admin_request("show", params=parameters)

        assert "true" in response, response
        assert "F722364" in response, response

        self.removeTokenByUser("root")

    def test_resync(self):
        self.createToken()

        # test resync of token 2
        parameters = {"user": "root", "otp1": "359864", "otp2": "348449"}
        response = self.make_admin_request("resync", params=parameters)
        # log.error("response %s\n",response)
        assert '"value": false' in response, response

        parameters = {"user": "root", "otp1": "359864", "otp2": "348448"}
        response = self.make_admin_request("resync", params=parameters)
        # Test response...
        log.error("response %s\n", response)
        assert '"value": true' in response, response

        self.delete_token("F722364")
        self.delete_token("F722363")
        self.delete_token("F722362")

    def test_resync_sha256(self):
        self.createTokenSHA256(serial="SHA256")

        parameters = {"serial": "SHA256", "otp1": "778729", "otp2": "094573"}
        response = self.make_admin_request("resync", params=parameters)

        assert '"value": true' in response, response
        self.delete_token("SHA256")

    def test_setPin(self):
        self.createToken3()

        # test resync of token 2
        parameters = {
            "serial": "003e808e",
            "userpin": "123456",
            "sopin": "123234",
        }
        response = self.make_admin_request("setPin", params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        assert '"set sopin": 1' in response, response
        assert '"set userpin": 1' in response, response

        self.delete_token("003e808e")

    def test_assign_tokens(self):
        """Verify the admin/assign api suports the handling of multiple serials."""

        # ----------------------------------------------------------------- --

        # create a set of tokens and query their serials into a list

        self.createToken()
        response = self.make_admin_request("show")

        data = response.json["result"]["value"]["data"]

        serials = []
        fake_serials = []
        for entry in data:
            serials.append(entry["LinOtp.TokenSerialnumber"])
            fake_serials.append("fake_" + entry["LinOtp.TokenSerialnumber"])

        # ----------------------------------------------------------------- --

        # assign the tokens to the root user within one request

        params = {"serial[]": serials, "user": "root"}
        response = self.make_admin_request("assign", params=params)

        assert response.json["result"]["value"]
        assert response.json["result"]["status"]

        # now try to assign the tokens of non existing token within one request

        params = {"serial[]": fake_serials, "user": "root"}
        response = self.make_admin_request("assign", params=params)

        assert response.json["result"]["status"] is False
        assert response.json["result"]["error"]["code"] == 1102

        # ----------------------------------------------------------------- --

        # submit the delete of the tokens within one request

        params = {"serial[]": serials}
        response = self.make_admin_request("remove", params=params)

        jresp = response.json
        assert jresp["result"]["status"]
        assert jresp["result"]["value"] == len(serials)

        # submit the delete of the tokens within one request

        params = {"serial[]": fake_serials}
        response = self.make_admin_request("remove", params=params)

        jresp = response.json
        assert jresp["result"]["status"] is False
        assert jresp["result"]["error"]["code"] == 1102

    def test_assign(self):
        serial = self.createToken2(serial="F722362")

        respRealms = self.make_system_request("getRealms", params=None)
        log.debug(respRealms)

        # test initial assign
        parameters = {"serial": serial, "user": "root"}
        response = self.make_admin_request("assign", params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        assert '"value": true' in response, response

        # test initial assign update
        parameters = {"serial": serial, "user": "root", "pin": "NewPin"}
        response = self.make_admin_request("assign", params=parameters)
        # log.error("response %s\n",response)
        # Test response...
        assert response.json["result"]["value"], response

        response = self.make_admin_request("show")
        # log.error("response %s\n",response)
        assert len(response.json["result"]["value"]["data"]) == 1, response
        assert response.json["result"]["value"]["data"][0]["LinOtp.Userid"] == "0", (
            response
        )

        # test initial assign update
        parameters = {"serial": serial, "user": "root"}
        response = self.make_admin_request("unassign", params=parameters)
        # log.error("response %s\n",response)
        assert '"value": true' in response, response

        # test wrong assign
        parameters = {"serial": serial, "user": "NoBody"}
        response = self.make_admin_request("assign", params=parameters)
        # log.error("response %s\n",response)
        assert "getUserId failed: no user >NoBody< found!" in response, response

        response = self.make_admin_request("show")
        # log.error("response %s\n",response)
        assert '"User.userid": "",' in response, response

        self.delete_token(serial)

    def test_assign_umlaut(self):
        self.createTokenSHA256(serial="umlauttoken")

        parameters = {"serial": "umlauttoken", "user": "kölbel"}
        response = self.make_admin_request("assign", params=parameters)
        assert '"value": true' in response, response

        self.delete_token("umlauttoken")
        return

    def test_losttoken_email(self):
        """
        test for losttoken callback - to support email tokens as replacement

        test with user hans, who has an email address
        - is the old one deactivated
        - is the new one active
        - is the new one of type 'email'

        remark:
            other losttoken tests depend on policy definition and are
            part of the test_policy.py

        """
        token_name = "verloren"
        self.createTokenSHA256(serial=token_name)

        parameters = {"serial": token_name, "user": "hans"}
        response = self.make_admin_request("assign", params=parameters)
        assert '"value": true' in response, response

        parameters = {"serial": token_name, "type": "email"}
        response = self.make_admin_request("losttoken", params=parameters)
        assert '"status": true' in response, response

        resp = json.loads(response.body)
        lost_token_name = resp.get("result", {}).get("value", {}).get("serial")

        # first check if old token is not active
        parameters = {"serial": token_name}
        response = self.make_admin_request("show", params=parameters)
        assert '"status": true' in response, response
        resp = json.loads(response.body)
        data = resp.get("result", {}).get("value", {}).get("data", [{}])[0]
        active = data.get("LinOtp.Isactive", True)
        assert not active, response
        user = data.get("User.username", "")
        assert user == "hans", response

        # second check if new token is active
        parameters = {"serial": lost_token_name}
        response = self.make_admin_request("show", params=parameters)
        assert '"status": true' in response, response
        resp = json.loads(response.body)
        data = resp.get("result", {}).get("value", {}).get("data", [{}])[0]
        active = data.get("LinOtp.Isactive", False)
        assert active, response

        user = data.get("User.username", "")
        assert user == "hans", response

        ttype = data.get("LinOtp.TokenType", "")
        assert ttype == "email", response

        self.delete_token(token_name)
        self.delete_token(lost_token_name)
        return

    def test_losttoken_sms(self):
        """
        test for losttoken callback - to support sms tokens as replacement

        test with user hans, who has a mobile number
        - is the old one deactivated
        - is the new one active
        - is the new one of type 'sms'

        remark:
            other losttoken tests depend on policy definition and are
            part of the test_policy.py

        """
        token_name = "verloren"
        self.createTokenSHA256(serial=token_name)

        parameters = {"serial": token_name, "user": "hans"}
        response = self.make_admin_request("assign", params=parameters)
        assert '"value": true' in response, response

        parameters = {"serial": token_name, "type": "sms"}
        response = self.make_admin_request("losttoken", params=parameters)
        assert '"status": true' in response, response

        resp = json.loads(response.body)
        lost_token_name = resp.get("result", {}).get("value", {}).get("serial")

        # first check if old token is not active
        parameters = {"serial": token_name}
        response = self.make_admin_request("show", params=parameters)
        assert '"status": true' in response, response
        resp = json.loads(response.body)
        data = resp.get("result", {}).get("value", {}).get("data", [{}])[0]
        active = data.get("LinOtp.Isactive", True)
        assert not active, response
        user = data.get("User.username", "")
        assert user == "hans", response

        # second check if new token is active
        parameters = {"serial": lost_token_name}
        response = self.make_admin_request("show", params=parameters)
        assert '"status": true' in response, response
        resp = json.loads(response.body)
        data = resp.get("result", {}).get("value", {}).get("data", [{}])[0]
        active = data.get("LinOtp.Isactive", False)
        assert active, response

        user = data.get("User.username", "")
        assert user == "hans", response

        ttype = data.get("LinOtp.TokenType", "")
        assert ttype == "sms", response

        self.delete_token(token_name)
        self.delete_token(lost_token_name)
        return

    def test_losttoken_fail(self):
        """
        test for losttoken callback - which might fail

        test with user horst, who has no mobile number and no email
        - is the old one deactivated
        - is the new one active
        - is the new one of type 'pw'

        remark:
            other losttoken tests depend on policy definition and are
            part of the test_policy.py
        """
        token_name = "verloren"
        user_name = "horst"

        self.createTokenSHA256(serial=token_name)

        parameters = {"serial": token_name, "user": user_name}
        response = self.make_admin_request("assign", params=parameters)
        assert '"value": true' in response, response

        parameters = {"serial": token_name, "type": "sms"}
        response = self.make_admin_request("losttoken", params=parameters)
        assert '"status": true' in response, response

        resp = json.loads(response.body)
        lost_token_name = resp.get("result", {}).get("value", {}).get("serial")

        # first check if old token is not active
        parameters = {"serial": token_name}
        response = self.make_admin_request("show", params=parameters)
        assert '"status": true' in response, response
        resp = json.loads(response.body)
        data = resp.get("result", {}).get("value", {}).get("data", [{}])[0]
        active = data.get("LinOtp.Isactive", True)
        assert not active, response
        user = data.get("User.username", "")
        assert user == user_name, response

        # second check if new token is active
        parameters = {"serial": lost_token_name}
        response = self.make_admin_request("show", params=parameters)
        assert '"status": true' in response, response
        resp = json.loads(response.body)
        data = resp.get("result", {}).get("value", {}).get("data", [{}])[0]
        active = data.get("LinOtp.Isactive", False)
        assert active, response

        user = data.get("User.username", "")
        assert user == user_name, response

        ttype = data.get("LinOtp.TokenType", "")
        assert ttype == "pw", response

        self.delete_token(token_name)
        self.delete_token(lost_token_name)
        return

    def test_losttoken_spass(self):
        """
        test for losttoken callback - to register replacement for lost spass

        test with user hans, who has a spass
        - is the old one deactivated
        - is the new one active
        - is the new one of type 'pw'
        - does the new password work

        remark:
            other losttoken tests depend on policy definition and are
            part of the test_policy.py

        """
        token_name = "verloren"
        spass_pin = "initial_pin"

        new_serial = self.createSPASS(serial=token_name, pin=spass_pin)
        assert token_name == new_serial

        parameters = {"serial": token_name, "user": "hans"}
        response = self.make_admin_request("assign", params=parameters)
        assert '"value": true' in response, response

        # check if this spass validates
        response = self.make_validate_request(
            "check_s", params={"serial": token_name, "pass": spass_pin}
        )
        assert '"value": true' in response, response

        parameters = {"serial": token_name, "type": "spass"}
        response = self.make_admin_request("losttoken", params=parameters)
        assert '"status": true' in response, response

        resp = json.loads(response.body)
        temp_token_name = resp.get("result", {}).get("value", {}).get("serial")
        temp_token_pass = resp.get("result", {}).get("value", {}).get("password")

        # first check if old token is not active
        parameters = {"serial": token_name}
        response = self.make_admin_request("show", params=parameters)
        assert '"status": true' in response, response
        resp = json.loads(response.body)
        data = resp.get("result", {}).get("value", {}).get("data", [{}])[0]
        active = data.get("LinOtp.Isactive", True)
        assert not active, response
        user = data.get("User.username", "")
        assert user == "hans", response

        # second check if new token is active and properly assigned
        parameters = {"serial": temp_token_name}
        response = self.make_admin_request("show", params=parameters)
        assert '"status": true' in response, response
        resp = json.loads(response.body)
        data = resp.get("result", {}).get("value", {}).get("data", [{}])[0]
        active = data.get("LinOtp.Isactive", False)
        assert active, response

        user = data.get("User.username", "")
        assert user == "hans", response

        ttype = data.get("LinOtp.TokenType", "")
        assert ttype == "pw", response

        # finally, check if old spass is blocked and new one works without
        # previous pin
        response = self.make_validate_request(
            "check_s", params={"serial": token_name, "pass": spass_pin}
        )
        assert '"value": false' in response, response
        response = self.make_validate_request(
            "check_s",
            params={"serial": temp_token_name, "pass": temp_token_pass},
        )
        assert '"value": true' in response, response

        # all fine, clean up
        self.delete_token(token_name)
        self.delete_token(temp_token_name)
        return

    def test_enroll_umlaut(self):
        parameters = {
            "serial": "umlauttoken",
            "otpkey": "47F6EE05C06FA1CDB8B9AADF520FCF86221DB0A107731452AE140EED0EB518B0",
            "type": "hmac",
            "hashlib": "sha256",
            "user": "kölbel",
        }
        response = self.make_admin_request("init", params=parameters)
        assert '"value": true' in response, response
        self.delete_token("umlauttoken")

    def test_check_serial(self):
        """
        Checking what happens if serial exists
        """
        response = self.make_admin_request(
            "init", params={"serial": "unique_serial_001", "type": "spass"}
        )

        assert '"value": true' in response, response

        response = self.make_admin_request(
            "check_serial", params={"serial": "unique_serial_002"}
        )

        assert '"unique": true' in response, response
        assert '"new_serial": "unique_serial_002"' in response, response

        response = self.make_admin_request(
            "check_serial", params={"serial": "unique_serial_001"}
        )

        assert '"unique": false' in response, response
        assert '"new_serial": "unique_serial_001_01"' in response, response

    def test_setPin_empty(self):
        """
        Testing setting empty PIN and SO PIN
        """
        response = self.make_admin_request(
            "init", params={"serial": "setpin_01", "type": "spass"}
        )

        assert '"value": true' in response, response

        response = self.make_admin_request("setPin", params={"serial": "setpin_01"})

        assert '"status": false' in response, response
        assert '"code": 77' in response, response

        response = self.make_admin_request(
            "setPin", params={"serial": "setpin_01", "sopin": "geheim"}
        )

        assert '"set sopin": 1' in response, response

    def test_set_misc(self):
        """
        Setting CountWindow, timeWindow, timeStep, timeShift
        """
        response = self.make_admin_request(
            "init", params={"serial": "token_set_misc", "type": "spass"}
        )

        assert '"value": true' in response, response

        response = self.make_admin_request(
            "set",
            params={
                "serial": "token_set_misc",
                "CounterWindow": "100",
                "timeWindow": "180",
                "timeStep": "30",
                "timeShift": "0",
            },
        )

        assert 'set CounterWindow": 1' in response, response
        assert '"set timeShift": 1' in response, response
        assert '"set timeWindow": 1' in response, response
        assert '"set timeStep": 1' in response, response

    def test_set_count(self):
        """
        Setting countAuth, countAuthMax, countAuthSucces countAuthSuccessMax
        """
        response = self.make_admin_request(
            "init", params={"serial": "token_set_count", "type": "spass"}
        )

        assert '"value": true' in response, response

        response = self.make_admin_request(
            "set",
            params={
                "serial": "token_set_count",
                "countAuth": "10",
                "countAuthMax": "180",
                "countAuthSuccess": "0",
                "countAuthSuccessMax": "10",
            },
        )

        assert '"set countAuthSuccess": 1' in response, response
        assert '"set countAuthSuccessMax": 1' in response, response
        assert '"set countAuth": 1' in response, response
        assert '"set countAuthMax": 1' in response, response

        return

    def test_set_validity(self):
        """
        Setting validity period
        """
        response = self.make_admin_request(
            "init", params={"serial": "token_set_validity", "type": "spass"}
        )

        assert '"value": true' in response, response

        response = self.make_admin_request(
            "set",
            params={
                "serial": "token_set_validity",
                "validityPeriodStart": "2012-10-12",
                "validityPeriodEnd": "2013-12-30",
            },
        )

        assert '"status": false' in response, response
        assert "does not match format" in response, response

        response = self.make_admin_request(
            "set",
            params={
                "serial": "token_set_validity",
                "validityPeriodStart": "12/12/12 10:00",
                "validityPeriodEnd": "30/12/13 13:00",
            },
        )

        assert '"status": true' in response, response
        assert '"set validityPeriodStart": 1' in response, response
        assert '"set validityPeriodEnd": 1' in response, response

    def test_set_validity_interface(self):
        """
        Setting validity period via admin/setValidity interface
        """

        token_serial_1 = "token_set_validity1"
        token_serial_2 = "token_set_validity2"

        response = self.make_admin_request(
            "init", params={"serial": token_serial_1, "type": "spass"}
        )

        assert '"value": true' in response, response

        response = self.make_admin_request(
            "init", params={"serial": token_serial_2, "type": "spass"}
        )

        assert '"value": true' in response, response

        response = self.make_admin_request(
            "setValidity",
            params={
                "tokens": [token_serial_1, token_serial_2],
                "validityPeriodStart": "2012-10-12",
                "validityPeriodEnd": "2013-12-30",
            },
            content_type="application/json",
        )

        assert '"status": false' in response, response
        msg = "invalid literal for int() with base 10: '2012-10-12'"
        assert msg in response, response

        response = self.make_admin_request(
            action="setValidity",
            params={
                "tokens": [
                    token_serial_1,
                    token_serial_2,
                ],
                "validityPeriodStart": "1355302800",
                "validityPeriodEnd": "1355310000",
            },
            content_type="application/json",
        )

        assert response.json["result"]["status"], (
            'Expected response.result.status to be True in response: "{}"'.format(
                response.json
            )
        )

        assert token_serial_1 in response.json["result"]["value"], (
            'Expected response.result.value to contain token id "{}" in response: "{}"'.format(
                token_serial_1, response.json
            )
        )

        assert token_serial_2 in response.json["result"]["value"], (
            'Expected response.result.value to contain token id "{}" in response: "{}"'.format(
                token_serial_2, response.json
            )
        )

    def test_set_empty(self):
        """
        Running set without parameter
        """
        response = self.make_admin_request(
            "init", params={"serial": "token_set_empty", "type": "spass"}
        )

        assert '"value": true' in response, response

        response = self.make_admin_request(
            "set",
            params={
                "serial": "token_set_empty",
            },
        )

        assert '"status": false' in response, response
        assert '"code": 77' in response, response

    def test_copy_token_pin(self):
        """
        testing copyTokenPin

        We create one token with a PIN and authenticate.
        Then we copy the PIN to another token and try to authenticate.
        """
        response = self.make_admin_request(
            "init",
            params={"serial": "copy_token_1", "type": "spass", "pin": "1234"},
        )

        assert '"value": true' in response, response

        response = self.make_validate_request(
            "check_s", params={"serial": "copy_token_1", "pass": "1234"}
        )

        assert '"value": true' in response, response

        response = self.make_admin_request(
            "init",
            params={
                "serial": "copy_token_2",
                "type": "spass",
                "pin": "otherPassword",
            },
        )

        assert '"value": true' in response, response

        response = self.make_validate_request(
            "check_s",
            params={"serial": "copy_token_2", "pass": "otherPassword"},
        )

        assert '"value": true' in response, response

        response = self.make_admin_request(
            "copyTokenPin",
            params={"from": "copy_token_1", "to": "copy_token_2"},
        )

        assert '"value": true' in response, response

        response = self.make_validate_request(
            "check_s", params={"serial": "copy_token_2", "pass": "1234"}
        )

        assert '"value": true' in response, response

    def test_copy_token_user(self):
        """
        testing copyTokenUser
        """
        response = self.make_admin_request(
            "init",
            params={
                "serial": "copy_user_1",
                "type": "spass",
                "pin": "copyTokenUser",
                "user": "root",
            },
        )

        assert '"value": true' in response, response

        response = self.make_validate_request(
            "check", params={"user": "root", "pass": "copyTokenUser"}
        )

        assert '"value": true' in response, response

        response = self.make_admin_request(
            "init",
            params={
                "serial": "copy_user_2",
                "type": "spass",
                "pin": "unknownSecret",
            },
        )

        assert '"value": true' in response, response

        response = self.make_admin_request(
            "copyTokenUser",
            params={"from": "copy_user_1", "to": "copy_user_2"},
        )

        assert '"value": true' in response, response

        response = self.make_validate_request(
            "check", params={"user": "root", "pass": "unknownSecret"}
        )

        assert '"value": true' in response, response

    def test_enroll_token_twice(self):
        """
        test to enroll another token with the same serial number
        """
        response = self.make_admin_request(
            "init",
            params={"serial": "token01", "type": "hmac", "otpkey": "123456"},
        )

        assert '"value": true' in response, response

        # enrolling the token of the same type is possible
        response = self.make_admin_request(
            "init",
            params={"serial": "token01", "type": "hmac", "otpkey": "567890"},
        )

        assert '"value": true' in response, response

        # enrolling of another type is not possible
        response = self.make_admin_request(
            "init",
            params={"serial": "token01", "type": "spass", "otpkey": "123456"},
        )

        assert "already exist with type" in response, response
        assert "Can not initialize token with new type" in response, response

        # clean up
        response = self.make_admin_request("remove", params={"serial": "token01"})

        assert '"status": true' in response, response

    def test_audit_for_actions(self):
        # Untested so far: resync
        audit_mapping = {
            "action": 4,
            "success": 5,
            "serial": 6,
            "type": 7,
            "user": 8,
            "realm": 9,
        }
        params = {
            "serial": "serial_1",
            "type": "pw",
            "otpkey": "123",
            "user": "root",
            "realm": "mydefrealm",
        }

        expected_audit = {
            "success": "1",
            "serial": params["serial"],
            "type": params["type"],
            "user": params["user"],
            "realm": params["realm"],
        }
        expected_audit_faulty = {
            "success": "0",
            "serial": f"{params['serial']}",
            "type": "",
            "user": "",
            "realm": "",
        }

        # test init
        action = "init"
        self.init_token(params)

        audit_entry = self.get_last_audit_entry()
        assert f"admin/{action}" == audit_entry[audit_mapping["action"]]
        for key, expected in expected_audit.items():
            actual = audit_entry[audit_mapping[key]]
            assert expected == actual, actual
        self.delete_all_token()

        # Test other:
        for action, values in {
            "remove": {
                "request_params": {"serial": params["serial"]},
                "expected_audit": expected_audit,
                "expected_audit_faulty": expected_audit_faulty,
            },
            "enable": {
                "request_params": {"serial": params["serial"]},
                "expected_audit": expected_audit,
                "expected_audit_faulty": expected_audit_faulty,
            },
            "disable": {
                "request_params": {"serial": params["serial"]},
                "expected_audit": expected_audit,
                "expected_audit_faulty": expected_audit_faulty,
            },
            "assign": {
                "request_params": {
                    "serial": params["serial"],
                    "user": "hans",
                },
                "expected_audit": {**expected_audit, "user": "hans"},
                "expected_audit_faulty": {
                    **expected_audit_faulty,
                    "user": "hans",
                    "realm": "mydefrealm",
                },
            },
            "unassign": {
                "request_params": {"serial": params["serial"]},
                "expected_audit": expected_audit,
                "expected_audit_faulty": expected_audit_faulty,
            },
            "getTokenOwner": {
                "request_params": {"serial": params["serial"]},
                "expected_audit": expected_audit,
                "expected_audit_faulty": expected_audit_faulty,
            },
            "losttoken": {
                "request_params": {"serial": params["serial"]},
                "expected_audit": {
                    **expected_audit,
                    "serial": f"lost{params['serial']}",
                    "type": "pw",
                },
                "expected_audit_faulty": expected_audit_faulty,
            },
            "reset": {
                "request_params": {"serial": params["serial"]},
                "expected_audit": expected_audit,
                "expected_audit_faulty": expected_audit_faulty,
            },
            "getSerialByOtp": {
                "request_params": {"otp": params["otpkey"]},
                "expected_audit": expected_audit,
                "expected_audit_faulty": {
                    **expected_audit_faulty,
                    "serial": "",
                },
            },
            "check_serial": {
                "request_params": {"serial": "unique_serial"},
                "expected_audit": {
                    **expected_audit,
                    "serial": "unique_serial",
                    "type": "",
                    "user": "",
                    "realm": "",
                },
                "expected_audit_faulty": {
                    **expected_audit_faulty,
                    # TODO
                    # Should check_serial have success=1 when serial is take?
                    # Currently we return a new unique serial
                    "success": "1",
                    "serial": "unique_serial",
                },
            },
            "setPin": {
                "request_params": {
                    "serial": params["serial"],
                    "userpin": "123",
                },
                "expected_audit": expected_audit,
                "expected_audit_faulty": expected_audit_faulty,
            },
            "setValidity": {
                "request_params": {
                    "tokens": [params["serial"]],
                    "validityPeriodStart": "1355302800",
                },
                "expected_audit": expected_audit,
                "expected_audit_faulty": {
                    **expected_audit_faulty,
                    # TODO
                    # Should setValidity return success=1 if requested token(s) dont exist?
                    "success": "1",
                },
            },
            "set": {
                "request_params": {
                    "serial": params["serial"],
                    "MaxFailCount": "1",
                },
                "expected_audit": expected_audit,
                "expected_audit_faulty": {
                    **expected_audit_faulty,
                    # TODO
                    # Should set return success=1 if requested token(s) dont exist?
                    # currently success equals `count` where `count += 1` for each set param
                    # even when the method returns `0`
                    "success": "1",
                },
            },
            "tokenrealm": {
                "request_params": {
                    "serial": params["serial"],
                    "realms": "myotherrealm",
                },
                "expected_audit": {**expected_audit, "realm": "myotherrealm"},
                "expected_audit_faulty": {
                    **expected_audit_faulty,
                    "realm": "myotherrealm",
                },
            },
            "copyTokenPin": {
                "request_params": {
                    "from": params["serial"],
                    "to": f"{params['serial']}_to",
                },
                "expected_audit": {
                    **expected_audit,
                    "serial": f"{params['serial']}_to",
                },
                "expected_audit_faulty": {
                    **expected_audit_faulty,
                    "serial": f"{params['serial']}_to",
                },
            },
            "copyTokenUser": {
                "request_params": {
                    "from": params["serial"],
                    "to": f"{params['serial']}_to",
                },
                "expected_audit": {
                    **expected_audit,
                    "serial": f"{params['serial']}_to",
                },
                "expected_audit_faulty": {
                    **expected_audit_faulty,
                    "serial": f"{params['serial']}_to",
                },
            },
            "unpair": {
                "request_params": {"serial": params["serial"]},
                "expected_audit": {
                    **expected_audit,
                    "success": "0",  # as its a PW token
                },
                "expected_audit_faulty": expected_audit_faulty,
            },
            "totp_lookup": {
                "request_params": {
                    "serial": params["serial"],
                    "otp": params["otpkey"],
                },
                "expected_audit": {
                    **expected_audit,
                    "success": "0",  # as its a PW token
                    "type": "",
                    "user": "",
                    "realm": "",
                },
                "expected_audit_faulty": expected_audit_faulty,
            },
        }.items():
            self.init_token(params)

            request_params = values["request_params"]

            if action in ["copyTokenPin", "copyTokenUser"]:
                new_serial = request_params["to"]
                self.init_token({**params, "serial": new_serial})

            content_type = "application/json" if action in ["setValidity"] else None
            response = self.make_admin_request(
                action=action, params=request_params, content_type=content_type
            )

            audit_entry = self.get_last_audit_entry()
            assert f"admin/{action}" == audit_entry[audit_mapping["action"]]
            for key, expected in values["expected_audit"].items():
                actual = audit_entry[audit_mapping[key]]
                assert expected == actual, action

            self.delete_all_token()

            # Test with faulty input since tokens are deleted
            if action == "check_serial":
                # init token with taken serial
                self.init_token(params={**params, "serial": request_params["serial"]})

            self.make_admin_request(
                action=action,
                params=request_params,
                content_type=content_type,
            )
            audit_entry = self.get_last_audit_entry()
            for key, expected in values["expected_audit_faulty"].items():
                actual = audit_entry[audit_mapping[key]]
                assert expected == actual, action

            self.delete_all_token()

    def test_audit_for_successful_admin_login(
        self,
    ) -> None:
        username = "admin"
        password = "Test123!"

        local_admin_resoler = LocalAdminResolver(self.app)
        local_admin_resoler.add_user(username, password)

        client = FlaskClient(self.app)
        res = client.post(
            "/admin/login", data=dict(username=username, password=password)
        )

        audit_entry = self.get_last_audit_entry()
        assert "admin/login" == audit_entry[4]
        assert "1" == audit_entry[5]
        assert username == audit_entry[8]
        assert "linotp_admins" == audit_entry[9]
        assert f"{username}@linotp_admins (LinOTP_local_admins)" in audit_entry[10]

    def test_audit_for_unsuccessful_admin_login(
        self,
    ) -> None:
        username = "admin"
        password = "Test123!"

        local_admin_resoler = LocalAdminResolver(self.app)
        local_admin_resoler.add_user(username, password)

        client = FlaskClient(self.app)
        res = client.post(
            "/admin/login",
            data=dict(username=username, password=password + "WRONG"),
        )

        audit_entry = self.get_last_audit_entry()
        assert "admin/login" == audit_entry[4]
        assert "0" == audit_entry[5]
        assert username == audit_entry[8]
        assert "linotp_admins" == audit_entry[9]
        assert f"{username}@linotp_admins" not in audit_entry[10]

    @patch("linotp.controllers.base.get_jwt")
    def test_audit_for_successful_admin_logout(self, get_jwt_mock: Mock) -> None:
        get_jwt_mock.return_value = {"jti": None, "exp": 1}

        username = "admin"

        res = self._make_authenticated_request(controller="admin", action="logout")

        audit_entry = self.get_last_audit_entry()
        assert "admin/logout" == audit_entry[4]
        assert "1" == audit_entry[5]
        assert username == audit_entry[8]
        assert "linotp_admins" == audit_entry[9]
        assert f"{username}@linotp_admins" in audit_entry[10]

    def create_reporting_policy(self, policy_params: dict = None):
        policy_params = policy_params or {}
        params = {
            "name": policy_params.get("name", "reporting_policy"),
            "scope": policy_params.get("scope", "reporting"),
            "action": policy_params.get(
                "action",
                "token_total, token_status=active, token_status=inactive, token_status=assigned, token_status=unassigned",
            ),
            "user": policy_params.get("user", "*"),
            "realm": policy_params.get("realm", "*"),
        }
        self.create_policy(params)

    def test_reporting_for_actions(self):
        """Test if action trigger expected report"""

        # default params to init the token
        default_params = {
            "serial": "serial_1",
            "type": "pw",
            "otpkey": "123",
            "user": "root",
            "realm": "mydefrealm",
        }

        # expected_realm_strings is the expected report
        # in form of
        # [f"{entry.realm} {entry.parameter} {entry.count}" for entry in report]
        test_dicts = [
            {
                "test_scenario": "init without realm",
                "action": "init",
                "request_params": {
                    "serial": default_params["serial"],
                    "type": default_params["type"],
                    "otpkey": default_params["otpkey"],
                },
                "expected_realm_strings": [
                    "/:no realm:/ total 1",
                    "/:no realm:/ assigned 0",
                    "/:no realm:/ unassigned 1",
                    "/:no realm:/ active 1",
                    "/:no realm:/ inactive 0",
                ],
            },
            {
                "test_scenario": "init with realm",
                "action": "init",
                "request_params": {
                    "serial": default_params["serial"],
                    "type": default_params["type"],
                    "otpkey": default_params["otpkey"],
                    "realm": default_params["realm"],
                },
                "expected_realm_strings": [
                    "mydefrealm total 1",
                    "mydefrealm assigned 0",
                    "mydefrealm unassigned 1",
                    "mydefrealm active 1",
                    "mydefrealm inactive 0",
                ],
            },
            {
                "test_scenario": "init with user",
                "action": "init",
                "request_params": {
                    "serial": default_params["serial"],
                    "type": default_params["type"],
                    "otpkey": default_params["otpkey"],
                    "user": default_params["user"],
                },
                "expected_realm_strings": [
                    "mydefrealm total 1",
                    "mydefrealm assigned 1",
                    "mydefrealm unassigned 0",
                    "mydefrealm active 1",
                    "mydefrealm inactive 0",
                ],
            },
            {
                "test_scenario": "assign to user",
                "action": "assign",
                "request_params": {
                    "serial": default_params["serial"],
                    "user": "hans",
                },
                "expected_realm_strings": [
                    "mydefrealm total 1",
                    "mydefrealm assigned 1",
                    "mydefrealm unassigned 0",
                    "mydefrealm active 1",
                    "mydefrealm inactive 0",
                ],
            },
            {
                "test_scenario": "assign to non-existing user",
                "action": "assign",
                "request_params": {
                    "serial": default_params["serial"],
                    "user": "non-existing user123",
                },
                "expected_realm_strings": [],
            },
            {
                "test_scenario": "unassign from user",
                "action": "unassign",
                "request_params": {"serial": default_params["serial"]},
                "expected_realm_strings": [
                    "mydefrealm total 1",
                    "mydefrealm assigned 0",
                    "mydefrealm unassigned 1",
                    "mydefrealm active 1",
                    "mydefrealm inactive 0",
                ],
            },
            {
                "test_scenario": "enable token",
                "action": "enable",
                "request_params": {"serial": default_params["serial"]},
                "expected_realm_strings": [
                    "mydefrealm total 1",
                    "mydefrealm assigned 1",
                    "mydefrealm unassigned 0",
                    "mydefrealm active 1",
                    "mydefrealm inactive 0",
                ],
            },
            {
                "test_scenario": "disable token",
                "action": "disable",
                "request_params": {"serial": default_params["serial"]},
                "expected_realm_strings": [
                    "mydefrealm total 1",
                    "mydefrealm assigned 1",
                    "mydefrealm unassigned 0",
                    "mydefrealm active 0",
                    "mydefrealm inactive 1",
                ],
            },
            {
                "test_scenario": "delete token",
                "action": "remove",
                "request_params": {"serial": default_params["serial"]},
                "expected_realm_strings": [
                    "mydefrealm total 0",
                    "mydefrealm assigned 0",
                    "mydefrealm unassigned 0",
                    "mydefrealm active 0",
                    "mydefrealm inactive 0",
                ],
            },
            {
                "test_scenario": "losttoken",
                "action": "losttoken",
                "request_params": {"serial": default_params["serial"]},
                "expected_realm_strings": [
                    "mydefrealm total 2",
                    "mydefrealm assigned 2",
                    "mydefrealm unassigned 0",
                    "mydefrealm active 1",
                    "mydefrealm inactive 1",
                ],
            },
            {
                "test_scenario": "set tokenrealm",
                "action": "tokenrealm",
                "request_params": {
                    "serial": default_params["serial"],
                    "realms": "myotherrealm",
                },
                "expected_realm_strings": [
                    "mydefrealm total 0",
                    "mydefrealm assigned 0",
                    "mydefrealm unassigned 0",
                    "mydefrealm active 0",
                    "mydefrealm inactive 0",
                    "myotherrealm total 1",
                    "myotherrealm assigned 1",
                    "myotherrealm unassigned 0",
                    "myotherrealm active 1",
                    "myotherrealm inactive 0",
                ],
            },
            {
                "test_scenario": "remove tokenrealm",
                "action": "tokenrealm",
                "request_params": {
                    "serial": default_params["serial"],
                    "realms": "",
                },
                "expected_realm_strings": [
                    "mydefrealm total 0",
                    "mydefrealm assigned 0",
                    "mydefrealm unassigned 0",
                    "mydefrealm active 0",
                    "mydefrealm inactive 0",
                    "/:no realm:/ total 1",
                    "/:no realm:/ assigned 1",
                    "/:no realm:/ unassigned 0",
                    "/:no realm:/ active 1",
                    "/:no realm:/ inactive 0",
                ],
            },
            {
                "test_scenario": "copyTokenUser",
                "action": "copyTokenUser",
                "request_params": {
                    "from": default_params["serial"],
                    "to": f"{default_params['serial']}_to",
                },
                "expected_realm_strings": [
                    "mydefrealm total 2",
                    "mydefrealm assigned 2",
                    "mydefrealm unassigned 0",
                    "mydefrealm active 2",
                    "mydefrealm inactive 0",
                ],
            },
        ]
        for test_dict in test_dicts:
            action = test_dict["action"]
            if action != "init":
                # init a token to perform the action on
                init_params = test_dict.get("optional_init_params") or default_params
                self.init_token(params=init_params)

                if action in ["copyTokenUser"]:
                    new_serial = test_dict["request_params"]["to"]
                    self.init_token({**init_params, "serial": new_serial})

            # create policy
            self.create_reporting_policy()

            # trigger action
            response = self.make_admin_request(
                action, params=test_dict.get("request_params")
            )

            # verify reporting for action
            with DBSession() as session:
                entries = session.query(Reporting).all()
                reported_realm_strings = [
                    f"{entry.realm} {entry.parameter} {entry.count}"
                    for entry in entries
                ]

                expected_realm_strings = test_dict["expected_realm_strings"]

                assert len(reported_realm_strings) == len(expected_realm_strings), (
                    test_dict["test_scenario"]
                )

                for realm_string in expected_realm_strings:
                    assert realm_string in reported_realm_strings, test_dict[
                        "test_scenario"
                    ]

                # Clean up reporting and Tokens
                session.query(Reporting).delete()
                session.commit()
            # Clean up policies and tokens
            self.delete_all_policies()
            self.delete_all_token()

    def test_bug_LINOTP_2084_unauthorized_request_does_not_trigger_reporting_admin_controller(
        self,
    ):
        # create token without triggering reporting
        serial = self.createSPASS()
        # create policy
        self.create_reporting_policy()

        # trigger action that would trigger reporting pre LINOTP-2084
        for action in [
            "assign",
            "unassign",
            "enable",
            "disable",
            "init",
            "loadtokens",
            "copyTokenUser",
            "losttoken",
            "remove",
            "tokenrealm",
        ]:
            response = self.make_request("admin", action, params={"serial": serial})

            # verify no reporting was triggered
            with DBSession() as session:
                entries = session.query(Reporting).all()
                assert [] == entries, action

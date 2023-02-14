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
"""

import json
import logging

from linotp.tests import TestController

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
        self.client.cookie_jar.clear_session_cookies

        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def createToken3(self):
        parameters = {
            "serial": "003e808e",
            "otpkey": "e56eb2bcbafb2eea9bce9463f550f86d587d6c71",
            "description": "my EToken",
        }

        response = self.make_admin_request("init", params=parameters)
        assert '"value": true' in response, response

    def createToken2(self, serial="F722362"):
        parameters = {
            "serial": serial,
            "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
            "description": "TestToken" + serial,
        }

        response = self.make_admin_request("init", params=parameters)
        assert '"value": true' in response, response
        return serial

    def createTokenSHA256(self, serial="SHA256"):
        parameters = {
            "serial": serial,
            "otpkey": "47F6EE05C06FA1CDB8B9AADF520FCF86221DB0A107731452AE140EED0EB518B0",
            "type": "hmac",
            "hashlib": "sha256",
        }
        response = self.make_admin_request("init", params=parameters)
        assert '"value": true' in response, response
        return serial

    def createSPASS(self, serial="LSSP0001", pin="1test@pin!42"):
        parameters = {"serial": serial, "type": "spass", "pin": pin}
        response = self.make_admin_request("init", params=parameters)
        assert '"value": true' in response, response
        return serial

    def createToken(self):
        parameters = {
            "serial": "F722362",
            "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
            "user": "root",
            "pin": "pin",
            "description": "TestToken1",
        }

        response = self.make_admin_request("init", params=parameters)
        assert '"value": true' in response, response

        parameters = {
            "serial": "F722363",
            "otpkey": "AD8EABE235FC57C815B26CEF3709075580B4473880B44738",
            "user": "root",
            "pin": "pin",
            "description": "TestToken2",
        }

        response = self.make_admin_request("init", params=parameters)
        assert '"value": true' in response, response

        parameters = {
            "serial": "F722364",
            "otpkey": "AD8EABE235FC57C815B26CEF37090755",
            "user": "root",
            "pin": "pin",
            "description": "TestToken3",
        }

        response = self.make_admin_request("init", params=parameters)
        assert '"value": true' in response, response

        # test the update
        parameters = {
            "serial": "F722364",
            "otpkey": "AD8EABE235FC57C815B26CEF37090755",
            "user": "root",
            "pin": "Pin3",
            "description": "TestToken3",
        }

        response = self.make_admin_request("init", params=parameters)
        # log.error("response %s\n",response)
        assert '"value": true' in response, response

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
        assert response.json["result"]["status"]
        assert response.json["result"]["value"] == len(serials)

        # submit the delete of the tokens within one request

        params = {"serial[]": fake_serials}
        response = self.make_admin_request("remove", params=params)

        jresp = response.json
        assert response.json["result"]["status"] is False
        assert response.json["result"]["error"]["code"] == 1119

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
        assert (
            response.json["result"]["value"]["data"][0]["LinOtp.Userid"] == "0"
        ), response

        # test initial assign update
        parameters = {"serial": serial, "user": "root"}
        response = self.make_admin_request("unassign", params=parameters)
        # log.error("response %s\n",response)
        assert '"value": true' in response, response

        # test wrong assign
        parameters = {"serial": serial, "user": "NoBody"}
        response = self.make_admin_request("assign", params=parameters)
        # log.error("response %s\n",response)
        assert (
            "getUserId failed: no user >NoBody< found!" in response
        ), response

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
        temp_token_pass = (
            resp.get("result", {}).get("value", {}).get("password")
        )

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

        response = self.make_admin_request(
            "setPin", params={"serial": "setpin_01"}
        )

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

        assert response.json["result"][
            "status"
        ], 'Expected response.result.status to be True in response: "{}"'.format(
            response.json
        )

        assert (
            token_serial_1 in response.json["result"]["value"]
        ), 'Expected response.result.value to contain token id "{}" in response: "{}"'.format(
            token_serial_1, response.json
        )

        assert (
            token_serial_2 in response.json["result"]["value"]
        ), 'Expected response.result.value to contain token id "{}" in response: "{}"'.format(
            token_serial_2, response.json
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
        response = self.make_admin_request(
            "remove", params={"serial": "token01"}
        )

        assert '"status": true' in response, response

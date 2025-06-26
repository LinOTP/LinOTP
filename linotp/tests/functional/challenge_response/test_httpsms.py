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
Test HttpSms Gateway

These tests will only pass if you start a LinOTP server on 127.0.0.1.
For example with paster:

    paster serve test.ini

We assume port 5001 is used (default). If you want to use another port you can
specify it with nose-testconfig (e.g. --tc=paster.port:5005).
"""

import json
import tempfile
from unittest.mock import patch

import requests

from linotp.lib.util import str2unicode
from linotp.tests.functional.challenge_response.testing_controller import (
    TestingChallengeResponseController,
)


class FakeResponse:
    text = None


class DefaultProvider:
    def __init__(self, test, config):
        # get the old default provider and remember
        # check that legacy provider is not the default one

        self.old_default = None

        self.test = test
        self.config = config
        self.provider_type = config["type"]

        params = {"type": self.provider_type}

        response = test.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        providers = jresp.get("result").get("value", {})

        for provider_name, provider_def in list(providers.items()):
            if "default" in provider_def:
                self.old_default = provider_name

    def __enter__(self):
        """
        define the new provider via setProvider
        """

        response = self.test.make_system_request("setProvider", params=self.config)
        assert response.json["result"]["value"], response

        response = self.test.make_system_request(
            "setDefaultProvider",
            params={
                "name": self.config.get("name"),
                "type": self.provider_type,
            },
        )
        assert response.json["result"]["value"], response
        return self

    def __exit__(self, *args):
        """on exit restore the old default provider"""

        if self.old_default:
            response = self.test.make_system_request(
                "setDefaultProvider",
                params={"name": self.old_default, "type": self.provider_type},
            )
            assert response.json["result"]["value"], response

        params = {"type": self.provider_type, "name": self.config.get("name")}

        response = self.test.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        providers = jresp.get("result").get("value", {})

        for provider_name, provider_def in list(providers.items()):
            if "Default" not in provider_def:
                response = self.test.make_system_request(
                    "delProvider", params={"name": provider_name}
                )
                assert response.json["result"]["value"], response


class TestHttpSmsController(TestingChallengeResponseController):
    """
    Here the HTTP SMS Gateway functionality is tested.
    """

    def setUp(self):
        """
        This sets up all the resolvers and realms
        """
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        self.serials = ["sms01", "sms02"]
        self.max = 22
        for num in range(3, self.max):
            serial = f"sms{num:02d}"
            self.serials.append(serial)

        TestingChallengeResponseController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

        self.initTokens()
        self.initProvider()

        self.sms_url = f"http://localhost:{self.paster_port}/testing/http2sms"

    def tearDown(self):
        TestingChallengeResponseController.tearDown(self)

    ##########################################################################
    def removeTokens(self):
        for serial in self.serials:
            parameters = {"serial": serial}
            response = self.make_admin_request(
                "remove", params=parameters, auth_user="superadmin"
            )
            assert response.json["result"]["status"], response

    def initTokens(self):
        """
        Initialize the tokens
        """

        parameters = {
            "serial": self.serials[0],
            "otpkey": "1234567890123456789012345678901234567890"
            + "123456789012345678901234",
            "realm": "myDefRealm",
            "type": "sms",
            "user": "user1",
            "pin": "1234",
            "phone": "016012345678",
        }
        response = self.make_admin_request(
            "init", params=parameters, auth_user="superadmin"
        )
        assert response.json["result"]["status"], response

        parameters = {
            "serial": self.serials[1],
            "otpkey": "1234567890123456789012345678901234567890"
            + "123456789012345678901234",
            "realm": "myDefRealm",
            "user": "user2",
            "type": "sms",
            "pin": "1234",
            "phone": "016022222222",
        }
        response = self.make_admin_request(
            "init", params=parameters, auth_user="superadmin"
        )
        assert response.json["result"]["status"], response

        for serial in self.serials[2 : self.max]:
            parameters = {
                "serial": serial,
                "otpkey": (
                    "1234567890123456789012345678901234567890123456789012345678901234"
                ),
                "realm": "myDefRealm",
                "type": "sms",
                "pin": "",
                "phone": "+49 01602/2222-222",
            }
            response = self.make_admin_request(
                "init", params=parameters, auth_user="superadmin"
            )
            assert response.json["result"]["status"], response

        return self.serials

    def initProvider(self):
        """
        Initialize the HttpSMSProvider
        """
        parameters = {
            "SMSProvider": "smsprovider.HttpSMSProvider.HttpSMSProvider",
        }
        response = self.make_system_request(
            "setConfig", params=parameters, auth_user="superadmin"
        )
        assert response.json["result"]["status"], response

    def last_audit(self, num=3, page=1):
        """
        Checks the last audit entry
        """
        # audit/search?sortorder=desc&rp=1
        params = {
            "sortorder": "desc",
            "rp": num,
            "page": page,
        }
        response = self.make_audit_request(action="search", params=params)
        return response

    @patch.object(requests, "get")
    def test_missing_param(self, mocked_requests_get):
        """
        Missing parameter at the SMS Gateway config. send SMS will fail
        """
        sms_conf = {
            "URL": self.sms_url,
            "PARAMETER": {"account": "clickatel", "username": "legit"},
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "to",
            "HTTP_Method": "GET",
            "RETURN_SUCCESS": "ID",
        }

        params = {
            "name": "test_missing_param",
            "config": json.dumps(sms_conf),
            "timeout": "100",
            "type": "sms",
            "class": "smsprovider.HttpSMSProvider.HttpSMSProvider",
        }

        fake_http_response = FakeResponse()
        fake_http_response.text = "MISSING PARAMETERS"
        mocked_requests_get.return_value = fake_http_response

        with DefaultProvider(self, params):
            # check the saved configuration:
            # getConfig will return only the crypted string

            response = self.make_system_request(
                action="getConfig",
                params={"key": "SMSProviderConfig"},
                auth_user="superadmin",
            )

            assert self.sms_url not in response, response

            # check the saved configuration:
            # getProvider will show the decrypted configuration

            response = self.make_system_request(
                action="getProvider",
                params={"name": "test_missing_param", "type": "sms"},
                auth_user="superadmin",
            )

            assert self.sms_url in response, response

            response = self.make_validate_request(
                "smspin", params={"user": "user1", "pass": "1234"}
            )
            assert not response.json["result"]["value"], response

            # check last audit entry
            response = self.last_audit()

            val = "-1"
            if '"total": null,' not in response:
                resp = json.loads(response.body)
                rows = resp.get("rows", [])
                for row in rows:
                    cell = row.get("cell", {})
                    if "validate/smspin" in cell:
                        idx = cell.index("validate/smspin")
                        val = cell[idx + 1]
                        break

            assert val == "0", response

    @patch.object(requests, "get")
    def test_successfull_auth(self, mocked_requests_get):
        """Successful SMS sending (via smspin) and authentication"""

        fake_http_response = FakeResponse()
        fake_http_response.text = "ID=123"
        mocked_requests_get.return_value = fake_http_response

        sms_conf = {
            "URL": self.sms_url,
            "PARAMETER": {"account": "clickatel", "username": "legit"},
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "HTTP_Method": "GET",
            "RETURN_SUCCESS": "ID",
        }

        params = {
            "name": "test_successfull_auth",
            "config": json.dumps(sms_conf),
            "timeout": "100",
            "type": "sms",
            "class": "smsprovider.HttpSMSProvider.HttpSMSProvider",
        }

        with DefaultProvider(self, params):
            response = self.make_validate_request(
                "smspin", params={"user": "user1", "pass": "1234"}
            )

            assert "state" in response.json["id"], (
                f"Expecting 'state' as challenge inidcator {response!r}"
            )

            # check last audit entry
            audit_response = self.last_audit().json

            sms_pin_success = False

            rows = audit_response.get("rows", [])
            for row in rows:
                cell = row.get("cell", {})
                if "validate/smspin" in cell:
                    idx = cell.index("validate/smspin")
                    sms_pin_success = cell[idx + 1] == "1"
                    break

            assert sms_pin_success, audit_response

            # test authentication
            response = self.make_validate_request(
                "check", params={"user": "user1", "pass": "1234973532"}
            )

            assert response.json["result"]["value"], response

    @patch.object(requests, "get")
    def test_successful_auth2(self, mocked_requests_get):
        """
        Successful SMS sending (via validate) and authentication
        """

        fake_http_response = FakeResponse()
        fake_http_response.text = "ID=123"
        mocked_requests_get.return_value = fake_http_response

        sms_conf = {
            "URL": self.sms_url,
            "PARAMETER": {"account": "clickatel", "username": "legit"},
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "HTTP_Method": "GET",
            "RETURN_SUCCESS": "ID",
        }

        params = {
            "name": "test_successful_auth2",
            "config": json.dumps(sms_conf),
            "timeout": "100",
            "type": "sms",
            "class": "smsprovider.HttpSMSProvider.HttpSMSProvider",
        }
        with DefaultProvider(self, params):
            response = self.make_validate_request(
                "check", params={"user": "user1", "pass": "1234"}
            )

            # authentication fails but sms is sent
            assert "state" in response.json["detail"]

            # test authentication
            response = self.make_validate_request(
                "check", params={"user": "user1", "pass": "1234973532"}
            )

            assert response.json["result"]["value"], response

    @patch.object(requests, "post")
    def test_successfull_auth_with_headers(self, mocked_requests_post):
        """
        Successful SMS sending (via validate)
        using a token based authentication in the http header
        """

        fake_http_response = FakeResponse()
        fake_http_response.text = "ID=123"
        mocked_requests_post.return_value = fake_http_response

        sms_conf = {
            "URL": self.sms_url,
            "PARAMETER": {"account": "clickatel", "username": "legit"},
            "HEADERS": {"AUTH_TOKEN": "authenticated"},
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "HTTP_Method": "POST",
            "RETURN_SUCCESS": "ID",
        }

        params = {
            "name": "test_successful_auth2",
            "config": json.dumps(sms_conf),
            "timeout": "100",
            "type": "sms",
            "class": "smsprovider.HttpSMSProvider.HttpSMSProvider",
        }
        with DefaultProvider(self, params):
            response = self.make_validate_request(
                "check", params={"user": "user1", "pass": "1234"}
            )

            # verify that the request post method was called with
            # with the AUTH_TOKEN in the headers
            (_, kwargs) = mocked_requests_post.call_args
            assert kwargs["headers"]["AUTH_TOKEN"] == "authenticated"

            # authentication fails but sms is sent
            assert "state" in response.json["detail"]

            # test authentication
            response = self.make_validate_request(
                "check", params={"user": "user1", "pass": "1234973532"}
            )

            assert response.json["result"]["value"], response

    @patch.object(requests, "get")
    def test_successful_SMS(self, mocked_requests_get):
        """
        Successful SMS sending with RETURN_FAILED
        """

        # ----------------------------------------------------------------- --

        # prepare the requests response

        fake_response = FakeResponse()
        fake_response.text = "ID=12356"
        mocked_requests_get.return_value = fake_response

        # ----------------------------------------------------------------- --

        sms_conf = {
            "URL": self.sms_url,
            "PARAMETER": {"account": "clickatel", "username": "legit"},
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "HTTP_Method": "GET",
            "RETURN_FAILED": "FAILED",
        }
        params = {
            "name": "test_successful_auth2",
            "config": json.dumps(sms_conf),
            "timeout": "100",
            "type": "sms",
            "class": "smsprovider.HttpSMSProvider.HttpSMSProvider",
        }
        with DefaultProvider(self, params):
            response = self.make_validate_request(
                "check", params={"user": "user1", "pass": "1234"}
            )

            assert "sms submitted" in response, response

    def test_successful_File_SMS(self):
        """
        Successful test of the File SMS Provider
        """

        # create a temporary filename, to avoid conflicts
        with tempfile.NamedTemporaryFile() as f:
            filename = f.name
            sms_conf = {"file": filename}

            params = {
                "name": "test_successful_File_SMS",
                "config": json.dumps(sms_conf),
                "timeout": "100",
                "type": "sms",
                "class": "smsprovider.FileSMSProvider.FileSMSProvider",
            }

            with DefaultProvider(self, params):
                response = self.make_validate_request(
                    "check",
                    params={
                        "user": "user1",
                        "pass": "1234",
                        "message": "Täst<otp>",
                    },
                )

                assert "state" in response.json["detail"], response
                assert "sms submitted" in response.json["detail"]["message"], response

                with open(filename) as f:
                    line = f.read()

                line = str2unicode(line)
                assert "Täst" in line, "'Täst' not found in line"

                _left, otp = line.split("Täst")
                response = self.make_validate_request(
                    "check", params={"user": "user1", "pass": f"1234{otp}"}
                )

                assert response.json["result"]["value"], response

    @patch.object(requests, "get")
    def test_failed_SMS(self, mocked_requests_get):
        """
        Failed SMS sending with RETURN_FAIL
        """

        sms_conf = {
            "URL": self.sms_url,
            "PARAMETER": {"account": "clickatel", "username": "anotherone"},
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "HTTP_Method": "GET",
            "RETURN_FAIL": "FAILED",
            "MSISDN": True,
            "SUPPRESS_PREFIX": "+",
        }

        params = {
            "name": "test_failed_SMS",
            "config": json.dumps(sms_conf),
            "timeout": "301",
            "type": "sms",
            "class": "smsprovider.HttpSMSProvider.HttpSMSProvider",
        }

        fake_http_response = FakeResponse()
        fake_http_response.text = "FAILED"
        mocked_requests_get.return_value = fake_http_response

        with DefaultProvider(self, params):
            response = self.make_validate_request(
                "smspin", params={"user": "user1", "pass": "1234"}
            )
            assert not response.json["result"]["value"], response

            # due to security fix to prevent information leakage the response
            # of validate/check will be only true or false
            # but wont contain the following message anymore
            #    'Failed to send SMS. We received a'
            #                ' predefined error from the SMS Gateway.

            params = {"sortorder": "desc", "rp": 3, "page": 1}
            response = self.make_audit_request(action="search", params=params)
            jresp = json.loads(response.body)

            found = any(
                "SMS could not be sent" in cell
                for row in jresp.get("rows", [])
                for cell in row.get("cell", [])
                if isinstance(cell, str)
            )

            assert found, "no entry 'SMS could not be sent' found"

    def create_sms_provider_configuration(
        self,
        name="test",
        method="GET",
        return_check=None,
        PARAMETERS=None,
    ):
        """
        use the internal testing server for
        """
        sms_conf = {
            "URL": self.sms_url,
            "PARAMETER": {"account": "clickatel", "username": "legit"},
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
        }

        # set the return check
        if not return_check:
            sms_conf["RETURN_SUCCESS"] = "ID"
        else:
            sms_conf.update(return_check)

        if PARAMETERS:
            sms_conf["PARAMETER"] = PARAMETERS

        sms_conf["HTTP_Method"] = method

        params = {
            "name": name,
            "config": json.dumps(sms_conf),
            "timeout": "100",
            "type": "sms",
            "class": "smsprovider.HttpSMSProvider.HttpSMSProvider",
        }

        return params

    @patch.object(requests, "post")
    @patch.object(requests, "get")
    def test_httpsmsprovider(self, mocked_requests_get, mocked_requests_post):
        """
        Test SMSProvider httplibs for working with GET and POST
        """

        return_check = {"RETURN_SUCCESS": "ID"}

        provider_conf = self.create_sms_provider_configuration(
            name="test_httpsmsprovider",
            return_check=return_check,
            method="POST",
        )

        with DefaultProvider(self, provider_conf):
            fake_response = FakeResponse()
            fake_response.text = "ID=POST"
            mocked_requests_post.return_value = fake_response

            # check if its possible to trigger challenge with empty pin
            params = {"serial": self.serials[2], "pass": ""}
            response = self.make_validate_request("check_s", params=params)

            assert "state" in response.json["detail"], (
                f"Expecting 'state' as challenge inidcator {response!r}"
            )

        provider_conf = self.create_sms_provider_configuration(
            name="test_httpsmsprovider",
            return_check=return_check,
            method="GET",
        )
        with DefaultProvider(self, provider_conf):
            fake_response = FakeResponse()
            fake_response.text = "ID=GET"
            mocked_requests_get.return_value = fake_response

            params = {"serial": self.serials[3], "pass": ""}
            response = self.make_validate_request("check_s", params=params)

            assert "state" in response.json["detail"], (
                f"Expecting 'state' as challenge inidcator {response!r}"
            )

    @patch.object(requests, "post")
    @patch.object(requests, "get")
    def test_twilio_httpsmsprovider(self, mocked_requests_get, mocked_requests_post):
        """
        Test Twilio as HttpSMSProvider which requires patter match for result
        """

        fake_http_response = FakeResponse()

        i = 11
        for method in ["POST", "GET"]:
            # ------------------------------------------------------------- --

            # use the next sms token for a valid twillio reply

            i = i + 1

            return_check = {"RETURN_SUCCESS_REGEX": "<Status>queued</Status>"}

            fake_http_response.text = "<Status>queued</Status>"
            mocked_requests_post.return_value = fake_http_response
            mocked_requests_get.return_value = fake_http_response

            provider_conf = self.create_sms_provider_configuration(
                name="sms_provider",
                return_check=return_check,
                method=method,
                PARAMETERS={"account": "twilio", "username": "legit"},
            )

            with DefaultProvider(self, provider_conf):
                params = {"serial": self.serials[i], "pass": ""}
                response = self.make_validate_request("check_s", params=params)

                assert "state" in response.json["detail"], (
                    f"Expecting 'state' {i}: {response!r}"
                )

            # ------------------------------------------------------------- --

            # use the next sms token for an invalid twillio reply
            #   where our fail regex 'RETURN_FAIL_REGEX' checks for a
            #   predefined error from the SMS Gateway"

            i = i + 1

            return_check = {"RETURN_FAIL_REGEX": "<Status>400</Status>"}

            fake_http_response.text = "<Status>400</Status>"
            mocked_requests_post.return_value = fake_http_response
            mocked_requests_get.return_value = fake_http_response

            provider_conf = self.create_sms_provider_configuration(
                name="sms_provider",
                return_check=return_check,
                method=method,
                PARAMETERS={"account": "twilio", "username": "legit"},
            )

            with DefaultProvider(self, provider_conf):
                params = {"serial": self.serials[i], "pass": ""}
                response = self.make_validate_request("check_s", params=params)

                assert not response.json["result"]["status"]
                assert not response.json["result"]["value"]


###eof#########################################################################

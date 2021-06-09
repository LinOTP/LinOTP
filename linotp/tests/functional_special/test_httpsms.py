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


"""
Test HttpSms Gateway

These tests will only pass if you start a LinOTP server on 127.0.0.1.
For example with paster:

    paster serve test.ini

We assume port 5001 is used (default). If you want to use another port you can
specify it with nose-testconfig (e.g. --tc=paster.port:5005).
"""


import json
import logging
import tempfile
import urllib.parse


from linotp.lib.util import str2unicode
from linotp.tests.functional_special import TestSpecialController

import linotp.provider.smsprovider.FileSMSProvider
import linotp.provider.smsprovider.HttpSMSProvider


# mocking hook is startting here
HTTP_RESPONSE_FUNC = None
HTTP_RESPONSE = None


def mocked_http_request(HttpObject, *argparams, **kwparams):

    resp = 200
    body = kwparams.get("body", "")
    params = dict(urllib.parse.parse_qsl(body))

    content = {
        "version": "LinOTP MOCK",
        "jsonrpc": "2.0",
        "result": {"status": True, "value": True},
        "id": 0,
    }

    global HTTP_RESPONSE
    if HTTP_RESPONSE:
        status, response = HTTP_RESPONSE
        if response:
            content = response
            resp = status
        HTTP_RESPONSE = None

    global HTTP_RESPONSE_FUNC
    if HTTP_RESPONSE_FUNC:
        test_func = HTTP_RESPONSE_FUNC
        resp, content = test_func(params)
        HTTP_RESPONSE_FUNC = None

    return resp, json.dumps(content)


log = logging.getLogger(__name__)

#


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

        return

    def __enter__(self):
        """
        define the new provider via setProvider
        """

        response = self.test.make_system_request(
            "setProvider", params=self.config
        )
        assert '"value": true' in response

        response = self.test.make_system_request(
            "setDefaultProvider",
            params={
                "name": self.config.get("name"),
                "type": self.provider_type,
            },
        )
        assert '"value": true' in response
        return self

    def __exit__(self, *args):
        """ on exit restore the old default provider """

        if self.old_default:
            response = self.test.make_system_request(
                "setDefaultProvider",
                params={"name": self.old_default, "type": self.provider_type},
            )
            assert '"value": true' in response

        params = {"type": self.provider_type, "name": self.config.get("name")}

        response = self.test.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        providers = jresp.get("result").get("value", {})

        for provider_name, provider_def in list(providers.items()):
            if "Default" not in provider_def:
                response = self.test.make_system_request(
                    "delProvider", params={"name": provider_name}
                )
                assert '"value": true' in response


class TestHttpSmsController(TestSpecialController):
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
            serial = "sms%02d" % num
            self.serials.append(serial)

        TestSpecialController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

        self.initTokens()
        self.initProvider()

        self.sms_url = (
            "http://localhost:%s/testing/http2sms" % self.paster_port
        )

    def tearDown(self):
        TestSpecialController.tearDown(self)

    ###############################################################################
    def removeTokens(self):
        for serial in self.serials:
            parameters = {"serial": serial}
            response = self.make_admin_request(
                "remove", params=parameters, auth_user="superadmin"
            )
            assert '"status": true' in response, response

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

        assert '"status": true' in response, response

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

        assert '"status": true' in response, response

        for serial in self.serials[2: self.max]:
            parameters = {
                "serial": serial,
                "otpkey": (
                    "1234567890123456789012345678901234567890"
                    "123456789012345678901234"
                ),
                "realm": "myDefRealm",
                "type": "sms",
                "pin": "",
                "phone": "+49 01602/2222-222",
            }
            response = self.make_admin_request(
                "init", params=parameters, auth_user="superadmin"
            )

            assert '"status": true' in response, response

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

        assert '"status": true' in response, response

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

    def test_missing_param(self):
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

            # due to security fix to prevent information leakage the response
            # of validate/check will be only true or false
            # but wont contain the following message anymore
            #    'Failed to send SMS. We received a'
            #                'Failed to send SMS.'
            assert '"value": false' in response, response

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

        return

    def test_succesfull_auth(self):
        """ Successful SMS sending (via smspin) and authentication """

        sms_conf = {
            "URL": self.sms_url,
            "PARAMETER": {"account": "clickatel", "username": "legit"},
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "HTTP_Method": "GET",
            "RETURN_SUCCESS": "ID",
        }

        params = {
            "name": "test_succesfull_auth",
            "config": json.dumps(sms_conf),
            "timeout": "100",
            "type": "sms",
            "class": "smsprovider.HttpSMSProvider.HttpSMSProvider",
        }

        with DefaultProvider(self, params):

            response = self.make_validate_request(
                "smspin", params={"user": "user1", "pass": "1234"}
            )

            assert '"state":' in response, (
                "Expecting 'state' as challenge inidcator %r" % response
            )

            # check last audit entry
            response2 = self.last_audit()
            # must be success == 1
            val = "-1"
            if '"total": null' not in response2:
                resp = json.loads(response2.body)
                rows = resp.get("rows", [])
                for row in rows:
                    cell = row.get("cell", {})
                    if "validate/smspin" in cell:
                        idx = cell.index("validate/smspin")
                        val = cell[idx + 1]
                        break

            assert val == "1", response2

            # test authentication
            response = self.make_validate_request(
                "check", params={"user": "user1", "pass": "1234973532"}
            )

            assert '"value": true' in response, response

        return

    def test_succesful_auth2(self):
        """
        Successful SMS sending (via validate) and authentication
        """
        sms_conf = {
            "URL": self.sms_url,
            "PARAMETER": {"account": "clickatel", "username": "legit"},
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "HTTP_Method": "GET",
            "RETURN_SUCCESS": "ID",
        }

        params = {
            "name": "test_succesful_auth2",
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
            assert '"value": false' in response, response

            # check last audit entry
            response2 = self.last_audit()
            # must be success == 1
            if '"total": null' not in response2:
                assert """challenge created""" in response2, response2

            # test authentication
            response = self.make_validate_request(
                "check", params={"user": "user1", "pass": "1234973532"}
            )

            assert '"value": true' in response, response

    def test_successful_SMS(self):
        """
        Successful SMS sending with RETURN_FAILED
        """
        sms_conf = {
            "URL": self.sms_url,
            "PARAMETER": {"account": "clickatel", "username": "legit"},
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "HTTP_Method": "GET",
            "RETURN_FAILED": "FAILED",
        }
        parameters = {
            "SMSProvider": "smsprovider.HttpSMSProvider.HttpSMSProvider",
            "SMSProviderConfig": json.dumps(sms_conf),
        }
        response = self.make_system_request(
            "setConfig", params=parameters, auth_user="superadmin"
        )

        assert '"status": true' in response, response

        response = self.make_validate_request(
            "smspin", params={"user": "user1", "pass": "1234"}
        )

        assert '"state"' in response, response

        return

    def test_successful_File_SMS(self):
        """
        Successful test of the File SMS Provider
        """
        # locate the lookup file in the servers home
        here = self.appconf.get("here", None)

        # create a temporary filename, to avoid conflicts
        f = tempfile.NamedTemporaryFile(delete=False, dir=here)
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

            assert '"message": "sms submitted"' in response, response
            assert '"state"' in response, response

            with open(filename, "r") as f:
                line = f.read()

            line = str2unicode(line)
            assert "Täst" in line, "'Täst' not found in line"

            _left, otp = line.split("Täst")
            response = self.make_validate_request(
                "check", params={"user": "user1", "pass": "1234%s" % otp}
            )

            assert '"value": true' in response, response

            import os

            os.remove(filename)

        return

    def test_failed_SMS(self):
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

        with DefaultProvider(self, params):

            response = self.make_validate_request(
                "smspin", params={"user": "user1", "pass": "1234"}
            )

            assert '"value": false' in response, response

            # due to security fix to prevent information leakage the response
            # of validate/check will be only true or false
            # but wont contain the following message anymore
            #    'Failed to send SMS. We received a'
            #                ' predefined error from the SMS Gateway.

            params = {"sortorder": "desc", "rp": 3, "page": 1}
            response = self.make_audit_request(action="search", params=params)

            found = False
            jresp = json.loads(response.body)

            for row in jresp.get("rows", []):
                entry = row.get("cell", [])
                for info in entry:
                    if isinstance(info, str):
                        if "SMS could not be sent" in info:
                            found = True
                            break
                if found:
                    break

            assert found, "no entry 'SMS could not be sent' found"

        return

    def setSMSProvider(
        self,
        name="test",
        preferred_httplib=None,
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
        if preferred_httplib:
            sms_conf["PREFERRED_HTTPLIB"] = preferred_httplib

        params = {
            "name": name,
            "config": json.dumps(sms_conf),
            "timeout": "100",
            "type": "sms",
            "class": "smsprovider.HttpSMSProvider.HttpSMSProvider",
        }

        return params

    def test_httpsmsprovider_httplib(self):
        """
        Test SMSProvider httplibs for working with GET and POST
        """
        provider_conf = self.setSMSProvider(
            preferred_httplib="httplib", method="POST"
        )

        provider_conf["name"] = "test_httpsmsprovider_httplib"

        with DefaultProvider(self, provider_conf):
            # check if its possible to trigger challenge with empty pin
            params = {"serial": self.serials[2], "pass": ""}
            response = self.make_validate_request("check_s", params=params)

            assert '"state":' in response, (
                "Expecting 'state' as challenge inidcator %r" % response
            )

        provider_conf = self.setSMSProvider(
            preferred_httplib="httplib", method="GET"
        )

        provider_conf["name"] = "test_httpsmsprovider_httplib"

        with DefaultProvider(self, provider_conf):

            params = {"serial": self.serials[3], "pass": ""}
            response = self.make_validate_request("check_s", params=params)
            assert '"state":' in response, (
                "Expecting 'state' as challenge inidcator %r" % response
            )

    def test_httpsmsprovider_urllib(self):
        """
        Test SMSProvider urllib for working with GET and POST
        """

        provider_config = self.setSMSProvider(
            preferred_httplib="urllib", method="POST"
        )

        with DefaultProvider(self, provider_config):

            params = {"serial": self.serials[4], "pass": ""}
            response = self.make_validate_request("check_s", params=params)
            assert '"state":' in response, (
                "Expecting 'state' as challenge inidcator %r" % response
            )

        provider_config = self.setSMSProvider(
            preferred_httplib="urllib", method="GET"
        )

        with DefaultProvider(self, provider_config):

            params = {"serial": self.serials[5], "pass": ""}
            response = self.make_validate_request("check_s", params=params)
            assert '"state":' in response, (
                "Expecting 'state' as challenge inidcator %r" % response
            )

        return

    def test_httpsmsprovider_requests(self):
        """
        Test SMSProvider 'requests' for working with GET and POST
        """
        # now we check as well the requests lib if its available
        skip = False
        try:
            import requests

            requests.__version__
        except ImportError:
            skip = True

        if skip:
            skip_reason = "Httplib 'requests' not supported in this env!"
            if hasattr(self, "skipTest"):
                self.skipTest(skip_reason)
            else:
                log.error(skip_reason)
                return

        provider_config = self.setSMSProvider(
            preferred_httplib="requests", method="POST"
        )

        with DefaultProvider(self, config=provider_config):

            params = {"serial": self.serials[6], "pass": ""}
            response = self.make_validate_request("check_s", params=params)
            assert '"state":' in response, (
                "Expecting 'state' as challenge inidcator %r" % response
            )

        provider_config = self.setSMSProvider(
            preferred_httplib="requests", method="GET"
        )

        with DefaultProvider(self, config=provider_config):

            params = {"serial": self.serials[7], "pass": ""}
            response = self.make_validate_request("check_s", params=params)
            assert '"state":' in response, (
                "Expecting 'state' as challenge inidcator %r" % response
            )

        return

    def test_twilio_httpsmsprovider_httplib(self):
        """
        Test Twilio as HttpSMSProvider which requires patter nmatch for result
        """
        # TODO: Fix and re-enable twilio tests
        self.skipTest("Temporarily skip twilio tests due to known problems")

        args = [
            {"preferred_httplib": "httplib", "method": "GET"},
            {"preferred_httplib": "httplib", "method": "POST"},
        ]
        i = 7
        for arg in args:
            i = i + 1
            parameters = {"account": "twilio", "username": "legit"}
            arguments = {
                "return_check": {
                    "RETURN_SUCCESS_REGEX": "<Status>queued</Status>"
                },
                "PARAMETERS": parameters,
            }
            arguments.update(arg)
            self.setSMSProvider(**arguments)

            params = {"serial": self.serials[i], "pass": ""}
            response = self.make_validate_request("check_s", params=params)
            assert '"state":' in response, "Expecting 'state' %d: %r" % (
                i,
                response,
            )

            parameters = {"account": "twilio", "username": "fail"}
            arguments = {
                "return_check": {"RETURN_FAIL_REGEX": "<Status>400</Status>"},
                "PARAMETERS": parameters,
            }
            arguments.update(arg)
            self.setSMSProvider(**arguments)
            i = i + 1
            params = {"serial": self.serials[i], "pass": ""}
            response = self.make_validate_request("check_s", params=params)
            assert (
                "predefined error from the SMS Gateway" in response
            ), "Expecting error %d: %r" % (i, response)

        return

    def test_twilio_httpsmsprovider_urllib(self):
        """
        Test Twilio as HttpSMSProvider which requires patter nmatch for result
        """
        # TODO: Fix and re-enable twilio tests
        self.skipTest("Temporarily skip twilio tests due to known problems")

        args = [
            {"preferred_httplib": "urllib", "method": "GET"},
            {"preferred_httplib": "urllib", "method": "POST"},
        ]

        i = 9
        for arg in args:
            i = i + 1
            parameters = {"account": "twilio", "username": "legit"}
            arguments = {
                "return_check": {
                    "RETURN_SUCCESS_REGEX": "<Status>queued</Status>"
                },
                "PARAMETERS": parameters,
            }
            arguments.update(arg)
            self.setSMSProvider(**arguments)

            params = {"serial": self.serials[i], "pass": ""}
            response = self.make_validate_request("check_s", params=params)
            assert '"state":' in response, "Expecting 'state' %d: %r" % (
                i,
                response,
            )

            parameters = {"account": "twilio", "username": "fail"}
            arguments = {
                "return_check": {"RETURN_FAIL_REGEX": "<Status>400</Status>"},
                "PARAMETERS": parameters,
            }
            arguments.update(arg)
            self.setSMSProvider(**arguments)
            i = i + 1
            params = {"serial": self.serials[i], "pass": ""}
            response = self.make_validate_request("check_s", params=params)
            assert (
                "predefined error from the SMS Gateway" in response
            ), "Expecting error %d: %r" % (i, response)

        return

    def test_twilio_httpsmsprovider_requests(self):
        """
        Test Twilio as HttpSMSProvider which requires patter nmatch for result
        """
        # TODO: Fix and re-enable twilio tests
        self.skipTest("Temporarily skip twilio tests due to known problems")

        # now we check as well the requests lib if its available
        skip = False
        try:
            import requests

            requests.__version__
        except ImportError:
            skip = True

        if skip:
            skip_reason = "Httplib 'requests' not supported in this env!"
            if hasattr(self, "skipTest"):
                self.skipTest(skip_reason)
            else:
                log.error(skip_reason)
                return

        args = [
            {"preferred_httplib": "requests", "method": "GET"},
            {"preferred_httplib": "requests", "method": "POST"},
        ]

        i = 11
        for arg in args:
            i = i + 1
            parameters = {"account": "twilio", "username": "legit"}
            arguments = {
                "return_check": {
                    "RETURN_SUCCESS_REGEX": "<Status>queued</Status>"
                },
                "PARAMETERS": parameters,
            }
            arguments.update(arg)
            self.setSMSProvider(**arguments)
            params = {"serial": self.serials[i], "pass": ""}
            response = self.make_validate_request("check_s", params=params)
            assert '"state":' in response, "Expecting 'state' %d: %r" % (
                i,
                response,
            )

            parameters = {"account": "twilio", "username": "fail"}
            arguments = {
                "return_check": {"RETURN_FAIL_REGEX": "<Status>400</Status>"},
                "PARAMETERS": parameters,
            }
            arguments.update(arg)
            self.setSMSProvider(**arguments)
            i = i + 1
            params = {"serial": self.serials[i], "pass": ""}
            response = self.make_validate_request("check_s", params=params)
            assert (
                "predefined error from the SMS Gateway" in response
            ), "Expecting error %d: %r" % (i, response)

        return


###eof#########################################################################

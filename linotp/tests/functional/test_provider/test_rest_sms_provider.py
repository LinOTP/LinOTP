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
Test REST Sms Gateway

These tests will only pass if you start a LinOTP server on 127.0.0.1.
For example with paster:

    paster serve test.ini

We assume port 5001 is used (default). If you want to use another port you can
specify it with nose-testconfig (e.g. --tc=paster.port:5005).
"""


import logging
import urllib.parse
import requests
from datetime import datetime
from datetime import timedelta

from freezegun import freeze_time

from mock import patch

from linotp.tests.functional_special import TestSpecialController

import linotp.provider.smsprovider.RestSMSProvider

REQUEST_BODY = ""
REQUEST_HEADERS = {}


def mocked_http_request(HttpObject, *argparams, **kwparams):

    global REQUEST_BODY
    REQUEST_BODY = kwparams["json"]

    global REQUEST_HEADERS
    REQUEST_HEADERS = kwparams.get("headers", {})

    # build up response
    class Response:
        pass

    r = Response()

    r.status = 200
    r.ok = True

    r.headers = {"fake": True}
    r.headers.update(kwparams.get("headers", {}))
    r.text = ""  # rest does not return a body
    r.content = ""

    return r


import json

log = logging.getLogger(__name__)


class TestRestSmsController(TestSpecialController):
    """
    Here the HTTP SMS Gateway functionality is tested.
    """

    def setUp(self):
        """
        This sets up all the resolvers and realms
        """
        TestSpecialController.setUp(self)

        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        TestSpecialController.tearDown(self)

    ###############################################################################

    @patch("requests.Session.post", mocked_http_request)
    def test_succesful_auth(self):
        """
        Successful SMS sending (via smspin) and authentication
        """
        sms_url = "http://myfake.com/"

        sms_conf = {
            "URL": sms_url,
            "PAYLOAD": {"text": "Message: <message>", "destination": ""},
            "PASSWORD": "v3ry53cr3t",
            "USERNAME": "heinz",
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "RETURN_SUCCESS": "ID",
        }

        params = {
            "name": "newone",
            "config": json.dumps(sms_conf),
            "timeout": "301",
            "type": "sms",
            "class": "RestSMSProvider",
        }

        response = self.make_system_request("setProvider", params=params)
        assert '"value": true' in response, response

        # ------------------------------------------------------------------ --

        # next we have to make it the default provider

        params = {
            "name": "smsprovider_newone",
            "scope": "authentication",
            "realm": "*",
            "action": "sms_provider=newone",
            "user": "*",
        }

        response = self.make_system_request(action="setPolicy", params=params)
        assert "false" not in response, response

        parameters = {
            "serial": "SMS_4_REST",
            "realm": "myDefRealm",
            "type": "sms",
            "user": "passthru_user1",
            "pin": "1234",
            "phone": "016012345678",
        }
        response = self.make_admin_request("init", params=parameters)

        assert '"value": true' in response, response

        params = {"user": "passthru_user1", "pass": "1234"}
        response = self.make_validate_request("check", params=params)

        assert '"value": false' in response, response
        assert "transactionid" in response, response

        return

    @patch("requests.Session.post", mocked_http_request)
    def test_smstext_with_data(self):
        """
        check we are using the request parameter 'data' as sms message
        """
        sms_url = "http://myfake.com/"

        sms_conf = {
            "URL": sms_url,
            "PAYLOAD": {"text": "Message: <message>", "destination": ""},
            "HEADERS": {
                "Authorization": "Bearer da634870addc4568859092b2e0223376"
            },
            "PASSWORD": "v3ry53cr3t",
            "USERNAME": "heinz",
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "RETURN_SUCCESS": "ID",
        }

        params = {
            "name": "newone",
            "config": json.dumps(sms_conf),
            "timeout": "301",
            "type": "sms",
            "class": "RestSMSProvider",
        }

        response = self.make_system_request("setProvider", params=params)
        assert '"value": true' in response, response

        # ------------------------------------------------------------------ --

        # next we have to make it the default provider

        params = {
            "name": "smsprovider_newone",
            "scope": "authentication",
            "realm": "*",
            "action": "sms_provider=newone",
            "user": "*",
        }

        response = self.make_system_request(action="setPolicy", params=params)
        assert "false" not in response, response

        parameters = {
            "serial": "SMS_4_REST",
            "realm": "myDefRealm",
            "type": "sms",
            "user": "passthru_user1",
            "pin": "1234",
            "phone": "016012345678",
        }
        response = self.make_admin_request("init", params=parameters)

        assert '"value": true' in response, response

        params = {
            "user": "passthru_user1",
            "pass": "1234",
            "data": "this is your otp <otp>",
        }
        global REQUEST_BODY
        REQUEST_BODY = {}

        global REQUEST_HEADERS
        REQUEST_HEADERS = {}

        response = self.make_validate_request("check", params=params)

        assert "this is your otp" in REQUEST_BODY.get("text", ""), REQUEST_BODY

        assert "Authorization" in REQUEST_HEADERS, REQUEST_HEADERS

        assert '"value": false' in response, response
        assert "transactionid" in response, response

        return

    @patch("requests.Session.post", mocked_http_request)
    def test_smstext_with_ignore_data(self):
        """
        if enforce_smstext policy is set, the request parameter 'data' is ignored
        """
        global REQUEST_BODY

        # ------------------------------------------------------------------ --

        # create the sms token for the user

        parameters = {
            "serial": "SMS_4_REST",
            "realm": "myDefRealm",
            "type": "sms",
            "user": "passthru_user1",
            "pin": "1234",
            "phone": "016012345678",
        }

        response = self.make_admin_request("init", params=parameters)

        assert '"value": true' in response, response

        # ------------------------------------------------------------------ --

        # define the sms provider

        sms_url = "http://myfake.com/"

        sms_conf = {
            "URL": sms_url,
            "PAYLOAD": {"text": "Message: <message>", "destination": ""},
            "HEADERS": {
                "Authorization": "Bearer da634870addc4568859092b2e0223376"
            },
            "PASSWORD": "v3ry53cr3t",
            "USERNAME": "heinz",
            "SMS_TEXT_KEY": "text",
            "SMS_PHONENUMBER_KEY": "destination",
            "RETURN_SUCCESS": "ID",
        }

        params = {
            "name": "newone",
            "config": json.dumps(sms_conf),
            "timeout": "301",
            "type": "sms",
            "class": "RestSMSProvider",
        }

        response = self.make_system_request("setProvider", params=params)
        assert '"value": true' in response, response

        # ------------------------------------------------------------------ --

        # next we have to make it the default provider

        params = {
            "name": "smsprovider_newone",
            "scope": "authentication",
            "realm": "*",
            "action": "sms_provider=newone",
            "user": "*",
        }

        response = self.make_system_request(action="setPolicy", params=params)
        assert "false" not in response, response

        # ------------------------------------------------------------------ --

        # verify: if no smstext is defined and enforce_smstext, we
        # do not allow data to define the message

        # next overwrite smstext over challenge data
        params = {
            "name": "smstext_overwrite",
            "scope": "authentication",
            "realm": "*",
            "action": "enforce_smstext,",
            "user": "*",
        }

        response = self.make_system_request(action="setPolicy", params=params)
        assert "false" not in response, response

        params = {
            "user": "passthru_user1",
            "pass": "1234",
            "data": "this is your otp <otp>",
        }

        REQUEST_BODY = {}

        response = self.make_validate_request("check", params=params)

        assert "this is your otp" not in REQUEST_BODY.get(
            "text", "this is your otp"
        ), REQUEST_BODY

        assert '"value": false' in response, response
        assert "transactionid" in response, response

        # ------------------------------------------------------------------ --

        # next overwrite smstext over challenge data
        params = {
            "name": "smstext_overwrite",
            "scope": "authentication",
            "realm": "*",
            "action": 'enforce_smstext, smstext="no data <otp>"',
            "user": "*",
        }

        response = self.make_system_request(action="setPolicy", params=params)
        assert "false" not in response, response

        params = {
            "user": "passthru_user1",
            "pass": "1234",
            "data": "this is your otp <otp>",
        }

        REQUEST_BODY = {}

        with freeze_time(datetime.now() + timedelta(seconds=120)):

            response = self.make_validate_request("check", params=params)

            assert "no data" in REQUEST_BODY.get("text", ""), REQUEST_BODY
            assert "this is your otp" not in REQUEST_BODY.get(
                "text", "this is your otp"
            ), REQUEST_BODY

            assert '"value": false' in response, response
            assert "transactionid" in response, response

        return

    @patch("requests.Session.post", mocked_http_request)
    def test_phone_list(self):
        """
        Successful SMS sending (via smspin) and authentication
        """
        sms_url = "http://myfake.com/"

        sms_conf = {
            "URL": sms_url,
            "PAYLOAD": {
                "to": ["<phone>"],
                "from": "123456789",
                "body": "Your OTP is: <message>",
            },
            "HEADERS": {
                "Authorization": "Bearer <APITOKEN>",
                "Content-Type": "application/json",
            },
            "SMS_TEXT_KEY": "body",
            "SMS_PHONENUMBER_KEY": "to",
        }

        params = {
            "name": "newone",
            "config": json.dumps(sms_conf),
            "timeout": "301",
            "type": "sms",
            "class": "RestSMSProvider",
        }

        response = self.make_system_request("setProvider", params=params)
        assert '"value": true' in response, response

        # ------------------------------------------------------------------ --

        # next we have to make it the default provider

        params = {
            "name": "smsprovider_newone",
            "scope": "authentication",
            "realm": "*",
            "action": "sms_provider=newone",
            "user": "*",
        }

        response = self.make_system_request(action="setPolicy", params=params)
        assert "false" not in response, response

        parameters = {
            "serial": "SMS_4_REST",
            "realm": "myDefRealm",
            "type": "sms",
            "user": "passthru_user1",
            "pin": "1234",
            "phone": "016012345678",
        }
        response = self.make_admin_request("init", params=parameters)

        assert '"value": true' in response, response

        global REQUEST_BODY
        REQUEST_BODY = {}

        params = {"user": "passthru_user1", "pass": "1234"}
        response = self.make_validate_request("check", params=params)

        assert '"value": false' in response, response
        assert "transactionid" in response, response

        assert "016012345678" in REQUEST_BODY.get("to", [])[0]

        return


###eof#########################################################################

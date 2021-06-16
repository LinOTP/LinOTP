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
Test the autoassignment Policy.
"""
import json

from mock import patch

from linotp.tests import TestController

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


class TestAutoassignSMSController(TestController):
    """
    Test the autoassignment Policy with the sms token
    """

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_token()

        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

        global REQUEST_BODY
        REQUEST_BODY = ""

    def define_sms_provider(self):
        """define the default sms provider"""

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

    @patch("requests.Session.post", mocked_http_request)
    def test_autoenroll_sms(self):
        """
        check request parameter 'data' is used as sms message in the autoenroll case
        """

        self.define_sms_provider()

        # ------------------------------------------------------------------ --

        policy = {
            "name": "auto_assign_sms",
            "active": True,
            "scope": "enrollment",
            "action": "autoenrollment=sms",
            "user": "*",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        user = "passthru_user1@myDefRealm"
        params = {
            "user": user,
            "pass": "geheim1",
            "data": "this is your otp <otp>",
        }
        response = self.make_validate_request("check", params)
        assert "this is your otp" in REQUEST_BODY["text"], REQUEST_BODY
        assert "sms submitted" in response, response

        return

    @patch("requests.Session.post", mocked_http_request)
    def test_simple_autoenroll_sms(self):
        """
        check request parameter 'data' is used as sms message in the autoenroll case
        """

        self.define_sms_provider()

        # ------------------------------------------------------------------ --

        policy = {
            "name": "auto_assign_sms",
            "active": True,
            "scope": "enrollment",
            "action": "autoenrollment=sms",
            "user": "*",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        user = "passthru_user1@myDefRealm"
        params = {
            "user": user,
            "pass": "geheim1",
            "data": "this is your otp <otp>",
        }
        response = self.make_validate_request("simplecheck", params)
        assert "this is your otp" in REQUEST_BODY["text"], REQUEST_BODY
        assert "sms submitted" in response, response

        return

    @patch("requests.Session.post", mocked_http_request)
    def test_validate_sms_token_wo_owner(self):
        """check what happens if the token has no user assigned"""

        self.define_sms_provider()

        serial = "MyTestToken"

        token = {
            "key": "0f51c51a55a3c2736ecd0c022913d541b25734b5",
            "otps": ["755224", "657344", "672823"],
        }

        params = {
            "type": "sms",
            "serial": serial,
            "otpkey": token["key"],
            "phone": "112324234234234234",
            "pin": "test123!",
        }

        response = self.make_admin_request("init", params=params)
        assert "false" not in response

        params = {
            "serial": serial,
            "pass": "test123!",
            "message": "submit <otp>",
            "user": "hugo",
        }

        response = self.make_validate_request("check_s", params=params)
        assert "submit" in REQUEST_BODY["text"]

        params = {
            "serial": serial,
            "pass": "test123!" + token["otps"][1],
            "user": "",
        }

        response = self.make_validate_request("check_s", params=params)
        assert "false" not in response.body

        return

    @patch("requests.Session.post", mocked_http_request)
    def test_autoassigne_sms_token(self):
        """check what happens if the token has no user assigned"""

        self.define_sms_provider()

        serial = "MyTestToken"

        token = {
            "key": "0f51c51a55a3c2736ecd0c022913d541b25734b5",
            "otps": ["755224", "657344", "672823", "144917"],
        }

        params = {
            "type": "sms",
            "serial": serial,
            "otpkey": token["key"],
            "phone": "112324234234234234",
            "pin": "test123!",
            "realm": "myDefRealm",
        }

        response = self.make_admin_request("init", params=params)
        assert "false" not in response

        policy = {
            "name": "autassign_sms",
            "active": True,
            "scope": "enrollment",
            "action": "autoassignment",
            "user": "*",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        params = {
            "user": "passthru_user1@myDefRealm",
            "pass": "geheim1" + token["otps"][1],
        }

        response = self.make_validate_request("check", params=params)
        assert "false" not in response, response

        params = {"user": "passthru_user1@myDefRealm", "pass": "geheim1"}

        response = self.make_validate_request("simplecheck", params=params)
        assert ":-(" in response, response
        assert "Message" in REQUEST_BODY["text"]

        otp = REQUEST_BODY["text"].split()[-1]

        params = {"user": "passthru_user1@myDefRealm", "pass": "geheim1" + otp}

        response = self.make_validate_request("simplecheck", params=params)
        assert ":-)" in response, response

        return


# eof

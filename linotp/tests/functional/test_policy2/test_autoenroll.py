# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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

import linotp.provider.emailprovider
from linotp.tests import TestController

REQUEST_BODY = ""
REQUEST_HEADERS = {}

EMAIL_MESSAGE_OTP = ("", "")


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


def mocked_email_submitMessage(EMail_Object, *argparams, **kwparams):
    # this hook is defined to grep the otp and make it globaly available
    global EMAIL_MESSAGE_OTP
    EMAIL_MESSAGE_OTP = argparams, kwparams

    # we call here the original sms submitter - as we are a functional test
    # res = EMAIL_Object.submitMessage(*argparams)
    return True, ""


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

    def define_email_provider(self):

        email_conf = {
            "SMTP_SERVER": "mail.example.com",
            "SMTP_USER": "secret_user",
            "SMTP_PASSWORD": "secret_pasword",
        }

        params = {
            "name": "new_email_provider",
            "config": json.dumps(email_conf),
            "timeout": "30",
            "type": "email",
            "class": "linotp.provider.emailprovider.SMTPEmailProvider",
        }

        response = self.make_system_request("setProvider", params=params)
        assert '"value": true' in response, response
        response = self.make_system_request("setProvider", params)
        assert '"status": true' in response

        # ------------------------------------------------------------------ --

        # next we have to make it the default email provider

        params = {
            "name": "emailprovider_newone",
            "scope": "authentication",
            "realm": "*",
            "action": "email_provider=new_email_provider",
            "user": "*",
        }

        response = self.make_system_request(action="setPolicy", params=params)
        assert "false" not in response, response

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
    def test_autoenroll_sms_email(self):
        """
        support for autoenroll alternatives with prefered sms
        """
        self.define_email_provider()
        self.define_sms_provider()

        # ------------------------------------------------------------------ --

        policy = {
            "name": "auto_assign_sms",
            "active": True,
            "scope": "enrollment",
            "action": "autoenrollment = sms  email",
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

    @patch.object(
        linotp.provider.emailprovider.SMTPEmailProvider,
        "submitMessage",
        mocked_email_submitMessage,
    )
    def test_autoenroll_email_sms(self):
        """
        support for autoenroll alternatives - prefered no is email
        """

        self.define_email_provider()
        self.define_sms_provider()

        # ------------------------------------------------------------------ --

        policy = {
            "name": "auto_assign_sms",
            "active": True,
            "scope": "enrollment",
            "action": "autoenrollment =  email  sms ",
            "user": "*",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        # ---------------------------------------------------------------- --

        # now auto enroll the email token

        user = "passthru_user1@myDefRealm"
        params = {
            "user": user,
            "pass": "geheim1",
        }

        response = self.make_validate_request("check", params)
        assert '"value": false' in response.body, response
        assert '"linotp_tokentype": "email"' in response.body, response

        # ---------------------------------------------------------------- --

        # verify that the otp of the email submission

        jresp = json.loads(response.body)
        trans_id = jresp.get("detail", {}).get("transactionid")

        _, submit_kwparams = EMAIL_MESSAGE_OTP
        otp = submit_kwparams.get("replacements").get("otp")
        assert otp is not None

        user = "passthru_user1@myDefRealm"
        params = {"user": user, "pass": otp, "transactionid": trans_id}

        response = self.make_validate_request("check", params)
        assert '"value": true' in response.body, response

        return

    @patch("requests.Session.post", mocked_http_request)
    def test_autoenroll_wildcard(self):
        """
        support for autoenroll alternatives with wild card
        """
        self.define_email_provider()
        self.define_sms_provider()

        # ------------------------------------------------------------------ --

        policy = {
            "name": "auto_assign_sms",
            "active": True,
            "scope": "enrollment",
            "action": "autoenrollment = *",
            "user": "*",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        user = "passthru_user1@myDefRealm"
        params = {
            "user": user,
            "pass": "geheim1",
        }
        response = self.make_validate_request("check", params)
        assert '"value": false' in response.body, response
        assert '"linotp_tokentype": "sms"' in response.body, response
        assert "sms submitted" in response.body, response

        return

    @patch.object(
        linotp.provider.emailprovider.SMTPEmailProvider,
        "submitMessage",
        mocked_email_submitMessage,
    )
    def test_autoenroll_only_email(self):
        """
        test autoenroll alternatives with sms or email policy but only email
        """
        self.define_email_provider()
        self.define_sms_provider()

        # ------------------------------------------------------------------ --

        policy = {
            "name": "auto_assign_sms",
            "active": True,
            "scope": "enrollment",
            "action": "autoenrollment = sms email",
            "user": "*",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        user = "email_only@myDefRealm"
        params = {
            "user": user,
            "pass": "geheim1",
        }
        response = self.make_validate_request("check", params)
        assert '"value": false' in response.body, response
        assert '"linotp_tokentype": "email"' in response.body, response

        return

    @patch("requests.Session.post", mocked_http_request)
    def test_autoenroll_only_mobil(self):
        """
        test autoenroll alternatives with sms or email policy but only sms
        """
        self.define_email_provider()
        self.define_sms_provider()

        # ------------------------------------------------------------------ --

        policy = {
            "name": "auto_assign_sms",
            "active": True,
            "scope": "enrollment",
            "action": "autoenrollment = email sms",
            "user": "*",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=policy)
        assert "false" not in response, response

        user = "mobile_only@myDefRealm"
        params = {
            "user": user,
            "pass": "geheim1",
        }
        response = self.make_validate_request("check", params)
        assert '"value": false' in response.body, response
        assert '"linotp_tokentype": "sms"' in response.body, response

        return


# eof

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
  Test linotp.tokens.emailtoken with template file and inline template
"""

import json
import os
import smtplib
from unittest.mock import patch

from linotp.provider.emailprovider import EMAIL_PROVIDER_TEMPLATE_KEY
from linotp.tests import TestController


class MockedSMTP(object):
    def __init__(self):
        self.patch_smtp = patch("smtplib.SMTP", spec=smtplib.SMTP)

    def __enter__(self):
        mock_smtp_class = self.patch_smtp.start()
        self.mock_smtp_instance = mock_smtp_class.return_value
        return self.mock_smtp_instance

    def __exit__(self, *args, **kwargs):
        self.patch_smtp.stop()


class TestEmailtoken(TestController):
    def setUp(self):
        """setup for std resolver / realms"""

        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        """clean up for all token and resolver / realms"""

        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_token()
        self.delete_all_policies()

        TestController.tearDown(self)

    def test_email_template_with_file_ref(self):
        """
        verify that email with template file reference does work
        """
        # ------------------------------------------------------------------ --

        # first define that the fixture path could be an
        # email_provider_template root directory - we will use the email.eml
        # template

        params = {EMAIL_PROVIDER_TEMPLATE_KEY: self.fixture_path}

        response = self.make_system_request("setConfig", params=params)
        assert "false" not in response

        # ------------------------------------------------------------------ --

        # now define the email provider

        email_provider_config = {
            "SMTP_SERVER": "mail.example.com",
            "SMTP_USER": "secret_user",
            "SMTP_PASSWORD": "secret_pasword",
            "EMAIL_SUBJECT": "Your requested otp ${otp} for token ${serial}",
            "TEMPLATE": "file://email.eml",
        }

        email_provider_definition = {
            "name": "TemplEMailProvider",
            "timeout": "3",
            "type": "email",
            "config": json.dumps(email_provider_config),
            "class": "linotp.provider.emailprovider.SMTPEmailProvider",
        }

        response = self.make_system_request(
            "setProvider", params=email_provider_definition
        )

        assert "false" not in response

        # ------------------------------------------------------------------ --

        # and make hime the default email provider

        params = {"type": "email", "name": "TemplEMailProvider"}
        response = self.make_system_request(
            "setDefaultProvider", params=params
        )

        assert "false" not in response

        # ------------------------------------------------------------------ --

        # enroll email token for user

        user = "root"
        serial = "EMAIL_TOKEN_001"

        params = {
            "user": user,
            "type": "email",
            "pin": "123",
            "email_address": "test@example.com",
            "serial": serial,
        }
        response = self.make_admin_request("init", params=params)
        assert "false" not in response

        # ------------------------------------------------------------------ --

        # setup the mocking smtp client from which we get the sendmail args
        # to verify the template prcessing

        with MockedSMTP() as mock_smtp_instance:

            mock_smtp_instance.sendmail.return_value = []

            # now trigger a challenge for the user

            params = {"user": user, "pass": "123"}
            response = self.make_validate_request("check", params=params)
            assert "false" in response

            call_args = mock_smtp_instance.sendmail.call_args
            _from, _to, raw_message = call_args[0]

            message = raw_message.decode("utf-8")

            assert "Content-Type: multipart/related;" in message
            assert "${otp}" not in message
            assert "${serial}" not in message
            assert serial in message

    def test_email_template_with_inline(self):
        """
        verify that email with template file reference does work
        """
        # ------------------------------------------------------------------ --

        # first define that the fixture path could be an
        # email_provider_template root directory - we will use the email.eml
        # template

        params = {EMAIL_PROVIDER_TEMPLATE_KEY: self.fixture_path}

        response = self.make_system_request("setConfig", params=params)
        assert "false" not in response

        # ------------------------------------------------------------------ --

        # define an email message policy which should be
        # overruled by the template

        params = {
            "name": "email_message",
            "active": True,
            "scope": "authentication",
            "action": (
                "emailtext='text from policy',"
                "emailsubject='subject from policy'"
            ),
            "user": "*",
            "realm": "*",
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response

        # ------------------------------------------------------------------ --

        # now define the email provider

        filename = os.path.join(self.fixture_path, "email.eml")
        with open(filename, "rb") as f:
            raw_content = f.read()

        content = raw_content.decode("utf-8")
        inline_template = '"' + content.replace('"', '"') + '"'

        email_provider_config = {
            "SMTP_SERVER": "mail.example.com",
            "SMTP_USER": "secret_user",
            "SMTP_PASSWORD": "secret_pasword",
            "EMAIL_SUBJECT": (
                "Your requested otp ${otp} for token ${serial} and ${user}"
            ),
            "TEMPLATE": inline_template,
        }
        email_provider_definition = {
            "name": "TemplEMailProvider",
            "timeout": "3",
            "type": "email",
            "config": json.dumps(email_provider_config),
            "class": "linotp.provider.emailprovider.SMTPEmailProvider",
        }

        response = self.make_system_request(
            "setProvider", params=email_provider_definition
        )

        assert "false" not in response

        # ------------------------------------------------------------------ --

        # and make him the default email provider

        params = {"type": "email", "name": "TemplEMailProvider"}
        response = self.make_system_request(
            "setDefaultProvider", params=params
        )

        assert "false" not in response

        # ------------------------------------------------------------------ --

        # enroll email token for user

        user = "root"
        serial = "EMAIL_TOKEN_001"

        params = {
            "user": user,
            "type": "email",
            "pin": "123",
            "email_address": "test@example.com",
            "serial": serial,
        }
        response = self.make_admin_request("init", params=params)
        assert "false" not in response

        # ------------------------------------------------------------------ --

        # setup the mocking smtp client from which we get the sendmail args
        # to verify the template prcessing

        with MockedSMTP() as mock_smtp_instance:

            mock_smtp_instance.sendmail.return_value = []

            # now trigger a challenge for the user

            params = {"user": user, "pass": "123"}
            response = self.make_validate_request("check", params=params)

            assert "false" in response
            assert '"message": "e-mail sent successfully"' in response

            call_args = mock_smtp_instance.sendmail.call_args
            _from, _to, raw_message = call_args[0]

            message = raw_message.decode("utf-8")

            # verify that the template is used instead of the message
            assert "Content-Type: multipart/related;" in message

            # verify that otp and serial are replaced in message
            assert "${otp}" not in message
            assert "${serial}" not in message
            assert serial in message

            # verify that unknown vars are not replaced
            assert "${user}" in message

            # verify that the policy did not overrule the template
            assert "from policy" not in message

    def test_dynamic_email_address(self):
        """use the email address of the user not of the token (dynamic)"""

        email_provider_config = {
            "SMTP_SERVER": "mail.example.com",
            "SMTP_USER": "secret_user",
            "SMTP_PASSWORD": "secret_pasword",
            "EMAIL_SUBJECT": (
                "Your requested otp ${otp} for token ${serial} and ${user}"
            ),
        }
        email_provider_definition = {
            "name": "TemplEMailProvider",
            "timeout": "3",
            "type": "email",
            "config": json.dumps(email_provider_config),
            "class": "linotp.provider.emailprovider.SMTPEmailProvider",
        }

        response = self.make_system_request(
            "setProvider", params=email_provider_definition
        )

        assert "false" not in response

        # ------------------------------------------------------------------ --

        # and make him the default email provider

        params = {"type": "email", "name": "TemplEMailProvider"}
        response = self.make_system_request(
            "setDefaultProvider", params=params
        )

        assert "false" not in response

        # ------------------------------------------------------------------ --

        # enroll email token for user

        user = "passthru_user1"
        serial = "EMAIL_TOKEN_001"

        params = {
            "user": user,
            "type": "email",
            "pin": "123",
            "email_address": "test@example.com",
            "serial": serial,
        }
        response = self.make_admin_request("init", params=params)
        assert "false" not in response

        # ------------------------------------------------------------------ --

        params = {
            "name": "dynamic_email_address",
            "scope": "authentication",
            "action": "dynamic_email_address",
            "user": user,
            "realm": "*",
            "active": True,
        }

        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response

        # ------------------------------------------------------------------ --

        # setup the mocking smtp client from which we get the sendmal args
        # to verify the template prcessing

        with MockedSMTP() as mock_smtp_instance:

            mock_smtp_instance.sendmail.return_value = []

            # now trigger a challenge for the user

            params = {"user": user, "pass": "123"}
            response = self.make_validate_request("check", params=params)

            assert "false" in response
            assert '"message": "e-mail sent successfully"' in response

            call_args = mock_smtp_instance.sendmail.call_args
            _from, to, _message = call_args[0]

            assert to == "pass.true@example.com"

    def test_verify_not_blocking(self):
        """verify that email challenges are not blocked if challenge is closed"""

        # ------------------------------------------------------------------ --

        # setup the email provider

        email_provider_config = {
            "SMTP_SERVER": "mail.example.com",
            "SMTP_USER": "secret_user",
            "SMTP_PASSWORD": "secret_pasword",
            "EMAIL_SUBJECT": "otp: ${otp}",
        }
        email_provider_definition = {
            "name": "TemplEMailProvider",
            "timeout": "3",
            "type": "email",
            "config": json.dumps(email_provider_config),
            "class": "linotp.provider.emailprovider.SMTPEmailProvider",
        }

        response = self.make_system_request(
            "setProvider", params=email_provider_definition
        )

        assert "false" not in response

        # ------------------------------------------------------------------ --

        # and make him the default email provider

        params = {"type": "email", "name": "TemplEMailProvider"}
        response = self.make_system_request(
            "setDefaultProvider", params=params
        )

        assert "false" not in response

        # ------------------------------------------------------------------ --

        # enroll email token for user and answer the challenge

        user = "passthru_user1"
        serial = "EMAIL_TOKEN_001"

        params = {
            "user": user,
            "type": "email",
            "pin": "123",
            "email_address": "test@example.com",
            "serial": serial,
        }
        response = self.make_admin_request("init", params=params)
        assert "false" not in response

        # ------------------------------------------------------------------ --

        # setup the mocking smtp client from which we get the sendmail args
        # to verify the template processing

        with MockedSMTP() as mock_smtp_instance:

            mock_smtp_instance.sendmail.return_value = []

            # -------------------------------------------------------------- --

            # now trigger a challenge for the user

            # to test the EMAIL_CHALLENGE_PROMPT we set it in the config
            prompt = "How are you email challenge?"
            params = {"EMAIL_CHALLENGE_PROMPT": prompt}
            response = self.make_system_request("setConfig", params)

            assert prompt in response, response
            assert response.json["result"]["status"], response

            params = {"user": user, "pass": "123"}
            response = self.make_validate_request("check", params=params)

            assert "false" in response
            assert response.json["detail"]["message"] == prompt

            jresp = json.loads(response.body)
            transaction_id = jresp["detail"]["transactionid"]

            call_args = mock_smtp_instance.sendmail.call_args
            _from, _to, message = call_args[0]
            otp = message.rpartition("\n")[2].strip()

            # unset the config entry
            params = {"key": "EMAIL_CHALLENGE_PROMPT"}
            response = self.make_system_request("delConfig", params)

            assert (
                '"delConfig EMAIL_CHALLENGE_PROMPT": true' in response
            ), response

            # -------------------------------------------------------------- --

            # now trigger a second challenge for the user which is blocked

            params = {"user": user, "pass": "123"}
            response = self.make_validate_request("check", params=params)

            assert "false" in response
            assert '"message": "e-mail with otp already submitted"' in response

            params = {
                "user": user,
                "pass": otp,
                "transactionid": transaction_id,
            }
            response = self.make_validate_request("check", params=params)

            assert "false" not in response

            # -------------------------------------------------------------- --

            # now trigger a challenge for the user -
            # which should now be possible without blocking

            params = {"user": user, "pass": "123"}
            response = self.make_validate_request("check", params=params)

            assert "false" in response

            assert '"message": "e-mail sent successfully"' in response


# eof

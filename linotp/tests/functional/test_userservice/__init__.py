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

import json

from linotp.tests import TestController

from .qr_token_validation import QR_Token_Validation as QR


class TestUserserviceController(TestController):
    def setUp(self):
        TestController.setUp(self)
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.create_common_resolvers()
        self.create_common_realms()
        self.setup_token_policies()

    def tearDown(self):
        TestController.tearDown(self)
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_policies()
        self.delete_all_token()

    def define_sms_provider(self, provider_params=None):
        """
        define the new provider via setProvider
        """
        params = {
            "name": "newone",
            "config": '{"file":"/tmp/newone"}',
            "timeout": "301",
            "type": "sms",
            "class": "smsprovider.FileSMSProvider.FileSMSProvider",
        }

        if provider_params:
            params.update(provider_params)

        response = self.make_system_request("setProvider", params=params)

        return response

    def define_email_provider(self, provider_params=None):
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

        if provider_params:
            params.update(provider_params)

        return self.make_system_request("setProvider", params=params)

    def setup_token_policies(self):
        cb_url = "/foo/bar/url"
        params = {
            "name": "dummy1",
            "scope": "authentication",
            "realm": "*",
            "action": f"qrtoken_pairing_callback_url={cb_url}, qrtoken_challenge_callback_url={cb_url}",
            "user": "*",
        }
        self.make_system_request(action="setPolicy", params=params)
        params = {
            "name": "enroll_policy",
            "scope": "selfservice",
            "realm": "*",
            "action": "activate_QRToken, enrollQR, verify",
            "user": "*",
        }
        self.make_system_request(action="setPolicy", params=params)

    def enroll_qr_token(
        self, user="passthru_user1@myDefRealm", serial="qrtoken", pin=""
    ):
        secret_key, public_key = QR.create_keys()
        params = {"type": "qr", "user": user, "serial": serial, "pin": pin}
        response = self.make_admin_request("init", params)
        pairing_url = QR.get_pairing_url_from_response(response)
        token_info = QR.create_user_token_by_pairing_url(pairing_url)
        pairing_response = QR.create_pairing_response(
            public_key, token_info, token_id=1
        )
        params = {"pairing_response": pairing_response}
        response = self.make_validate_request("pair", params)
        # trigger a challenge
        params = {"serial": serial, "pass": pin, "data": serial}
        response = self.make_validate_request("check_s", params)
        detail = response.json.get("detail")
        assert "transactionid" in detail
        assert "message" in detail

        # verify the transaction
        # calculate the challenge response from the returned message
        # for verification we can use tan or sig
        message = detail.get("message")
        challenge, _sig, tan = QR.calculate_challenge_response(
            message, token_info, secret_key
        )
        params = {"transactionid": challenge["transaction_id"], "pass": tan}
        response = self.make_validate_request("check_t", params)
        assert "false" not in response

        return token_info, secret_key, public_key

    def enroll_pw_token(
        self, user="passthru_user1@myDefRealm", serial="pwtoken", pin="1234"
    ):
        """
        Enroll a password token for the user
        """
        params = {
            "type": "pw",
            "user": user,
            "serial": serial,
            "pin": pin,
            "otpkey": "",
        }
        response = self.make_admin_request("init", params)
        assert response.json["result"]["value"] is True
        return serial

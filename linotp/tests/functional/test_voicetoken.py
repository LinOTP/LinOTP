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

import json

from mock import patch

from linotp.tests import TestController


class TestVoiceToken(TestController):
    def setUp(self):

        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        super(TestVoiceToken, self).setUp()
        self.create_common_resolvers()
        self.create_common_realms()
        self.create_voice_provider()
        self.create_policies()

    def tearDown(self):

        self.delete_all_policies()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_token()
        super(TestVoiceToken, self).tearDown()

    def create_voice_provider(self):
        """
        Creates a voice provider 'DevVoiceProv' with
        dummy configuration
        """

        configDict = {}

        configDict["twilioConfig"] = {
            "accountSid": "ACf9095f540f0b090edbd239b99230a8ee",
            "authToken": "8f36aab7ca485b432500ce49c15280c5",
            "voice": "alice",
            "callerNumber": "+4989231234567",
        }

        configDict["server_url"] = "https://mydummy"

        params = {
            "name": "DefVoiceProv",
            "class": "CustomVoiceProvider",
            "config": json.dumps(configDict),
            "timeout": "120",
            "type": "voice",
        }

        self.make_system_request("setProvider", params=params)

    def create_policies(self):
        """
        Creates test values for the following policies:

        * authentication/voice_message
        * authentication/voice_language
        * authentication/voice_provider
        """

        params = {
            "name": "voice_policies",
            "scope": "authentication",
            "action": "voice_language=de, "
            "voice_message=Hi! {otp},"
            "voice_provider=DefVoiceProv",
            "user": "*",
            "realm": "*",
            "client": "",
            "time": "",
        }

        self.create_policy(params=params)

    @patch(
        "linotp.provider.voiceprovider.custom_voice_provider."
        "CustomVoiceProvider.submitVoiceMessage"
    )
    def test_validate_check(self, mocked_submit_method):
        """VoiceToken: Check if validate/check works correctly"""

        serial = "KIVO123foobar789"
        token_phone_number = "123987456787"

        params = {
            "type": "voice",
            "serial": serial,
            "pin": "1234",
            "phone": token_phone_number,
            "user": "passthru_user1@myDefRealm",
        }

        response = self.make_admin_request("init", params)
        response_dict = json.loads(response.body)
        assert "detail" in response_dict

        # trigger voice challenge

        mocked_submit_method.return_value = (True, "lmao")

        params = {"user": "passthru_user1@myDefRealm", "pass": "1234"}

        response = self.make_validate_request("check", params)
        response_dict = json.loads(response.body)
        result = response_dict.get("result", {})
        status = result.get("status")
        value = result.get("value")
        detail = response_dict.get("detail", {})
        transaction_id = detail.get("transactionid")
        assert transaction_id is not None

        assert status
        assert not value

        _, call_kwargs = mocked_submit_method.call_args
        callee_number = call_kwargs.get("calleeNumber")
        assert callee_number == token_phone_number
        otp = call_kwargs.get("otp")

        # respond to challenge with correct otp

        params = {
            "user": "passthru_user1@myDefRealm",
            "transactionid": transaction_id,
            "pass": otp,
        }

        response = self.make_validate_request("check", params)
        response_dict = json.loads(response.body)
        result = response_dict.get("result", {})
        status = result.get("status")
        value = result.get("value")

        assert status
        assert value

        # trigger another voice challenge

        mocked_submit_method.return_value = (True, "lmao")

        params = {"user": "passthru_user1@myDefRealm", "pass": "1234"}

        response = self.make_validate_request("check", params)
        response_dict = json.loads(response.body)
        result = response_dict.get("result", {})
        status = result.get("status")
        value = result.get("value")
        detail = response_dict.get("detail", {})
        transaction_id = detail.get("transactionid")
        assert transaction_id is not None

        assert status
        assert not value

        _, call_kwargs = mocked_submit_method.call_args
        callee_number = call_kwargs.get("calleeNumber")
        assert callee_number == token_phone_number
        otp = call_kwargs.get("otp")

        # respond to challenge with a wrong otp

        # generate an otp that has the same length, but is
        # is guaranteed to be different
        wrong_otp = str((int(otp) + 1) % 10 ** len(otp)).zfill(len(otp))

        params = {
            "user": "passthru_user1@myDefRealm",
            "transactionid": transaction_id,
            "pass": wrong_otp,
        }

        response = self.make_validate_request("check", params)
        response_dict = json.loads(response.body)
        result = response_dict.get("result", {})
        status = result.get("status")
        value = result.get("value")

        assert status
        assert not value

        # trigger another voice challenge for check with pin+otp

        mocked_submit_method.return_value = (True, "lmao")

        params = {"user": "passthru_user1@myDefRealm", "pass": "1234"}

        response = self.make_validate_request("check", params)
        response_dict = json.loads(response.body)
        result = response_dict.get("result", {})
        status = result.get("status")
        value = result.get("value")
        detail = response_dict.get("detail", {})
        transaction_id = detail.get("transactionid")
        assert transaction_id is not None

        assert status
        assert not value

        _, call_kwargs = mocked_submit_method.call_args
        callee_number = call_kwargs.get("calleeNumber")
        assert callee_number == token_phone_number
        otp = call_kwargs.get("otp")

        # respond to challenge with pin+otp and without
        # transaction_id

        params = {"user": "passthru_user1@myDefRealm", "pass": "1234" + otp}

        response = self.make_validate_request("check", params)
        response_dict = json.loads(response.body)
        result = response_dict.get("result", {})
        status = result.get("status")
        value = result.get("value")

        assert status
        assert value

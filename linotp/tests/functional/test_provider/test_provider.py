# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
test the administrative handling of providers:
  * create new provider
  * check for default provider
  * define default provider
  * usage of provider via policy
  * fallback to default if policy does not match
"""

import json
import logging
import os

from mock import patch

import linotp.provider.smsprovider.FileSMSProvider
import linotp.provider.voiceprovider.custom_voice_provider
from linotp.tests import TestController

log = logging.getLogger(__name__)


# mocking hook is starting here
SMS_MESSAGE_OTP = ("", "")
SMS_MESSAGE_CONFIG = {}


def mocked_submitMessage(FileSMS_Object, *argparams, **kwparams):
    # this hook is defined to grep the otp and make it globaly available
    global SMS_MESSAGE_OTP
    SMS_MESSAGE_OTP = argparams

    # we call here the original sms submitter - as we are a functional test
    global SMS_MESSAGE_CONFIG
    SMS_MESSAGE_CONFIG = FileSMS_Object.config

    return True


def mocked_connectiontest(CustomVoiceProvider_Object, *argparams, **kwparams):
    return True, "Bad Request"


class TestProviderController(TestController):
    def setUp(self):
        self.removeProviderConfig()

        super(TestProviderController, self).setUp()
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.removeProviderConfig()

        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_policies()

        super(TestProviderController, self).tearDown()

    def create_sms_token(self, serial=None, token_params=None):
        params = {
            "otpkey": (
                "1234567890123456789012345678901234567890"
                "123456789012345678901234"
            ),
            "realm": "myDefRealm",
            "type": "sms",
            "user": "user1",
            "pin": "1234",
            "phone": "016012345678",
        }

        if token_params:
            params.update(token_params)
        if serial:
            params["serial"] = serial

        response = self.make_admin_request(action="init", params=params)

        return response

    def setPolicy(self, policy_params=None):
        params = {
            "name": "smsprovider_newone",
            "scope": "authentication",
            "realm": "*",
            "action": "sms_provider=newone",
            "user": "*",
        }
        if policy_params:
            params.update(policy_params)

        response = self.make_system_request(action="setPolicy", params=params)

        return response

    def define_legacy_provider(self, provider_params=None):
        """
        define the legacy provider via setConfig
        """
        params = {
            "SMSProviderTimeout": "301",
            "SMSProviderConfig": '{"file":"/tmp/legacy"}',
            "SMSProvider": "smsprovider.FileSMSProvider.FileSMSProvider",
            "SMSProviderConfig.type": "password",
        }

        if provider_params:
            params.update(provider_params)

        response = self.make_system_request("setConfig", params=params)

        return response

    def removeProviderConfig(self):
        entries = [
            "Provider.Default.",
            "SMSProvider",
            "EmailProvider",
            "PushProvider",
            "VoiceProvider",
        ]

        for entry in entries:
            self.delete_config(prefix=entry)

    def define_new_provider(self, provider_params=None):
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

    def test_create_legacy_provider(self):
        """
        check if legacy provider is default after create
        """
        response = self.define_legacy_provider()
        assert "/tmp/legacy" in response, response

        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("imported_default", {})
        assert provider.get("Default", False), response

        params = {"type": "email"}
        response = self.make_system_request("getProvider", params=params)
        assert '"value": {}' in response, response

    def test_create_new_provider(self):
        """
        check if new provider is default after create
        """
        response = self.define_new_provider()
        assert '"value": true' in response, response

        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("newone", {})
        assert provider.get("Default", False), response

        response = self.define_legacy_provider()
        assert "/tmp/legacy" in response, response

        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("imported_default", {})
        assert not provider.get("Default", False), response

    def test_create_unicode_provider(self):
        """
        check if new provider is default after create
        """
        config = '{"file": "/tmp/müßte_gèhn"}'

        # ------------------------------------------------------------------ --

        # verify the new provider interface

        provider_params = {"config": config.encode("utf-8")}
        response = self.define_new_provider(provider_params=provider_params)
        assert '"value": true' in response, response

        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("newone", {})
        assert provider.get("Default", False), response

        p_config = provider.get("Config", "")
        assert config == p_config, jresp

        # ------------------------------------------------------------------ --

        # verify the old provider interface done via setConfig

        provider_params = {"SMSProviderConfig": config.encode("utf-8")}
        response = self.define_legacy_provider(provider_params=provider_params)
        assert "/tmp/m" in response, response

        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("imported_default", {})
        assert not provider.get("Default", False), response

        p_config = provider.get("Config", "")
        assert config == p_config, jresp

    @patch.object(
        linotp.provider.smsprovider.FileSMSProvider.FileSMSProvider,
        "submitMessage",
        mocked_submitMessage,
    )
    def test_legacy_default_provider(self):
        """
        check if legacy provider is loaded by default
        """

        response = self.define_legacy_provider()
        assert "/tmp/legacy" in response, response

        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("imported_default", {})
        assert provider.get("Default", False), response

        serial = "sms1234"
        response = self.create_sms_token(serial=serial)
        assert serial in response

        params = {"serial": serial, "pass": "1234"}
        response = self.make_validate_request("check_s", params=params)
        assert response.json["result"]["status"], response

        global SMS_MESSAGE_CONFIG
        assert "/tmp/legacy" in SMS_MESSAGE_CONFIG.get("file")

    @patch.object(
        linotp.provider.smsprovider.FileSMSProvider.FileSMSProvider,
        "submitMessage",
        mocked_submitMessage,
    )
    def test_new_provider(self):
        """
        check if legacy provider is loaded by default
        """

        response = self.define_new_provider()
        assert '"value": true' in response, response

        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("newone", {})
        assert provider.get("Default", False), response

        serial = "sms1234"
        response = self.create_sms_token(serial=serial)
        assert serial in response

        params = {"serial": serial, "pass": "1234"}
        response = self.make_validate_request("check_s", params=params)
        assert response.json["result"]["status"], response

        global SMS_MESSAGE_CONFIG
        assert "/tmp/newone" in SMS_MESSAGE_CONFIG.get("file")

    @patch.object(
        linotp.provider.smsprovider.FileSMSProvider.FileSMSProvider,
        "submitMessage",
        mocked_submitMessage,
    )
    def test_provider_via_policy(self):
        """
        check if new provider is loaded by policy
        """

        # create legacy provider
        response = self.define_legacy_provider()
        assert "/tmp/legacy" in response, response

        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("imported_default", {})
        assert provider.get("Default", False), response

        # create new provider
        response = self.define_new_provider()
        assert '"value": true' in response, response

        # check that this is not the default one
        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)
        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("newone", {})
        assert not provider.get("Default", True), response

        # define smsprovider policy to use the 'newone'
        response = self.setPolicy()
        assert '"setPolicy smsprovider_newone"' in response, response

        # trigger sms and check that the correct provider is used
        serial = "sms1234"
        response = self.create_sms_token(serial=serial)
        assert serial in response

        params = {"serial": serial, "pass": "1234"}
        response = self.make_validate_request("check_s", params=params)
        assert response.json["result"]["status"], response

        global SMS_MESSAGE_CONFIG
        assert "/tmp/newone" in SMS_MESSAGE_CONFIG.get("file")

    @patch.object(
        linotp.provider.smsprovider.FileSMSProvider.FileSMSProvider,
        "submitMessage",
        mocked_submitMessage,
    )
    def test_default_provider_via_policy(self):
        """
        check if default provider is loaded if policy does not match
        """

        # create new provider
        response = self.define_new_provider()
        assert '"value": true' in response, response

        # check that this is the default one
        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)
        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("newone", {})
        assert provider.get("Default", False), response

        # create legacy provider
        response = self.define_legacy_provider()
        assert "/tmp/legacy" in response, response

        # check that legacy provider is not the default one
        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("imported_default", {})
        assert not provider.get("Default", True), response

        # set legacy provider as default provider
        params = {"type": "sms", "name": "imported_default"}
        response = self.make_system_request(
            "setDefaultProvider", params=params
        )
        assert '"value": true' in response

        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)
        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("imported_default", {})
        assert provider.get("Default", False), response

        # define sms provider policy to use the 'newone'
        response = self.setPolicy(
            policy_params={
                "user": "egon",
            }
        )
        assert '"setPolicy smsprovider_newone"' in response, response

        # trigger sms and check that the default provider is used
        serial = "sms1234"
        response = self.create_sms_token(serial=serial)
        assert serial in response

        params = {"serial": serial, "pass": "1234"}
        response = self.make_validate_request("check_s", params=params)
        assert response.json["result"]["status"], response

        global SMS_MESSAGE_CONFIG
        assert "/tmp/legacy" in SMS_MESSAGE_CONFIG.get("file")

    def test_managed_provider(self):
        """
        check that a managed provider does not return the configuration
        """

        response = self.define_new_provider()
        assert '"value": true' in response, response

        response = self.define_new_provider(
            {"managed": "mypass", "name": "managed_one"}
        )
        assert '"value": true' in response, response

        params = {"type": "sms"}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get("managed_one", {})
        assert not provider.get("Default", True), response

        response = self.define_new_provider(
            {"managed": "wrongpass", "name": "managed_one"}
        )
        msg = "Not allowed to overwrite "
        assert msg in response, response

        response = self.define_new_provider(
            {"managed": "mypass", "name": "managed_one"}
        )
        assert '"value": true' in response, response

        params = {"managed": "mypass", "name": "managed_one", "type": "sms"}
        self.make_system_request("delProvider", params)
        assert '"value": true' in response, response

    @patch.object(
        linotp.provider.voiceprovider.custom_voice_provider.CustomVoiceProvider,
        "test_connection",
        mocked_connectiontest,
    )
    def test_voice_provider(self):
        """
        check if custom voice provider could be saved, retrieved and deleted
        """
        # ----------------------------------------------------------------- --

        # basic voice provider configuartion

        configDict = {
            "access_certificate": os.path.join(self.fixture_path, "cert.pem"),
        }

        configDict["twilioConfig"] = {
            "accountSid": "ACf9095f540f0b090edbd239b99230a8ee",
            "authToken": "8f36aab7ca485b432500ce49c15280c5",
            "callerNumber": "+4989231234567",
            "voice": "alice",
        }

        configDict["server_url"] = "https://vcs.keyidentity.com/"

        # ----------------------------------------------------------------- --

        # define the new provider, which should become default

        provider_name = "new_voice"

        provider_params = {
            "name": provider_name,
            "config": json.dumps(configDict),
            "timeout": "301",
            "type": "voice",
            "class": "CustomVoiceProvider",
        }

        response = self.define_new_provider(provider_params=provider_params)
        assert '"value": true' in response, response

        # ----------------------------------------------------------------- --

        # check for the loaded provider, which should be default

        params = {"type": "voice"}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get(provider_name, {})
        assert provider.get("Default", False), response

        params = {"type": "voice", "name": provider_name}
        response = self.make_system_request("testProvider", params=params)
        assert '"value": true' in response, response

        # ----------------------------------------------------------------- --

        # define second provider, which should not be default and could be
        # deleted

        provider_name_2 = "new_voice_2"

        provider_params = {
            "name": provider_name_2,
            "config": json.dumps(configDict),
            "timeout": "301",
            "type": "voice",
            "class": "CustomVoiceProvider",
        }

        response = self.define_new_provider(provider_params=provider_params)
        assert '"value": true' in response, response

        # ----------------------------------------------------------------- --

        # lookup for the new provider, which should not be default

        params = {"type": "voice", "name": provider_name_2}
        response = self.make_system_request("getProvider", params=params)

        jresp = json.loads(response.body)
        provider = jresp["result"]["value"].get(provider_name_2, {})
        assert not provider.get("Default", False), response

        # ----------------------------------------------------------------- --

        # finally we can delete the second, non default one

        params = {"type": "voice", "name": provider_name_2}
        response = self.make_system_request("delProvider", params=params)
        assert '"value": true' in response, response


# eof #####################################################################

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
    functional test for the CustomVoiceProvider:
    - check the CustomVoiceProvider functions

"""

import json
import logging
import os

import pytest
import requests
from mock import patch

from linotp.provider.voiceprovider.custom_voice_provider import (
    CustomVoiceProvider,
)
from linotp.tests import TestController

VALID_REQUEST = "You received an authentication request."

log = logging.getLogger(__name__)


def mocked_http_request(HttpObject, *argparams, **kwparams):
    class Response:
        pass

    r = Response()

    request_url = argparams[0]
    request_body = kwparams["json"]

    r.status = TestVoiceProviderController.R_AUTH_STATUS
    r.text = TestVoiceProviderController.R_AUTH_DETAIL

    if r.status == 200:
        r.ok = True
        r.content = json.dumps(
            {"text": r.text, "url": request_url, "body": request_body}
        )
        return r

    r.ok = False
    r.reason = r.text

    return r


class TestVoiceProviderController(TestController):
    """
    test the push provider
    """

    R_AUTH_STATUS = 200
    R_AUTH_DETAIL = VALID_REQUEST

    VCS_URL = "https://vcs.keyidentity.com/v1/twilio/call"

    def setUp(self):
        return

    def tearDown(self):
        self.delete_all_resolvers()
        super(TestVoiceProviderController, self).tearDown()

    def test_read_config(self):
        """
        test push provider configuration handling
        """

        voice_provider = CustomVoiceProvider()

        #
        # first test the valid configuration
        #
        configDict = {
            "access_certificate": os.path.join(self.fixture_path, "cert.pem"),
        }

        configDict["twilioConfig"] = {
            "accountSid": "ACf9095f540f0b090edbd239b99230a8ee",
            "authToken": "8f36aab7ca485b432500ce49c15280c5",
            "voice": "alice",
            "callerNumber": "+4989231234567",
        }

        configDict["Timeout"] = "30"
        configDict["server_url"] = self.VCS_URL

        voice_provider.loadConfig(configDict)

        #
        # verify server url check
        #

        with pytest.raises(requests.exceptions.InvalidSchema):
            configDict["server_url"] = "hXXXs://vcs.keyidentity.com:8800/send"
            voice_provider.loadConfig(configDict)

        #
        # restore configuration for server_url
        #

        configDict["server_url"] = self.VCS_URL

        #
        # extended option: proxy
        #

        configDict["proxy"] = "https://proxy.keyidentity.com:8800/"
        voice_provider.loadConfig(configDict)

        #
        # extended option: proxy with wrong url scheme
        #

        with pytest.raises(requests.exceptions.InvalidSchema):
            configDict["proxy"] = "hXXXs://proxy.keyidentity.com:8800/"
            voice_provider.loadConfig(configDict)

        # restore valid proxy url
        configDict["proxy"] = "https://proxy.keyidentity.com:8800/"

        #
        # valid extended timeout format
        #

        configDict["timeout"] = "3,10"
        voice_provider.loadConfig(configDict)

        del configDict["timeout"]

        #
        # invalid timeout format: "invalid literal for float()"
        #

        with pytest.raises(ValueError):
            configDict["Timeout"] = "30s"
            voice_provider.loadConfig(configDict)

        # timeout has a default and is not required
        del configDict["Timeout"]

        #
        # non existing certificate file - should raise exception
        # 'required authenticating client cert could not be found'
        #

        with pytest.raises(IOError):
            cert_file_name = os.path.join(self.fixture_path, "non_exist.pem")
            configDict["access_certificate"] = cert_file_name
            voice_provider.loadConfig(configDict)

        #
        # test if access_certificate is optional
        #

        del configDict["access_certificate"]
        voice_provider.loadConfig(configDict)

        # restore access certificate parameter
        cert_file_name = os.path.join(self.fixture_path, "cert.pem")
        configDict["access_certificate"] = cert_file_name

        # check if missing server_url is as well detected
        with pytest.raises(KeyError):
            del configDict["server_url"]
            voice_provider.loadConfig(configDict)

        # restore required server_url
        configDict["server_url"] = self.VCS_URL

        #
        # check if server cert is provided, the existance of directory or
        # file is made
        #

        server_cert_file_name = os.path.join(self.fixture_path, "cert.pem")
        configDict["server_certificate"] = server_cert_file_name
        voice_provider.loadConfig(configDict)

        with pytest.raises(IOError):
            server_cert_file_name = "/abc/ssl/certs"
            configDict["server_certificate"] = server_cert_file_name
            voice_provider.loadConfig(configDict)

        return

    @patch.object(requests.Session, "post", mocked_http_request)
    def test_request(self):
        """
        do some mocking of a requests request
        """

        configDict = {
            "access_certificate": os.path.join(self.fixture_path, "cert.pem"),
        }

        configDict["twilioConfig"] = {
            "accountSid": "ACf9095f540f0b090edbd239b99230a8ee",
            "authToken": "8f36aab7ca485b432500ce49c15280c5",
            "callerNumber": "+4989231234567",
            "voice": "alice",
        }

        configDict["Timeout"] = "30"
        configDict["server_url"] = self.VCS_URL

        voice_provider = CustomVoiceProvider()
        voice_provider.loadConfig(configDict)

        messageTemplate = "Your otp is {otp}"
        otp = "432423"
        locale = "en"
        calleeNumber = "+49 6151 860 860"

        # set the response status
        TestVoiceProviderController.R_AUTH_STATUS = 200

        # run the fake request
        status, response = voice_provider.submitVoiceMessage(
            calleeNumber, messageTemplate, otp, locale
        )

        assert status
        assert VALID_REQUEST in response

        request_json = json.loads(response)

        target_url = "https://vcs.keyidentity.com/v1/twilio/call"
        assert target_url in request_json.get("url")

        # compare the request dictionary, with the expected structure

        cmp_content = {
            "call": {
                "messageTemplate": "Your otp is {otp}",
                "otp": "432423",
                "locale": "en",
                "calleeNumber": "+49 6151 860 860",
                "twilioConfig": {
                    "authToken": "8f36aab7ca485b432500ce49c15280c5",
                    "accountSid": "ACf9095f540f0b090edbd239b99230a8ee",
                    "voice": "alice",
                    "callerNumber": "+4989231234567",
                },
            }
        }

        assert request_json.get("body") == cmp_content


# eof #

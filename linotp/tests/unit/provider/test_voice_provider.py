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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#


import os
import unittest

from mock import patch

import linotp.provider.voiceprovider.custom_voice_provider
from linotp.provider.voiceprovider.custom_voice_provider import (
    CustomVoiceProvider,
)

# submitVoiceMessage


def mocked_make_http_post_request_(
    CustomVoiceProvider_Object, *argparams, **kwparams
):
    return True, "all ok"


fixture_path = os.path.abspath(
    os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "..",
        "functional",
        "fixtures",
    )
)


class TestVoiceProvider(unittest.TestCase):
    """
    unit test for voice provider
    """

    @patch.object(
        linotp.provider.voiceprovider.custom_voice_provider.CustomVoiceProvider,
        "_make_http_post_request_",
        mocked_make_http_post_request_,
    )
    def test_warning_called(self):
        """
        test the log.warning, if no {otp} in template
        """
        custom_provider = CustomVoiceProvider()

        configDict = {
            "access_certificate": os.path.join(fixture_path, "cert.pem"),
        }

        configDict["twilioConfig"] = {
            "accountSid": "ACf9095f540f0b090edbd239b99230a8ee",
            "authToken": "8f36aab7ca485b432500ce49c15280c5",
            "voice": "alice",
            "callerNumber": "+4989231234567",
        }

        configDict["Timeout"] = "30"
        vcs_url = "http://vcs-service.keyidentity.com/v1/twilio/call"
        configDict["server_url"] = vcs_url
        custom_provider.loadConfig(configDict)

        with patch(
            "linotp.provider.voiceprovider."
            "custom_voice_provider.log.warning"
        ) as mocked_log_warning:

            custom_provider.submitVoiceMessage(
                "+49 123546891", "your otp", "123456", "en"
            )
            called = mocked_log_warning.called

        with patch(
            "linotp.provider.voiceprovider."
            "custom_voice_provider.log.warning"
        ) as mocked_log_warning:

            custom_provider.submitVoiceMessage(
                "+49 123546891", "your {otp}", "123456", "en"
            )
            called2 = mocked_log_warning.called

        return


# eof #

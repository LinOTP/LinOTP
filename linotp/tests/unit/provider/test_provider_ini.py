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
import os
import unittest

from mock import patch

from linotp.provider import load_provider_ini, save_new_provider


class TestProviderTestCase(unittest.TestCase):
    """
    unit test for provider methods
    """

    provider_ini = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "../testdata/provider.ini"
    )

    testdata = [
        {
            "name": "Test1",
            "default": "False",
            "config": "{\n"
            '"push_url": "https://push.keyidentity.com/send",\n'
            '"access_certificate": "/etc/linotp/push-license.pem",\n'
            '"server_certificate": "/etc/linotp/push-ca-bundle.crt"\n'
            "}",
            "timeout": "120",
            "type": "push",
            "class": "DefaultPushProvider",
        },
        {
            "name": "newone",
            "default": "True",
            "config": '{"file":"/tmp/müßte_gèhn"}',
            "timeout": "301",
            "type": "sms",
            "class": "smsprovider.FileSMSProvider.FileSMSProvider",
        },
        {
            "managed": "$6$..hNcgTtOhvkQlIW$fuF/LWmmXPmPVjvEWd8kCdZN3KetoNQRn9Dn././0XAOFtoHDUIBow3qU2eO1ngV0bxwaPmgDGjqvlSG4HizE.",
            "name": "managed_one",
            "default": "False",
            "type": "sms",
            "timeout": "301",
            "config": '{"file":"/tmp/newone"}',
            "class": "smsprovider.FileSMSProvider.FileSMSProvider",
        },
    ]

    class MockedFileSMSProvider(object):
        def getConfigMapping(self):
            config_mapping = {
                "timeout": ("Timeout", None),
                "config": ("Config", "password"),
            }
            return config_mapping

    @patch("linotp.provider.setProvider")
    def test_load_provider_ini(self, mock_setProvider):
        mock_setProvider.return_value = (True, {})
        load_provider_ini(self.provider_ini)
        for data in self.testdata:
            mock_setProvider.assert_any_call(data)

    @patch("linotp.provider._load_provider_class")
    @patch("linotp.provider.storeConfig")
    def test_save_managed_provider_from_ini(self, mock_storeConfig, mock_load_provider):
        """
        save provider from ini file
        """
        mock_storeConfig.return_value = True
        mock_load_provider.return_value = self.MockedFileSMSProvider()

        params = self.testdata[2]
        provider_type = params["type"]
        provider_name = params["name"]
        provider_prefix = "linotp.SMSProvider.managed_one"

        res = save_new_provider(provider_type, provider_name, params)
        try:
            mock_storeConfig.assert_any_call(
                key=provider_prefix + "." + "Config",
                val='{"file":"/tmp/newone"}',
                typ="password",
            )
            mock_storeConfig.assert_any_call(
                key=provider_prefix + "." + "Managed",
                val=params["managed"],
                typ=None,
            )
            mock_storeConfig.assert_any_call(
                key=provider_prefix + "." + "Timeout", val="301", typ=None
            )
            mock_storeConfig.assert_any_call(
                key=provider_prefix,
                val="smsprovider.FileSMSProvider.FileSMSProvider",
            )

        except AssertionError as aserror:
            call_args_list = mock_storeConfig.call_args_list
            raise Exception(
                "Error was: %r, calls were: %r" % (aserror.message, call_args_list)
            )

        assert res == (True, {})

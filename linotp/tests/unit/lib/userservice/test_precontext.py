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
"verfify that the userservice pre_context works as intended"

import unittest

import pytest
from mock import patch

from linotp.lib.userservice import get_pre_context


@pytest.mark.usefixtures("app")
class TestPrecontext(unittest.TestCase):
    @patch("linotp.lib.userservice.get_selfservice_action_value")
    @patch("linotp.lib.userservice.getRealmBox")
    @patch("linotp.lib.userservice.getDefaultRealm")
    @patch("linotp.lib.userservice._get_realms_")
    @patch("linotp.lib.userservice.get_copyright_info")
    @patch("linotp.lib.userservice.get_version")
    def test_footer_fields(
        self,
        mock_get_version,
        mock_get_copyright_info,
        mock_get_realms,
        mock_getDefaultRealm,
        mock_getRealmBox,
        mock_get_selfservice_action_value,
    ):
        """
        verify that the precontext contains footer fields
        """

        mock_get_version.return_value = "version"
        mock_get_copyright_info.return_value = "copyright"
        mock_get_realms.return_value = "realms"
        mock_getDefaultRealm.return_value = "realm"
        mock_getRealmBox.return_value = True
        mock_get_selfservice_action_value.side_effect = [
            False,
            False,
            False,
            False,
            "footer",
            "imprint",
            "privacy",
        ]

        client = "127.0.0.1"

        assert get_pre_context(client) == {
            "version": "version",
            "copyright": "copyright",
            "realms": "realms",
            "settings": {
                "default_realm": "realm",
                "realm_box": True,
                "mfa_login": False,
                "mfa_3_fields": False,
                "autoassign": False,
                "autoenroll": False,
                "footer_text": "footer",
                "imprint_url": "imprint",
                "privacy_notice_url": "privacy",
            },
        }

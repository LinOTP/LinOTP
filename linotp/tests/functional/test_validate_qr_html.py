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
Test the 'qr=html' challenge response of /validate/check
"""

from html import escape

from linotp.tests import TestController

PAYLOAD = "<img src=x onerror=alert(document.domain)>"


class TestValidateQrHtml(TestController):
    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

        params = {
            "name": "ch_resp",
            "scope": "authentication",
            "action": "challenge_response=hmac, ",
            "active": True,
            "user": "*",
            "realm": "*",
        }
        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response, response

        params = {
            "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
            "pin": "pin",
            "user": "passthru_user1",
            "type": "hmac",
            "serial": "QR_HTML_HMAC",
        }
        response = self.make_admin_request("init", params=params)
        assert '"value": true' in response, response

    def tearDown(self):
        self.delete_all_token()
        self.delete_all_policies()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def test_check_qr_html_escapes_reflected_params(self):
        """Request parameters reflected into the qr html page must be escaped."""

        params = {
            "user": "passthru_user1",
            "pass": "pin",
            "qr": "html",
            "data": PAYLOAD,
            PAYLOAD: "value",
        }
        response = self.make_validate_request("check", params=params)

        assert response.content_type.startswith("text/html"), response
        assert "challenge_qrcode" in response.body, response
        assert PAYLOAD not in response.body
        assert escape(PAYLOAD) in response.body

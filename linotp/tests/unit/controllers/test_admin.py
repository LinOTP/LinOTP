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
import copy
import unittest
from unittest import mock

import flask
import pytest

from linotp.controllers.admin import AdminController
from linotp.lib.user import User


@pytest.mark.usefixtures("app")
class TestAdminController(unittest.TestCase):
    token = {
        "LinOtp.TokenId": 201,
        "LinOtp.TokenInfo": '{\n"hashlib": "sha1", \n"timeShift": -10.0, \n"timeWindow": 180, \n"validity_period_end": "23/12/23 23:23", \n"validity_period_start": "01/01/01 01:01", \n"timeStep": "30"\n}',
        "LinOtp.OtpLen": 6,
        "LinOtp.TokenType": "TOTP",
        "LinOtp.TokenSerialnumber": "F722362",
        "LinOtp.CountWindow": 10,
        "User.username": "passthru_user1",
        "LinOtp.TokenDesc": "TestToken1",
    }

    token2 = {
        "LinOtp.TokenId": 201,
        "LinOtp.TokenInfo": "",
        "LinOtp.OtpLen": 6,
        "LinOtp.TokenType": "TOTP",
        "LinOtp.TokenSerialnumber": "F722362",
        "LinOtp.CountWindow": 10,
        "User.username": "passthru_user1",
        "LinOtp.TokenDesc": "TestToken1",
    }

    expected_subset = {
        "validity_period_start": "2001-01-01T01:01:00",
        "validity_period_end": "2023-12-23T23:23:00",
    }

    def test_parse_tokeninfo(self):
        """
        check if admin._parse_tokeninfo works
        """
        tok = copy.deepcopy(self.token)

        AdminController._parse_tokeninfo(tok)

        assert isinstance(tok.get("LinOtp.TokenInfo"), dict), (
            "TokenInfo is not of type dict!"
        )
        assert dict(tok.get("LinOtp.TokenInfo"), **self.expected_subset) == tok.get(
            "LinOtp.TokenInfo"
        ), tok.get("LinOtp.TokenInfo")

    @mock.patch("linotp.controllers.admin.TokenIterator")
    @mock.patch("linotp.controllers.admin.checkPolicyPre")
    @mock.patch("linotp.model.db.session")
    @mock.patch("linotp.controllers.admin.Response")
    @mock.patch("linotp.app.request")
    @mock.patch("linotp.controllers.admin.request_context", new={})
    @mock.patch("linotp.controllers.admin.BaseController.__init__", return_value=None)
    def check_token(
        self,
        mock_base,
        mock_request,
        mock_response,
        mock_session,
        mock_check_policy_pre,
        mock_TokenIterator,
        with_json,
    ):
        """
        call admin/show with/without argument tokeninfo_format
        and return if _parse_tokeninfo has been called
        """
        request_params = {
            "tokeninfo_format": with_json,
        }
        mock_check_policy_pre.return_value = {
            "active": False,
            "admin": "unittest",
        }
        tok = copy.deepcopy(self.token)
        mock_TokenIterator.return_value = [tok]

        flask.g.audit = {}

        # Add a mock user to the request context
        mock_user = User(login="admin", realm="adminrealm")
        # Create a new dict for request_context to avoid modifying the mock directly
        request_context = {"RequestUser": mock_user, "action": "show"}
        with mock.patch(
            "linotp.controllers.admin.request_context", new=request_context
        ):
            admin = AdminController()
            mock_request.json = request_params
            admin.show()

    @mock.patch("linotp.controllers.admin.AdminController._parse_tokeninfo")
    def test_with_tokeninfo_format(self, mock_parse_tokeninfo):
        self.check_token(with_json="json")
        mock_parse_tokeninfo.assert_called()

    @mock.patch("linotp.controllers.admin.AdminController._parse_tokeninfo")
    def test_without_tokeninfo_format(
        self,
        mock_parse_tokeninfo,
    ):
        self.check_token(with_json="")
        mock_parse_tokeninfo.assert_not_called()

    def test_parse_empty_tokeninfo(self):
        """
        verify that token info is valid even if it is initially empty
        """
        tok = copy.deepcopy(self.token2)
        AdminController._parse_tokeninfo(tok)

        assert tok["LinOtp.TokenInfo"] == {}

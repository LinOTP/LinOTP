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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
"""
Tests for google authenticator url
"""

import unittest
from mock import patch

from linotp.lib.apps import create_google_authenticator
from linotp.lib.policy import get_tokenissuer
from linotp.lib.policy import get_tokenlabel


class TestTokenLabel(unittest.TestCase):
    @patch("linotp.lib.policy.has_client_policy")
    @patch("linotp.lib.policy._get_client")
    def test_get_tokenlabel_wo_policy(
        self, mock__get_client, mock_has_client_policy
    ):

        mock__get_client.return_value = "localhost"
        mock_has_client_policy.return_value = {}

        res = get_tokenlabel(serial="123")
        assert res == "123"

        res = get_tokenlabel(serial="123", user="hugo")
        assert res == "hugo"

        res = get_tokenlabel(serial="123", user="hugo", realm="home")
        assert res == "hugo"

        res = get_tokenlabel(
            serial="123", user="hugo", realm="home", description="nothing"
        )
        assert res == "hugo"

    @patch("linotp.lib.policy.get_action_value")
    @patch("linotp.lib.policy.has_client_policy")
    @patch("linotp.lib.policy._get_client")
    def test_get_tokenlabel_w_policy(
        self, mock__get_client, mock_has_client_policy, mock_get_action_value
    ):

        mock__get_client.return_value = "localhost"
        mock_has_client_policy.return_value = {}
        mock_get_action_value.return_value = "<d>.<r>.<u>.<s>"

        res = get_tokenlabel(serial="!")
        assert res == "...!"

        res = get_tokenlabel(serial="!", user="matters")
        assert res == "..matters.!"

        res = get_tokenlabel(serial="!", user="matters", realm="else")
        assert res == ".else.matters.!"

        res = get_tokenlabel(
            serial="!", user="matters", realm="else", description="nothing"
        )
        assert res == "nothing.else.matters.!"

    @patch("linotp.lib.policy.has_client_policy")
    @patch("linotp.lib.policy._get_client")
    def test_get_tokenissuer_wo_policy(
        self, mock__get_client, mock_has_client_policy
    ):

        mock__get_client.return_value = "localhost"
        mock_has_client_policy.return_value = {}

        res = get_tokenissuer(serial="123")
        assert res == "LinOTP"

        res = get_tokenissuer(serial="123", user="hugo")
        assert res == "LinOTP"

        res = get_tokenissuer(serial="123", user="hugo", realm="home")
        assert res == "LinOTP"

        res = get_tokenissuer(
            serial="123", user="hugo", realm="home", description="nothing"
        )
        assert res == "LinOTP"

    @patch("linotp.lib.policy.get_action_value")
    @patch("linotp.lib.policy.has_client_policy")
    @patch("linotp.lib.policy._get_client")
    def test_get_tokenissuer_w_policy(
        self, mock__get_client, mock_has_client_policy, mock_get_action_value
    ):

        mock__get_client.return_value = "localhost"
        mock_has_client_policy.return_value = {}
        mock_get_action_value.return_value = "<d>.<r>.<u>.<s>"

        res = get_tokenissuer(serial="!")
        assert res == "...!"

        res = get_tokenissuer(serial="!", user="matters")
        assert res == "..matters.!"

        res = get_tokenissuer(serial="!", user="matters", realm="else")
        assert res == ".else.matters.!"

        res = get_tokenissuer(
            serial="!", user="matters", realm="else", description="nothing"
        )
        assert res == "nothing.else.matters.!"

    @patch("linotp.lib.policy.get_action_value")
    @patch("linotp.lib.policy.has_client_policy")
    @patch("linotp.lib.policy._get_client")
    def test_token_label_issuer_default(
        self, mock__get_client, mock_has_client_policy, mock_get_action_value
    ):
        """Google Authenticator url with default issuer and label

        with this empty setting
        - the tokenissuer should become 'LinOTP' and
        - the tokenlabel should become the serial

        using hmac non defaults: SHA256, 8 digits
        """

        mock__get_client.return_value = "localhost"
        mock_has_client_policy.return_value = {}
        mock_get_action_value.return_value = ""

        param = {
            "hashlib": "SHA256",
            "otpkey": "cc5bad98a76279171a08a5d18fd400e748945c2b",
            "serial": "HOTP1234",
            "otplen": "8",
            "type": "hmac",
        }

        url = create_google_authenticator(param=param)
        assert url.startswith("otpauth://hotp/LinOTP:HOTP1234?")

        assert "counter=0" in url
        assert "digits=8" in url
        assert "algorithm=SHA256" in url

        param["user.login"] = "hugo"
        url = create_google_authenticator(param=param)
        assert url.startswith("otpauth://hotp/LinOTP:hugo?")

        param["user.realm"] = "realm"
        url = create_google_authenticator(param=param)
        assert url.startswith("otpauth://hotp/LinOTP:hugo?")

        param["description"] = "description"
        url = create_google_authenticator(param=param)
        assert url.startswith("otpauth://hotp/LinOTP:hugo?")

    @patch("linotp.lib.policy.get_action_value")
    @patch("linotp.lib.policy.has_client_policy")
    @patch("linotp.lib.policy._get_client")
    def test_token_label_issuer_policy(
        self, mock__get_client, mock_has_client_policy, mock_get_action_value
    ):
        """Google Authenticator url with issuer and label policy set

        with this empty setting
        - the tokenissuer should become 'LinOTP' and
        - the tokenlabel should become the serial
        """

        mock__get_client.return_value = "localhost"
        mock_has_client_policy.return_value = {}
        mock_get_action_value.return_value = "<d>.<r>.<u>.<s>"

        param = {
            "hashlib": "SHA1",
            "otpkey": "cc5bad98a76279171a08a5d18fd400e748945c2b",
            "serial": "TOTP1234",
            "otplen": "6",
            "type": "totp",
            "timeStep": "30",
        }

        url = create_google_authenticator(param=param)
        assert url.startswith("otpauth://totp/...TOTP1234:...TOTP1234?")

        # verify that the totp / hotp defaults are not in the url
        assert "SHA1" not in url
        assert "period" not in url
        assert "digits" not in url

        param["user.login"] = "hugo"
        url = create_google_authenticator(param=param)
        msg = "otpauth://totp/..hugo.TOTP1234:..hugo.TOTP1234?"
        assert url.startswith(msg)

        param["user.realm"] = "realm"
        url = create_google_authenticator(param=param)
        msg = "otpauth://totp/.realm.hugo.TOTP1234:.realm.hugo.TOTP1234?"
        assert url.startswith(msg)

        param["description"] = "descr:ption"
        url = create_google_authenticator(param=param)
        msg = (
            "otpauth://totp/descr%3Aption.realm.hugo.TOTP1234:"
            "descr%3Aption.realm.hugo.TOTP1234?"
        )
        assert url.startswith(msg)


# eof #

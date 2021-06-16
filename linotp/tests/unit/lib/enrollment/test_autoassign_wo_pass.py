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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

import unittest

import pytest
from mock import patch

from flask import g

from linotp.lib.policy import (
    get_autoassignment_from_realm,
    get_autoassignment_without_pass,
)
from linotp.lib.token import TokenHandler
from linotp.lib.user import User
from linotp.tokens.passwordtoken import PasswordTokenClass


@pytest.mark.usefixtures("app")
class TestAutoEnroll(unittest.TestCase):
    @patch("linotp.lib.token.context")
    @patch("linotp.lib.token.TokenHandler.assignToken")
    @patch("linotp.lib.token.TokenHandler.getTokensOfType")
    @patch("linotp.lib.token.getTokens4UserOrSerial")
    @patch("linotp.lib.policy.get_autoassignment_without_pass")
    @patch("linotp.lib.policy.get_autoassignment_from_realm")
    def test_autenroll_wo_pass(
        self,
        mocked_policy_src_realm,
        mocked_policy_autosignment_wo,
        mockedgetTokens4UserOrSerial,
        mocked_getTokensOfType,
        mocked_assignToken,
        mocked_context,
    ):

        thdle = TokenHandler()

        options = {}
        user = User("Hugo", realm="def_realm")
        otp = "123467"

        class Token(object):

            LinOtpCountWindow = 10
            typ = ""

            def setType(self, type_name):
                self.typ = type_name

            def getType(self):
                return self.typ

            def getSerial(self):
                return "ABCDEFG"

        aToken = Token()

        class MockPasswordTokenClass(PasswordTokenClass):
            def check_otp_exist(self, *args, **kwargs):
                return 1

        pwtoken = MockPasswordTokenClass(aToken)

        mocked_policy_src_realm.return_value = None
        mocked_policy_autosignment_wo.return_value = True
        mockedgetTokens4UserOrSerial.return_value = []
        mocked_getTokensOfType.return_value = [pwtoken]
        mocked_assignToken.return_value = True

        g.audit = {}

        res = thdle.auto_assign_otp_only(otp, user, options)

        assert res
        assert mocked_assignToken.called

        return

    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.policy._get_client")
    @patch("linotp.lib.policy.get_client_policy")
    def test_get_autoassignment_without_pass(
        self,
        mocked_get_client_policy,
        mocked_get_client,
        mocked_get_policy_definitions,
    ):

        user = User("Hugo", realm="Home_realm")

        mocked_get_client_policy.return_value = {
            "my_autoassign_policy_wo_pass": {
                "realm": "mydefrealm",
                "active": "True",
                "client": "*",
                "user": "*",
                "time": "*",
                "action": "autoassignment_without_password=True",
                "scope": "enrollment",
            }
        }
        mocked_get_client.return_value = "127.0.0.1"

        mocked_get_policy_definitions.return_value = {
            "enrollment": {"autoassignment_without_password": {"type": "bool"}}
        }

        res = get_autoassignment_without_pass(user=user)
        assert res

        mocked_get_client_policy.return_value = {
            "my_autoassign_policy_wo_pass": {
                "realm": "mydefrealm",
                "active": "True",
                "client": "*",
                "user": "*",
                "time": "*",
                "action": "autoassignment_without_password",
                "scope": "enrollment",
            }
        }

        res = get_autoassignment_without_pass(user=user)
        assert res

        mocked_get_client_policy.return_value = {
            "my_autoassign_policy_wo_pass": {
                "realm": "mydefrealm",
                "active": "True",
                "client": "*",
                "user": "*",
                "time": "*",
                "action": "autoassignment_without_password=False",
                "scope": "enrollment",
            }
        }

        res = get_autoassignment_without_pass(user=user)
        assert not res

        mocked_get_client_policy.return_value = {
            "my_autoassign_policy_wo_pass": {
                "realm": "mydefrealm",
                "active": "True",
                "client": "*",
                "user": "*",
                "time": "*",
                "action": "autoassignment_without_password=error",
                "scope": "enrollment",
            }
        }

        res = get_autoassignment_without_pass(user=user)
        assert not res

    @patch("linotp.lib.policy.action.get_policy_definitions")
    @patch("linotp.lib.policy._get_client")
    @patch("linotp.lib.policy.get_client_policy")
    def test_get_autoassignment_from_realm(
        self,
        mocked_get_client_policy,
        mocked_get_client,
        mocked_get_policy_definitions,
    ):

        user = User("Hugo", realm="Home_realm")
        mocked_get_client.return_value = "127.0.0.1"
        src_realm = "token-realm "

        mocked_get_client_policy.return_value = {
            "my_autoassign_policy_wo_pass": {
                "realm": "mydefrealm",
                "active": "True",
                "client": "*",
                "user": "*",
                "time": "*",
                "action": "autoassignment_from_realm=%s" % src_realm,
                "scope": "enrollment",
            }
        }

        mocked_get_policy_definitions.return_value = {
            "enrollment": {"autoassignment_from_realm": {"type": "str"}}
        }

        realm = get_autoassignment_from_realm(user)
        assert src_realm.strip() == realm

        src_realm = " "
        mocked_get_client_policy.return_value = {
            "my_autoassign_policy_wo_pass": {
                "realm": "mydefrealm",
                "active": "True",
                "client": "127.0.0.1",
                "user": "*",
                "time": "*",
                "action": "autoassignment_from_realm=%s" % src_realm,
                "scope": "enrollment",
            }
        }

        realm = get_autoassignment_from_realm(user)
        assert not realm

        return


# eof #

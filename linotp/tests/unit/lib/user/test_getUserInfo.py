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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#


import unittest

from mock import patch

from linotp.lib.user import User, getUserInfo


class TestGetUserInfo(unittest.TestCase):
    @patch("linotp.lib.user.lookup_user_in_resolver")
    def test_getUserInfo_fallback(self, mock_lookup_user_in_resolver):
        """
        verify that the fallback is an empty dict for
        - lookup result is None
        - no userid as input is provided
        """

        mock_lookup_user_in_resolver.return_value = None, None, None

        assert {} == getUserInfo("userId", "resolver", "resolver_conf")
        assert {} == getUserInfo(None, "resolver", "resolver_conf")

    @patch("linotp.lib.user.lookup_user_in_resolver")
    def test_getUserInfo_good(self, mock_lookup_user_in_resolver):
        """
        verify that the lookup result is forwarded
        """

        mock_lookup_user_in_resolver.return_value = (
            "1223",
            "myResolver",
            {"login": "heinz", "email": "heinz.el@mann.de"},
        )

        userInfo = getUserInfo("userId", "resolver", "resolver_conf")

        assert userInfo["login"] == "heinz"

        return


# eof #

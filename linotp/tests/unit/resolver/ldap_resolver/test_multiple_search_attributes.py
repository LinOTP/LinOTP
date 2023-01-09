# -*- coding: utf-8 -*-

#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010-2019 KeyIdentity GmbH
#   Copyright (C) 2019-     netgo software GmbH
#
#   This file is part of LinOTP userid resolvers.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU Affero General Public
#   License, version 3, as published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the
#              GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#   E-mail: info@linotp.de
#   Contact: www.linotp.org
#   Support: www.linotp.de

"""
LDAP Resolver unit test - search for multiple login names
"""

import unittest

import pytest
from mock import patch

from linotp.useridresolver.LDAPIdResolver import IdResolver as LDAPResolver

from . import Bindresult


@pytest.mark.usefixtures("app")
class TestLDAPResolverMultipleSearchIds(unittest.TestCase):
    """ldapresolver test: support search for multiple login names"""

    @patch("linotp.useridresolver.LDAPIdResolver.IdResolver.unbind")
    @patch("linotp.useridresolver.LDAPIdResolver.IdResolver.bind")
    def test_multiple_search_ids(self, mock_bind, mock_unbind):
        """verify ldapresolver supports search for multiple names

        to support for example the login with sAMAccountName and
        userPrincipalName. The test verifies that the login name will be
        expanded into the search filter multiple times, replacing all %s
        occurrences in the resolver.filter string.
        """

        # 1. setup the test environment

        uid_type = "üid"

        bindresult = Bindresult(uid_type=uid_type)

        mock_bind.return_value = bindresult
        mock_unbind.return_value = None

        resolver = LDAPResolver()

        resolver.filter = (
            "(&(|(sAMAccountName=%s)(userPrincipalName=%s))(objectClass=user))"
        )
        resolver.uidType = uid_type

        login_name = "mozart@composer.org"

        # 2. finally trigger the call getUserId

        userid = resolver.getUserId(loginname=login_name)

        # 3. verify that the login name occurs multiple times in the filter

        assert bindresult._filter_str.count(login_name) == 2


# eof #

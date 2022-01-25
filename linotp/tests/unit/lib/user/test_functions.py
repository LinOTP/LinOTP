# -*- coding: utf-8 -*-

#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
#   E-mail: linotp@keyidentity.com
#   Contact: www.linotp.org
#   Support: www.keyidentity.com

"""Unit tests for auxiliary functions in the `linotp/lib/user.py`
module.

"""

import json
from pathlib import Path

import pytest

from flask import g

from linotp.lib.config import getFromConfig, getLinotpConfig
from linotp.lib.user import User, getSearchFields, getUserList
from linotp.model.local_admin_user import LocalAdminResolver

# The 'searchFields` and `getUserList` functions don't seem to have
# any unit tests anywhere, but today we're not here to fix
# this. Instead we simply want to make sure that resolver name
# comparisons are case-sensitive.


@pytest.fixture
def fthsm(mocker):
    # We don't care for encrypted passwords because that would pull
    # in an HSM that we don't have. Especially for SQLite which doesn't
    # use passwords in the first place.

    mock_from_unenc = mocker.patch(
        "linotp.lib.crypto.encrypted_data.EncryptedData.from_unencrypted"
    )
    mock_from_unenc.return_value = mocker.MagicMock()
    mock_from_unenc.return_value.get_unencrypted.return_value = lambda: ""


@pytest.fixture
def admin_res(app):
    # This is so we can later have a user to list.

    lar = LocalAdminResolver(app)
    lar.add_user("heinz", "XXX")
    yield lar
    lar.remove_user("heinz")


def test_getsearchfields_case_sensitive_resolver_names(fthsm, app):

    g.request_context["Config"] = getLinotpConfig()  # This sucks.
    g.request_context["CacheManager"] = app.cache  # This sucks even worse.

    admin_realm_name = app.config["ADMIN_REALM_NAME"]
    admin_resolvers_key = f"useridresolver.group.{admin_realm_name}"
    admin_resolvers = getFromConfig(admin_resolvers_key, "")
    _, _, aci = admin_resolvers.rpartition(".")

    user = User(
        login="user1", realm=admin_realm_name, resolver_config_identifier=aci
    )

    # If the user's resolver config identifier matches its resolver, then the
    # `getSearchFields` function should return a set of search fields. If there
    # is no match, the result should be empty. Hence if we tweak the RCI to be
    # the uppercase version, then if the comparison is case-sensitive the result
    # should be empty.

    user.resolver_config_identifier = user.resolver_config_identifier.upper()
    search_fields = getSearchFields(user)
    assert (
        not search_fields
    ), "getSearchFields resolver name comparison is not case-sensitive"


def test_getuserlist_case_sensitive_resolver_names(fthsm, app, admin_res):

    g.request_context["Config"] = getLinotpConfig()  # This sucks.
    g.request_context["CacheManager"] = app.cache  # This sucks even worse.
    g.request_context["UserLookup"] = {}  # Don't get me started.

    admin_realm_name = app.config["ADMIN_REALM_NAME"]
    admin_resolvers_key = f"useridresolver.group.{admin_realm_name}"
    admin_resolvers = getFromConfig(admin_resolvers_key, "")
    _, _, aci = admin_resolvers.rpartition(".")

    # As before, if we make the RCI uppercase and the `getUserList()` function
    # still returns a user list, then the comparison must have been
    # case-insensitive. With a case-sensitive comparison, the result should
    # be empty.

    search_user = User(
        login="user1",
        realm=admin_realm_name,
        resolver_config_identifier=aci.upper(),
    )
    user_list = getUserList({}, search_user)
    assert (
        not user_list
    ), "getUserList resolver name comparison is not case-sensitive"

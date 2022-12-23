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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

import pytest

from linotp.lib.policy import checkAdminAuthorization
from linotp.lib.user import User

# We satisfy ourselves that resolver matches are done in a case-sensitive
# manner.


def test_check_admin_auth_case_sensitive_resolver_names(app):

    user = User(
        login="user1", realm="realm", resolver_config_identifier="resolver"
    )

    policies = {
        "user": "",
        "scope": "selfservice",
        "action": "p1",
        "realms": [],
        "active": True,
        "client": "*",
        "time": "* * * * * *;",
        "resolvers": ["RESOLVER"],
    }

    assert not checkAdminAuthorization(policies, None, user), (
        "checkAdminAuthorization resolver name comparison "
        "is not case-sensitive"
    )

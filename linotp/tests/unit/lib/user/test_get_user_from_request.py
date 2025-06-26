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

from mock import patch

from linotp.lib.user import User, getUserFromRequest


def test_JWT_authentifictaion(app):
    authUser = User(
        login="JWT_AUTHENTICATED_USER",
        realm="def_realm",
        resolver_config_identifier="def_resolver",
    )
    with patch("linotp.lib.user.getattr") as mocked_getattr:
        mocked_getattr.return_value = authUser

        user = getUserFromRequest()

        assert user.login == "JWT_AUTHENTICATED_USER"


def test_empty_auth(app):
    authUser = User(
        login="",
        realm="",
        resolver_config_identifier="",
    )
    with patch("linotp.lib.user.getattr") as mocked_getattr:
        mocked_getattr.return_value = authUser

        user = getUserFromRequest()

        assert user.login == ""

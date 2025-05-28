# -*- coding: utf-8 -*-

#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010-2019 KeyIdentity GmbH
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

from flask import g

from linotp.lib.config import getFromConfig, refreshConfig
from linotp.model import db
from linotp.model.config import set_config
from linotp.model.local_admin_user import LocalAdminResolver


def test_lar_case_sensitive_resolver_names(app):
    admin_realm_name = app.config["ADMIN_REALM_NAME"]
    admin_resolvers_key = f"useridresolver.group.{admin_realm_name}"
    admin_resolvers = getFromConfig(admin_resolvers_key, "")

    lar = LocalAdminResolver(app)

    # Replace the local admin resolver name in the realm with a
    # name that is the same but in uppercase. If we then try to
    # re-add the original local admin resolver using the officially
    # approved `.add_to_admin_realm()` method, it should show
    # up if names are compared case-sensitively.

    prefix, _, name = admin_resolvers.rpartition(".")
    new_name = f"{prefix}.{name.upper()}"
    set_config(
        key=admin_resolvers_key,
        value=new_name,
        typ="text",
        description="None",
        update=True,
    )
    db.session.commit()

    refreshConfig()  # force config reload
    lar.add_to_admin_realm()

    refreshConfig()  # force config reload
    new_admin_resolvers = getFromConfig(admin_resolvers_key, "")
    assert new_admin_resolvers == admin_resolvers + "," + new_name, (
        "local admin resolver name comparison is not case-sensitive"
    )

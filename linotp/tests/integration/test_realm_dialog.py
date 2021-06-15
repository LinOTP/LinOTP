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
"""LinOTP Selenium Test that creates UserIdResolvers in the WebUI"""

import pytest
from linotp_selenium_helper import TestCase

import integration_data as data


class TestCreateRealmDialog(TestCase):
    """TestCase class that checks basic realm functionality"""

    def test_realm_open(self):
        r = self.manage_ui.realm_manager
        r.open()

    def test_clear_realms(self):
        r = self.manage_ui.realm_manager
        r.clear_realms_via_api()

        m = self.manage_ui.useridresolver_manager
        m.clear_resolvers_via_api()

        resolver_data = data.musicians_ldap_resolver
        m.create_resolver_via_api(resolver_data)

        r.create("test_clear_realm", resolver_data["name"])

        realms = r.get_realms_list()
        assert len(realms) == 1, "Realm count should be 1"

        r.clear_realms()

        realms = r.get_realms_list()
        assert len(realms) == 0, "Realm count should be 0"

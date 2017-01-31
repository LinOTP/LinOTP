# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
#    Support: www.keyidentity.com
#
"""LinOTP Selenium Test that creates UserIdResolvers in the WebUI"""

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.realm import RealmManager
from linotp_selenium_helper.user_id_resolver import UserIdResolverManager

import integration_data as data

class TestCreateRealmDialog(TestCase):
    """TestCase class that checks basic realm functionality"""
    def setUp(self):
        TestCase.setUp(self)

    def test_realm_open(self):            
        r = RealmManager(self)
        r.open()

    def test_clear_realms(self):
        r = RealmManager(self)
        r.clear_realms()
        r.close()

        m = UserIdResolverManager(self)
        m.clear_resolvers()

        resolver_data = data.musicians_ldap_resolver
        m.create_resolver(resolver_data)
        
        r.create("test_clear_realm", resolver_data['name'])
        
        realms =  r.get_realms_list()
        self.assertEqual(len(realms), 1, "Realm count should be 1")
        
        r.clear_realms()

        realms =  r.get_realms_list()
        self.assertEqual(len(realms), 0, "Realm count should be 0")

        
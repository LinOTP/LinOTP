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
#    Support: www.lsexperts.de
#
"""LinOTP Selenium Test that creates UserIdResolvers in the WebUI"""

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.user_view import UserView
from linotp_selenium_helper.realm import RealmManager
from linotp_selenium_helper.manage_ui import ManageUi
from linotp_selenium_helper.user_id_resolver import UserIdResolverManager

import integration_data as data

class TestCreateUserIdResolvers(TestCase):
    """TestCase class that creates 4 UserIdResolvers"""
    def setUp(self):
        TestCase.setUp(self)

    def clear_realms(self):
        # Need to clear realms so that useridresolvers can be deleted
        realmMgr = RealmManager(self)
        realmMgr.clear_realms()

    def create_resolvers_and_realm(self, resolver_data):
        """Test the connection with the corresponding button in the UI.
        Return the number of found users.
        """
        driver = self.driver
        created_resolvers = []
        total_expected_users = 0

        realmMgr = RealmManager(self)
        realmMgr.clear_realms()

        m = UserIdResolverManager(self)
        m.clear_resolvers()

        for d in resolver_data:
            expected_users = d['expected_users']
            m.open()
            r = m.create_resolver(d)
            m.test_connection(d['name'], expected_users)
            created_resolvers.append(r)
            total_expected_users += expected_users

        realm_name = "SE_realm1"
        realmMgr.create(realm_name, created_resolvers)

        user_view = UserView(driver, self.base_url, realm_name)
        self.assertEqual(total_expected_users, user_view.get_num_users(),
                         "Not the expected number of users")

    def create_resolver(self, testdata):
        m = UserIdResolverManager(self)
        name = testdata['name']
        m.open()
        if name in m.get_defined_resolvers():
            self.clear_realms()
            m.open()
            m.delete_resolver(name)
            m.open()
        m.create_resolver(testdata)

    def test_01_ldap_resolver(self):
        self.create_resolver(data.musicians_ldap_resolver)

    def test_02_passwd_resolver_creation(self):
        self.create_resolver(data.sepasswd_resolver)

    def test_03_sql_resolver_creation(self):
        self.create_resolver(data.sql_resolver)

    def test_10_resolver_workflow(self):
        # Quick test complete workflow
        testdata = (data.sepasswd_resolver,)
        return self.create_resolvers_and_realm(testdata)

    def test_11_multiple_resolvers(self):
        testdata = (data.musicians_ldap_resolver, data.physics_ldap_resolver,
                         data.sql_resolver, data.sepasswd_resolver)
        return self.create_resolvers_and_realm(testdata)

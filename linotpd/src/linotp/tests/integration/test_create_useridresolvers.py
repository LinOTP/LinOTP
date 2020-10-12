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


class TestCreateUserIdResolvers(TestCase):
    """TestCase class that creates 4 UserIdResolvers"""

    def clear_realms(self):
        # Need to clear realms so that useridresolvers can be deleted
        self.manage_ui.realm_manager.clear_realms_via_api()

    def create_resolvers_and_realm(self, resolver_data):
        """Test the connection with the corresponding button in the UI.
        Return the number of found users.
        """
        created_resolvers = []
        total_expected_users = 0
        realm_manager = self.manage_ui.realm_manager

        self.clear_realms()
        m = self.manage_ui.useridresolver_manager
        m.clear_resolvers_via_api()

        for d in resolver_data:
            expected_users = d['expected_users']
            r = m.create_resolver(d)
            m.test_connection(d['name'], expected_users)
            created_resolvers.append(r)
            total_expected_users += expected_users

        m.close()

        realm_name = "SE_realm1"
        realm_manager.create(realm_name, created_resolvers)
        realm_manager.close()

        user_view = self.manage_ui.user_view
        assert total_expected_users == user_view.get_num_users(realm_name), \
            "Expected %i users, got %i" % \
            (total_expected_users, user_view.get_num_users(realm_name))

    def create_resolver(self, testdata):
        m = self.manage_ui.useridresolver_manager
        name = testdata['name']
        m.open()
        if name in m.get_defined_resolvers():
            m.close()
            self.clear_realms()
            m.open()
            m.delete_resolver(name)
        m.create_resolver(testdata)
        m.close()

    def test_01_ldap_resolver(self):
        # ldaps URL
        self.create_resolver(data.musicians_ldap_resolver)

    def test_02_passwd_resolver_creation(self):
        self.create_resolver(data.sepasswd_resolver)

    def test_03_sql_resolver_creation(self):
        self.create_resolver(data.sql_resolver)

    def test_04_ad_resolver_creation(self):
        self.create_resolver(data.physics_ldap_resolver)

    def test_05_ldap_enforce_starttls(self):
        ldap_data = data.musicians_ldap_resolver.copy()
        ldap_data['enforce_tls'] = True
        ldap_data['uri'] = ldap_data['uri'].replace('ldaps:', 'ldap:')

        self.create_resolver(ldap_data)

    def test_06_ldap_dont_enforce_starttls(self):
        ldap_data = data.musicians_ldap_resolver.copy()
        ldap_data['enforce_tls'] = False
        ldap_data['uri'] = ldap_data['uri'].replace('ldaps:', 'ldap:')
        del ldap_data['only_trusted_certs']

        self.create_resolver(ldap_data)

    def test_10_resolver_workflow(self):
        # Quick test complete workflow
        testdata = (data.sepasswd_resolver,)
        return self.create_resolvers_and_realm(testdata)

    def test_11_multiple_resolvers(self):
        testdata = (data.musicians_ldap_resolver, data.physics_ldap_resolver,
                    data.sql_resolver, data.sepasswd_resolver)

        return self.create_resolvers_and_realm(testdata)

    def test_12_api_roundtrip_with_utf8(self):
        """
        Check that we can define a resolver with UTF8 using the API and read the results back
        """
        m = self.manage_ui.useridresolver_manager
        self.clear_realms()
        m.clear_resolvers_via_api()

        ldap_data = data.musicians_ldap_resolver

        # Make sure that we really have a UTF-8 string
        assert 'cn="عبد الحليم حافظ"' in ldap_data['binddn'], "Test BindDN does not contain UTF-8"

        m.create_resolver_via_api(ldap_data)
        resolver_config = m.get_resolver_params_via_api(ldap_data['name'])

        assert resolver_config['type'] == ldap_data['type']
        assert resolver_config['resolver'] == ldap_data['name']
        assert resolver_config['data']['BINDDN'] == ldap_data['binddn']

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
"""LinOTP Selenium Test that creates UserIdResolvers in the WebUI"""

from unittest import skip

import integration_data as data
import pytest

from linotp_selenium_helper import TestCase


def test_ldap_resolver_via_api(testcase):
    """Test musicians resolver creation via API call"""
    # Get a test case without starting selenium

    testcase.loadClsConfig()

    # create musician resolver with ldaps URL
    # - before creating a new resolver, we cleanup former realm and resolvers

    testcase.manage_ui.realm_manager.clear_realms_via_api()

    resolver_manager = testcase.manage_ui.useridresolver_manager

    resolver_manager.clear_resolvers_via_api()
    resolver_manager.create_resolver_via_api(data.musicians_ldap_resolver)


class TestCreateUserIdResolvers:
    @pytest.fixture(autouse=True)
    def setUp(self, testcase):
        """testcase is a fixture"""
        self.testcase = testcase

    @pytest.fixture(autouse=True)
    def tearDown(self):
        yield
        self.testcase.manage_ui.close_all_dialogs()

    def clear_realms(self):
        # Need to clear realms so that useridresolvers can be deleted
        self.testcase.manage_ui.realm_manager.clear_realms_via_api()

    def create_resolvers_and_realm(self, resolver_data):
        """Test the connection with the corresponding button in the UI.
        Return the number of found users.
        """
        created_resolvers = []
        total_expected_users = 0
        realm_manager = self.testcase.manage_ui.realm_manager

        self.clear_realms()
        uid_resolver_manager = self.testcase.manage_ui.useridresolver_manager
        uid_resolver_manager.clear_resolvers_via_api()

        for d in resolver_data:
            expected_users = d["expected_users"]
            r = uid_resolver_manager.create_resolver(d)
            uid_resolver_manager.test_connection(d["name"], expected_users)
            created_resolvers.append(r)
            total_expected_users += expected_users

        uid_resolver_manager.close()

        realm_name = "SE_realm1"
        realm_manager.create(realm_name, created_resolvers)
        realm_manager.close()

        user_view = self.testcase.manage_ui.user_view
        assert total_expected_users == user_view.get_num_users(realm_name), (
            "Expected %i users, got %i"
            % (
                total_expected_users,
                user_view.get_num_users(realm_name),
            )
        )

    def create_resolver(self, testdata):
        uid_resolver_manager = self.testcase.manage_ui.useridresolver_manager
        name = testdata["name"]
        uid_resolver_manager.open()
        if name in uid_resolver_manager.get_defined_resolvers():
            uid_resolver_manager.close()
            self.clear_realms()
            uid_resolver_manager.open()
            uid_resolver_manager.delete_resolver(name)
        uid_resolver_manager.create_resolver(testdata)
        uid_resolver_manager.close()

    def test_01_ldap_resolver(self):
        # ldaps URL
        self.create_resolver(data.musicians_ldap_resolver)

    def test_02_passwd_resolver_creation(self):
        self.create_resolver(data.sepasswd_resolver)

    def test_03_sql_resolver_creation(self):
        self.create_resolver(data.sql_resolver)

    def test_04_ad_resolver_creation(self):
        """Add the ldap resolver, (it should normally work even if the ldap server is not available)"""
        self.create_resolver(data.physics_ldap_resolver)

    def test_05_ldap_enforce_starttls(self):
        ldap_data = data.musicians_ldap_resolver.copy()
        ldap_data["enforce_tls"] = True
        ldap_data["uri"] = ldap_data["uri"].replace("ldaps:", "ldap:")

        self.create_resolver(ldap_data)

    def test_06_ldap_dont_enforce_starttls(self):
        ldap_data = data.musicians_ldap_resolver.copy()
        ldap_data["enforce_tls"] = False
        ldap_data["uri"] = ldap_data["uri"].replace("ldaps:", "ldap:")
        del ldap_data["only_trusted_certs"]

        self.create_resolver(ldap_data)

    def test_10_resolver_workflow(self):
        # Quick test complete workflow
        testdata = (data.sepasswd_resolver,)
        return self.create_resolvers_and_realm(testdata)

    def test_11_multiple_resolvers(self):
        """Creates multiple resolvers and required realms and tests the connection"""
        testdata = (
            data.musicians_ldap_resolver,
            # TODO
            # commented out after hottybotty (ldap test server used in
            # integration_data.physics_ldap_resolver, ) went down.
            # It should come back when we have an equivalent >>
            # data.physics_ldap_resolver,
            data.sql_resolver,
            data.sepasswd_resolver,
        )

        return self.create_resolvers_and_realm(testdata)

    def test_12_api_roundtrip_with_utf8(self):
        """
        Check that we can define a resolver with UTF8 using the API and read the results back
        """
        uid_resolver_manager = self.testcase.manage_ui.useridresolver_manager
        self.clear_realms()
        uid_resolver_manager.clear_resolvers_via_api()

        ldap_data = data.musicians_ldap_resolver

        # Make sure that we really have a UTF-8 string
        assert 'cn="عبد الحليم حافظ"' in ldap_data["binddn"], (
            "Test BindDN does not contain UTF-8"
        )

        uid_resolver_manager.create_resolver_via_api(ldap_data)
        resolver_config = uid_resolver_manager.get_resolver_params_via_api(
            ldap_data["name"]
        )

        assert resolver_config["type"] == ldap_data["type"]
        assert resolver_config["resolver"] == ldap_data["name"]
        assert resolver_config["data"]["BINDDN"] == ldap_data["binddn"]

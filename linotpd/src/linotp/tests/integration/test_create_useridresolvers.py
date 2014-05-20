# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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

import time

from linotp_selenium_helper import TestCase, LdapUserIdResolver, \
    SqlUserIdResolver, PasswdUserIdResolver, Realm
from linotp_selenium_helper.user_view import UserView

class TestCreateUserIdResolvers(TestCase):
    """TestCase class that creates 4 UserIdResolvers"""

    def test_create_user_id_resolvers(self):
        """Creates User-Id-Resolvers"""
        driver = self.driver

        ad_certificate = \
"""-----BEGIN CERTIFICATE-----
MIIDcjCCAtugAwIBAgIQVSU6NwMTmKNI6t3WcjY6uTANBgkqhkiG9w0BAQUFADBC
MRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxGTAXBgoJkiaJk/IsZAEZFglsc2V4cGVy
dHMxDjAMBgNVBAMTBUNBMDAxMB4XDTA1MDQxMTE2NDgzOVoXDTQwMDQxMTE2NTY1
MFowQjEVMBMGCgmSJomT8ixkARkWBWxvY2FsMRkwFwYKCZImiZPyLGQBGRYJbHNl
eHBlcnRzMQ4wDAYDVQQDEwVDQTAwMTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAqlWLfYK+dExjG+Qa/jpYjSo3EQnweQ7azacosa+xsrTMfDV5wLgMBSclCTX2
i/35VRg282Bh7hKCZifOBnAxjCBIHMpHQmW9c0T/GpeWSOQ1x0KeKrZ4PRj5oHEv
/uDJ7q2HlWXgRQo6NR75yDGLpsAWk64TyQ/I4f2vlC+AtjMCAyPS46OCAWcwggFj
MBMGCSsGAQQBgjcUAgQGHgQAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBTCY8rVNcU/NGvgZxaPmO+Kz8bG4TCB/AYDVR0fBIH0MIHx
MIHuoIHroIHohoGwbGRhcDovLy9DTj1DQTAwMSxDTj1sc2V4czAxLENOPUNEUCxD
Tj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1
cmF0aW9uLERDPWxzZXhwZXJ0cyxEQz1sb2NhbD9jZXJ0aWZpY2F0ZVJldm9jYXRp
b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnSGM2h0
dHA6Ly9sc2V4czAxLmxzZXhwZXJ0cy5sb2NhbC9DZXJ0RW5yb2xsL0NBMDAxLmNy
bDAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQUFAAOBgQBa+RGoezCgJS5W
PFCPy9BWqZr7iRimfRGBDqHpYDCPDtgec2fKCZ+u4jfwuTisZ7UOoiM1iEvkw0hH
Z7R1pz4Yd6E074kS/fe6u7U+9L3dmSUjFvO3gkLKtHKbhQi0NA+EHMRrPsQQemLm
gYzNiYwtvAu74Q+eTC6R5Uf0hOlFig==
-----END CERTIFICATE-----"""

        # Create musicians LDAP
        music_ldap_name = "SE_musicians"
        music_ldap_num_expected_users = 10
        music_ldap_id_resolver = LdapUserIdResolver(
            music_ldap_name,
            driver,
            self.base_url,
            uri="ldaps://blackdog",
            certificate=ad_certificate,
            basedn="ou=people,dc=blackdog,dc=office,dc=lsexperts,dc=de",
            # You may also use cn="Wolfgang Amadeus Mozart"
            binddn=u'cn="عبد الحليم حافظ",ou=people,dc=blackdog,dc=office,dc=lsexperts,dc=de',
            password="Test123!",
            preset_ldap=True
        )
        time.sleep(1)
        music_ldap_num_users_found = music_ldap_id_resolver.test_connection()
        try:
            self.assertTrue(music_ldap_num_users_found >= music_ldap_num_expected_users,
                            "Not enough users found in musicians' LDAP")
        except AssertionError as assertion_error:
            self.verification_errors.append(str(assertion_error))
        time.sleep(1)

        # Create physics AD
        physics_ad_name = "SE_physics"
        physics_ad_num_expected_users = 7
        physics_ad_id_resolver = LdapUserIdResolver(
            physics_ad_name,
            driver,
            self.base_url,
            uri="ldaps://hottybotty",
            certificate=ad_certificate,
            basedn="dc=hotad,dc=example,dc=net",
            binddn=u'cn="Clark Maxwell",ou=corp,dc=hotad,dc=example,dc=net',
            password="Test123!",
            preset_ldap=False
        )
        time.sleep(1)
        physics_ad_num_users_found = physics_ad_id_resolver.test_connection()
        try:
            self.assertTrue(physics_ad_num_users_found >= physics_ad_num_expected_users,
                            "Not enough users found in physics' LDAP")
        except AssertionError as assertion_error:
            self.verification_errors.append(str(assertion_error))
        time.sleep(1)

        # Create SQL UserIdResolver
        sql_name = "SE_mySql"
        sql_num_expected_users = 4
        sql_id_resolver = SqlUserIdResolver(
            sql_name,
            driver,
            self.base_url,
            server="blackdog",
            database="userdb",
            user="resolver_user",
            password="Test123!",
            table="user",
            limit="500",
            encoding="latin1"
        )
        time.sleep(1)
        sql_num_users_found = sql_id_resolver.test_connection()
        try:
            self.assertEquals(sql_num_users_found, sql_num_expected_users)
        except AssertionError as assertion_error:
            self.verification_errors.append(str(assertion_error))
        time.sleep(1)

        # Create Passwd UserIdResolver
        #
        # Expected content of /etc/se_mypasswd is:
        #
        # hans:x:42:0:Hans Müller,Room 22,+49(0)1234-22,+49(0)5678-22,hans@example.com:x:x
        # susi:x:1336:0:Susanne Bauer,Room 23,+49(0)1234-24,+49(0)5678-23,susanne@example.com:x:x
        # rollo:x:21:0:Rollobert Fischer,Room 24,+49(0)1234-24,+49(0)5678-24,rollo@example.com:x:x
        #
        passwd_name = "SE_myPasswd"
        passwd_num_expected_users = 3
        passwd_id_resolver = PasswdUserIdResolver(
            passwd_name,
            driver,
            self.base_url,
            filename="/etc/se_mypasswd"
        )
        time.sleep(1)

        # Create realm for all resolvers
        resolvers_realm = [sql_id_resolver,
                          passwd_id_resolver,
                          music_ldap_id_resolver,
                          physics_ad_id_resolver]
        realm_name = "SE_realm1"
        realm = Realm(realm_name, resolvers_realm)
        realm.create(driver, self.base_url)
        time.sleep(1)

        ## Assert that all users were found
        total_expected_users = sum([sql_num_users_found,
                                    passwd_num_expected_users,
                                    music_ldap_num_users_found,
                                    physics_ad_num_users_found])

        user_view = UserView(driver, self.base_url, realm_name)
        self.assertEqual(total_expected_users, user_view.get_num_users(),
                         "Not the expected number of users")

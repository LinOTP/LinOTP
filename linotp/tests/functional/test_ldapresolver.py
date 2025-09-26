# #
# #    LinOTP - the open source solution for two factor authentication
# #    Copyright (C) 2010-2019 KeyIdentity GmbH
# #    Copyright (C) 2019-     netgo software GmbH
# #
# #    This file is part of LinOTP server.
# #
# #    This program is free software: you can redistribute it and/or
# #    modify it under the terms of the GNU Affero General Public
# #    License, version 3, as published by the Free Software Foundation.
# #
# #    This program is distributed in the hope that it will be useful,
# #    but WITHOUT ANY WARRANTY; without even the implied warranty of
# #    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# #    GNU Affero General Public License for more details.
# #
# #    You should have received a copy of the
# #               GNU Affero General Public License
# #    along with this program.  If not, see <http://www.gnu.org/licenses/>.
# #
# #
# #    E-mail: info@linotp.de
# #    Contact: www.linotp.org
# #    Support: www.linotp.de
# #

# """
# ldap resolver tests
# """

# import json

# import ldap
# import pytest
# from ldap.controls import SimplePagedResultsControl
# from mockldap import LDAPObject, MockLdap

# from linotp.tests import TestController

# # pylint: disable=redefined-outer-name, unused-argument


# @pytest.mark.skip(reason="Skipping this test class")
# @pytest.mark.usefixtures("app")
# class TestLDAPResolver(TestController):
#     def define_ldap_resolver(
#         self,
#         name,
#         base_dn="OU=people,DC=hotad,DC=example,DC=net",
#         manager_dn="CN=Clark Maxwell,OU=corp,DC=hotad,DC=example,DC=net",
#         ldap_uri="ldap://localhost/",
#         params=None,
#         ad_entries=None,
#     ):
#         """"""

#         u_map = {
#             "username": "sAMAccountName",
#             "phone": "telephoneNumber",
#             "mobile": "mobile",
#             "email": "mail",
#             "surname": "sn",
#             "givenname": "givenName",
#         }

#         iparams = {
#             "name": name,
#             "BINDDN": manager_dn,
#             "BINDPW": ad_entries[manager_dn]["userPassword"],
#             "LDAPBASE": base_dn,
#             "LDAPURI": ldap_uri,
#             "CACERTIFICATE": "",
#             "LOGINNAMEATTRIBUTE": "sAMAccountName",
#             # 'LDAPSEARCHFILTER': '(sAMAccountName=*)(objectClass=user)',
#             "LDAPSEARCHFILTER": "(sAMAccountName=*)",
#             # 'LDAPFILTER': '(&(sAMAccountName=%s)(objectClass=user))',
#             "LDAPFILTER": "(sAMAccountName=%s)",
#             "UIDTYPE": "dn",
#             "USERINFO": json.dumps(u_map),
#             "TIMEOUT": "5",
#             "SIZELIMIT": "500",
#             "NOREFERRALS": "True",
#             "type": "ldapresolver",
#             "EnforceTLS": "True",
#         }

#         if params:
#             iparams.update(params)

#         response = self.make_system_request("setResolver", params=iparams)
#         assert response.json["result"]["value"]

#         return response, iparams

#     @pytest.fixture
#     def ldap_realm_test(self, mock_ldap, ad_entries):
#         """
#         Fixture to provide a test LDAP resolver in realm 'test'
#         """
#         # define the resolver 'test'

#         resolver_name = "test"
#         realm_name = "test"

#         # define the realm 'test'
#         resolver_base = "useridresolver.LDAPIdResolver.IdResolver."
#         resolver_list = [resolver_base + resolver_name]

#         (response, _params) = self.define_ldap_resolver(
#             resolver_name, ad_entries=ad_entries
#         )
#         assert '"value": true' in response

#         response = self.create_realm(realm_name, resolver_list)
#         assert '"value": true' in response

#     @pytest.fixture
#     def ldap_realm_corp(self, mock_ldap, ad_entries):
#         """
#         Fixture to provide a test LDAP resolver in realm 'corp'
#         with the uidType: objectGUID
#         """
#         # define the resolver 'test'

#         resolver_name = "corp"
#         realm_name = "corp"

#         manager_dn = "CN=Clark Maxwell,OU=corp,DC=hotad,DC=example,DC=net"
#         base_dn = "OU=corp,DC=hotad,DC=example,DC=net"

#         (response, _params) = self.define_ldap_resolver(
#             resolver_name,
#             manager_dn=manager_dn,
#             base_dn=base_dn,
#             params={"UIDTYPE": "objectGUID"},
#             ad_entries=ad_entries,
#         )
#         assert '"value": true' in response

#         # define the realm 'test'
#         resolver_base = "useridresolver.LDAPIdResolver.IdResolver."
#         resolver_list = [resolver_base + resolver_name]

#         response = self.create_realm(realm_name, resolver_list)
#         assert '"value": true' in response

#     @pytest.mark.usefixtures("ldap_realm_test")
#     def test_ldap_dn(self):
#         """search in ldapresolver pointing to ad with uid type: dn"""

#         realm = "test"
#         user = "charlie.chaplin"

#         params = {"realm": realm}
#         response = self.make_admin_request("userlist", params=params)

#         usernames = [u["username"] for u in response.json["result"]["value"]]

#         assert user in usernames
#         assert len(usernames) == 14

#         params = {
#             "user": user,
#             "type": "pw",
#             "otpkey": "geheim1",
#             "realm": realm,
#         }

#         response = self.make_admin_request("init", params=params)
#         assert "detail" in response

#         params = {
#             "name": "pin_policy",
#             "scope": "authentication",
#             "active": True,
#             "client": "*",
#             "realm": "*",
#             "user": "*",
#             "action": "otppin=password",
#         }
#         response = self.make_system_request("setPolicy", params=params)
#         assert "false" not in response

#         params = {"user": user, "realm": realm, "pass": "Test123!geheim1"}
#         response = self.make_validate_request("check", params=params)
#         assert "false" not in response

#         return

#     @pytest.mark.usefixtures("ldap_realm_corp")
#     def test_ldap_objectGUID(self):
#         """search in ldapresolver pointing to ad with uid type: objectGUID"""

#         realm = "corp"
#         user = "maxwell"

#         params = {"realm": realm}
#         response = self.make_admin_request("userlist", params=params)

#         usernames = [u["username"] for u in response.json["result"]["value"]]

#         assert user in usernames
#         assert len(usernames) == 4

#         params = {
#             "user": user,
#             "type": "pw",
#             "otpkey": "geheim1",
#             "realm": realm,
#         }
#         response = self.make_admin_request("init", params=params)
#         assert "detail" in response

#         params = {
#             "name": "pin_policy",
#             "scope": "authentication",
#             "active": True,
#             "client": "*",
#             "realm": "*",
#             "user": "*",
#             "action": "otppin=password",
#         }
#         response = self.make_system_request("setPolicy", params=params)
#         assert "false" not in response

#         params = {"user": user, "realm": realm, "pass": "Test123!geheim1"}
#         response = self.make_validate_request("check", params=params)
#         assert "false" not in response

#         return

#     @pytest.mark.usefixtures("ldap_realm_test")
#     def test_user_of_LDAP_resolver_with_DN_type_uid(self):
#         response = self.make_api_v2_request(
#             "/resolvers/test/users/cn=karla%20anderson,ou=people,dc=hotad,dc=example,dc=net",
#             auth_user="admin",
#         )
#         assert response.json["result"]["status"]
#         user = response.json["result"]["value"]
#         assert user["username"] == "karla.anderson"

#     @pytest.mark.usefixtures("ldap_realm_corp")
#     def test_user_of_LDAP_resolver_with_GUID_type_uid(self):
#         response = self.make_api_v2_request(
#             "/resolvers/corp/users/9a1359b67546d44eba0f20c9fdd97b00",
#             auth_user="admin",
#         )
#         assert response.json["result"]["status"]
#         user = response.json["result"]["value"]
#         assert user["username"] == "maxwell"

#     @pytest.mark.usefixtures("ldap_realm_test")
#     def test_user_of_LDAP_resolver_with_searchTerm(self):
#         response = self.make_api_v2_request(
#             "/resolvers/test/users",
#             params={"searchTerm": "karla"},
#             auth_user="admin",
#         )
#         assert response.json["result"]["status"]
#         username_list = [
#             user["username"]
#             for user in response.json["result"]["value"]["pageRecords"]
#         ]
#         assert ["karla.anderson", "karla.anderson2"] == username_list

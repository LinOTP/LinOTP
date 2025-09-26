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

"""
ldap resolver tests
"""

import json

import pytest

from linotp.tests import TestController

# from linotp.tests import TestController


@pytest.mark.usefixtures("app")
class TestLDAPResolver(TestController):
    def define_ldap_resolver(
        self,
        name,
        base_dn="dc=corp,dc=lsexperts,dc=de",
        manager_dn="CN=admin,CN=Users,DC=corp,DC=lsexperts,DC=de",
        ldap_uri="ldap://blackdog-samba",
        params=None,
    ):
        u_map = {
            "username": "sAMAccountName",
            # "username": "dn",
            "phone": "telephoneNumber",
            "mobile": "mobile",
            "email": "mail",
            "surname": "sn",
            "givenname": "givenName",
        }

        iparams = {
            "name": name,
            "BINDDN": manager_dn,
            "BINDPW": "Test123!",
            "LDAPBASE": base_dn,
            "LDAPURI": ldap_uri,
            "CACERTIFICATE": "",
            "LOGINNAMEATTRIBUTE": "sAMAccountName",
            # "LOGINNAMEATTRIBUTE": "cn",
            # 'LDAPSEARCHFILTER': '(sAMAccountName=*)(objectClass=user)',
            "LDAPSEARCHFILTER": "(sAMAccountName=*)",
            # "LDAPSEARCHFILTER": "(cn=*)",
            # 'LDAPFILTER': '(&(sAMAccountName=%s)(objectClass=user))',
            "LDAPFILTER": "(sAMAccountName=%s)",
            # "LDAPFILTER": "(cn=%s)",
            "UIDTYPE": "dn",
            "USERINFO": json.dumps(u_map),
            "TIMEOUT": "5",
            "SIZELIMIT": "500",
            "NOREFERRALS": "True",
            "type": "ldapresolver",
            "EnforceTLS": "False",
        }

        if params:
            iparams.update(params)

        response = self.make_system_request("setResolver", params=iparams)
        assert response.json["result"]["value"]

        return response, iparams

    @pytest.fixture
    def ldap_realm_test(self):
        """
        Fixture to provide a test LDAP resolver in realm 'test'
        """
        # define the resolver 'test'

        resolver_name = "test"
        realm_name = "test"

        # define the realm 'test'
        resolver_base = "useridresolver.LDAPIdResolver.IdResolver."
        resolver_list = [resolver_base + resolver_name]

        (response, _params) = self.define_ldap_resolver(resolver_name)
        assert '"value": true' in response

        response = self.create_realm(realm_name, resolver_list)
        assert '"value": true' in response

    @pytest.fixture
    def ldap_realm_corp(self):
        """
        Fixture to provide a test LDAP resolver in realm 'corp'
        with the uidType: objectGUID
        """
        # define the resolver 'test'

        resolver_name = "corp"
        realm_name = "corp"

        (response, _params) = self.define_ldap_resolver(
            resolver_name,
            params={"UIDTYPE": "objectGUID"},
        )
        assert '"value": true' in response

        # define the realm 'test'
        resolver_base = "useridresolver.LDAPIdResolver.IdResolver."
        resolver_list = [resolver_base + resolver_name]

        response = self.create_realm(realm_name, resolver_list)
        assert '"value": true' in response

    @pytest.mark.usefixtures("ldap_realm_test")
    def test_ldap_dn(self):
        """search in ldapresolver pointing to ad with uid type: dn"""

        realm = "test"
        user = "Johann.Bach"

        params = {"realm": realm}
        response = self.make_admin_request("userlist", params=params)

        usernames = [u["username"] for u in response.json["result"]["value"]]

        assert user in usernames
        assert len(usernames) == 5570, len(usernames)

        params = {
            "user": user,
            "type": "pw",
            "otpkey": "geheim1",
            "realm": realm,
        }

        response = self.make_admin_request("init", params=params)
        assert "detail" in response

        params = {
            "name": "pin_policy",
            "scope": "authentication",
            "active": True,
            "client": "*",
            "realm": "*",
            "user": "*",
            "action": "otppin=password",
        }
        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response

        params = {"user": user, "realm": realm, "pass": "Test123!geheim1"}
        response = self.make_validate_request("check", params=params)
        assert "false" not in response

    @pytest.mark.usefixtures("ldap_realm_corp")
    def test_ldap_objectGUID(self):
        """search in ldapresolver pointing to ad with uid type: objectGUID"""

        realm = "corp"
        user = "Johann.Bach"

        params = {"realm": realm}
        response = self.make_admin_request("userlist", params=params)

        usernames = [u["username"] for u in response.json["result"]["value"]]

        assert user in usernames
        assert len(usernames) == 5570, len(usernames)

        params = {
            "user": user,
            "type": "pw",
            "otpkey": "geheim1",
            "realm": realm,
        }
        response = self.make_admin_request("init", params=params)
        assert "detail" in response

        params = {
            "name": "pin_policy",
            "scope": "authentication",
            "active": True,
            "client": "*",
            "realm": "*",
            "user": "*",
            "action": "otppin=password",
        }
        response = self.make_system_request("setPolicy", params=params)
        assert "false" not in response

        params = {"user": user, "realm": realm, "pass": "Test123!geheim1"}
        response = self.make_validate_request("check", params=params)
        assert "false" not in response

    @pytest.mark.usefixtures("ldap_realm_test")
    def test_user_of_LDAP_resolver_with_DN_type_uid(self):
        response = self.make_api_v2_request(
            "/resolvers/test/users/cn=Johann%20Sebastian%20Bach,cn=Users,dc=corp,dc=lsexperts,dc=de",
            auth_user="admin",
        )
        assert response.json["result"]["status"], response.json["result"]
        user = response.json["result"]["value"]
        assert user["username"] == "Johann.Bach", user["username"]

    @pytest.mark.usefixtures("ldap_realm_corp")
    def test_user_of_LDAP_resolver_with_GUID_type_uid(self):
        response = self.make_api_v2_request(
            "/resolvers/corp/users/595474e4-8fca-454b-b08e-ec3c275a52bd",
            auth_user="admin",
        )
        assert response.json["result"]["status"]
        user = response.json["result"]["value"]
        assert user["username"] == "Johann.Bach"

    @pytest.mark.usefixtures("ldap_realm_test")
    def test_user_of_LDAP_resolver_with_searchTerm(self):
        response = self.make_api_v2_request(
            "/resolvers/test/users",
            params={"searchTerm": "Elinor"},
            auth_user="admin",
        )
        assert response.json["result"]["status"]
        username_list = [
            user["username"] for user in response.json["result"]["value"]["pageRecords"]
        ]
        assert username_list == [
            "Elinor.Jaurigui",
            "Elinor.Kozlik",
            "Elinor.Landquist",
        ], str(username_list)

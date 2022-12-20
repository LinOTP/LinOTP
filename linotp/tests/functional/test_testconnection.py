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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#


"""
test the admin/testresolver api

the admin/testresolver api could be used wo password, if the resolver
is already known in LinOTP
"""
import json
import logging

import pytest
from mock import patch

from linotp.tests import TestController
from linotp.tests.functional.test_orphaned import OrphandTestHelpers

log = logging.getLogger(__name__)

PASSWORD = ""
LDAPURI = ""


class MockedResolver:
    @classmethod
    def testconnection(*argparams, **kwparams):
        """
        stub to check if password is integrated in the parameters or not

        :return: just always return an connection error, which is ignored
        """
        global PASSWORD
        global LDAPURI

        param = argparams[1]

        PASSWORD = param.get("BINDPW")
        LDAPURI = param.get("LDAPURI")

        desc = {"desc": "Can't contact LDAP server"}
        status = "error"
        return (status, desc)


class TestTestresolverAPI(TestController, OrphandTestHelpers):
    """
    test class for the admin/testresolver api
    """

    def setUp(self):
        TestController.setUp(self)

    def define_ldap_resolver(self, name):
        """"""
        u_map = {
            "username": "sAMAccountName",
            "phone": "telephoneNumber",
            "mobile": "mobile",
            "email": "mail",
            "surname": "sn",
            "givenname": "givenName",
        }

        params = {
            "BINDDN": "cn=administrator,dc=yourdomain,dc=tld",
            "LDAPFILTER": "(&(sAMAccountName=%s)(objectClass=user))",
            "LDAPBASE": "dc=yourdomain,dc=tld",
            "name": name,
            "CACERTIFICATE": "",
            "LOGINNAMEATTRIBUTE": "sAMAccountName",
            "LDAPURI": "ldap://linotpserver1, ldap://linotpserver2",
            "LDAPSEARCHFILTER": "(sAMAccountName=*)(objectClass=user)",
            "UIDTYPE": "objectGUID",
            "BINDPW": "Test123!",
            "USERINFO": json.dumps(u_map),
            "TIMEOUT": "5",
            "SIZELIMIT": "500",
            "NOREFERRALS": "True",
            "type": "ldapresolver",
            "EnforceTLS": "True",
        }

        response = self.make_system_request("setResolver", params=params)

        return response, params

    def _transform_(self, defintion):
        mapping = {
            "USERINFO": "ldap_mapping",
            "LDAPFILTER": "ldap_userfilter",
            "LDAPBASE": "ldap_basedn",
            "BINDPW": "ldap_password",
            "BINDDN": "ldap_binddn",
            "SIZELIMIT": "ldap_sizelimit",
            "LDAPSEARCHFILTER": "ldap_searchfilter",
            "LOGINNAMEATTRIBUTE": "ldap_loginattr",
            "EnforceTLS": "enforcetls",
            "LDAPURI": "ldap_uri",
            "UIDTYPE": "ldap_uidtype",
            "NOREFERRALS": "noreferrals",
            "TIMEOUT": "ldap_timeout",
            "CACERTIFICATE": "ldap_certificate",
        }

        transform = {}
        for key, value in list(defintion.items()):
            if key in mapping:
                transform[mapping[key]] = value

        return transform

    @patch(
        "linotp.useridresolver.LDAPIdResolver.IdResolver.testconnection",
        MockedResolver.testconnection,
    )
    def test_testresolver_for_ldap(self):
        """admin testresolver api for the ldap resolver definition

        - provided parameters are ignored
        - verify that for the testconnection the resolver configuration is
            loaded though no parameters are provided.

        """
        global PASSWORD
        PASSWORD = None

        resolver_name = "MyLDAP"

        response, defintion = self.define_ldap_resolver(resolver_name)
        assert response.json["result"]["value"], response

        params = {
            "name": resolver_name,
        }
        response = self.make_admin_request("testresolver", params=params)
        value = response.json["result"]["value"]
        assert value["desc"]["desc"] == ("Can't contact LDAP server")

        # verify the method is called and a password is loaded from the config
        assert PASSWORD is not None

        global LDAPURI
        LDAPURI = None

        params = {
            "name": resolver_name,
            "LDAPURI": "ldap_uri",
        }
        response = self.make_admin_request("testresolver", params=params)
        value = response.json["result"]["value"]
        assert value["desc"]["desc"] == ("Can't contact LDAP server")

        # verify the method is called and "LDAPURI" parameter is ignored
        assert LDAPURI != "ldap_uri"
        assert LDAPURI is not None

    @pytest.mark.exclude_sqlite
    def test_testresolver_for_sql(self):
        """
        run the admin testresolver api for the sql resolver definition

        - no parameters other than the resolver name, must be specified
        """

        self.setUpSQL()

        self.delete_all_realms()
        self.delete_all_resolvers()

        resolverName = "MySQLResolver"
        realmName = "sqlrealm".lower()

        self.addUsers()
        self.addSqlResolver(resolverName)
        self.addSqlRealm(realmName, resolverName, defaultRealm=True)

        params = {"name": resolverName}

        response = self.make_admin_request("testresolver", params=params)
        assert '"rows": 12' in response

        self.delSqlRealm(realmName)
        self.delSqlResolver(resolverName)


# eof

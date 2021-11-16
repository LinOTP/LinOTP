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


"""
Test for admin authentication quality of life:
    provide flag for admin realm / resolver
"""

from flask import current_app

from linotp.tests import TestController


class TestAdminLabel(TestController):
    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        TestController.tearDown(self)

    def test_get_resolvers_with_flag(self):
        """verify that the 'ADMIN_RESOLVER_NAME' is marked as admin=True."""

        admin_resolver_name = current_app.config["ADMIN_RESOLVER_NAME"]

        response = self.make_system_request("getResolvers", params={})

        resolvers = response.json["result"]["value"]
        assert resolvers[admin_resolver_name]["admin"], resolvers

    def test_get_multiple_admin_resolvers(self):
        """verify that all resolvers of the admin realm are labeled as admin

        - we query all resolvers, which are the def, other and default admin
          resolver

        - all of them but not the admin resolver will be added to the admin
          realm. They now should have all the label 'admin'.

        - finally we have to drop all new defined admin resolvers from the
          admin realm. Otherwise the delete_all_resolvers() will fail.
          This is done by defining the admin realm to only contain the
          admin resolver

        """

        admin_realm_name = current_app.config["ADMIN_REALM_NAME"]
        fallback_admin_resolver_name = current_app.config[
            "ADMIN_RESOLVER_NAME"
        ]

        # ----------------------------------------------------------------- --

        # query all defined resolvers

        response = self.make_system_request("getResolvers", params={})
        resolvers = response.json["result"]["value"]

        resolver_specs = set()
        for resolver_name, resolver_description in resolvers.items():

            # preserve the admin resolver spec for later

            if resolver_name == fallback_admin_resolver_name:
                fallback_admin_resolver_spec = resolver_description["spec"]
                continue

            resolver_specs.add(resolver_description["spec"])

        # ----------------------------------------------------------------- --

        # create the admin realm with the identified resolver

        params = {
            "realm": admin_realm_name,
            "resolvers": ",".join(resolver_specs),
        }

        response = self.make_system_request("setRealm", params=params)
        assert response.json["result"]["value"], response

        # ----------------------------------------------------------------- --

        # verify that every resolver other than the default admin resolver
        # now contains the admin label

        response = self.make_system_request("getResolvers", params={})
        resolvers = response.json["result"]["value"]
        for resolver_name, resolver_description in resolvers.items():

            # the default admin resolver is now no more an admin resolver
            if resolver_name == fallback_admin_resolver_name:
                continue

            assert resolver_description["admin"], resolver_description

        # ----------------------------------------------------------------- --

        # finally reset the admin realm

        params = {
            "realm": admin_realm_name,
            "resolvers": fallback_admin_resolver_spec,
        }
        response = self.make_system_request(
            "setRealm",
            params=params,
            auth_resolver=fallback_admin_resolver_spec,
        )
        assert response.json["result"]["value"], response

    def test_admin_realm(self):
        """Verify admin realm and all its resolvers have the admin label.

        this tests verifies that the system endpoint getRealm and getResolver
        provide the admin label
        """

        admin_realm_name = current_app.config["ADMIN_REALM_NAME"].lower()

        response = self.make_system_request("getRealms", params={})
        assert response.json["result"]["status"], response
        realms = response.json["result"]["value"]

        admin_realm = realms[admin_realm_name]
        assert admin_realm, response
        assert admin_realm["admin"], response

        for resolver in admin_realm["useridresolver"]:
            params = {"resolver": resolver.rpartition(".")[2]}
            response = self.make_system_request("getResolver", params=params)
            resolver = response.json["result"]["value"]
            assert resolver["admin"], response

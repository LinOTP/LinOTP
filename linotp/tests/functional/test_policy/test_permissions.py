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

from linotp.lib.policy.definitions import get_policy_definitions

from . import TestPoliciesBase

REALMED_POLICY_SCOPES = ["admin", "getToken", "reporting.access"]
GLOBAL_POLICY_SCOPES = [
    "audit",
    "monitoring",
    "system",
    "tools",
]


class TestPermissions(TestPoliciesBase):
    def setUp(self):
        """setup the test controller"""
        TestPoliciesBase.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        """clean up after the tests"""
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestPoliciesBase.tearDown(self)
        return

    @property
    def _all_permissions(self):
        permissions = []
        policy_definitions = get_policy_definitions()
        for scope, actions in policy_definitions.items():
            permissions.extend([f"{scope}/{action}" for action in actions])
        return permissions

    @property
    def all_realmed_permissions(self):
        return [
            permission
            for permission in self._all_permissions
            if permission.startswith(tuple(REALMED_POLICY_SCOPES))
        ]

    @property
    def all_global_permissions(self):
        return [
            permission
            for permission in self._all_permissions
            if permission.startswith(tuple(GLOBAL_POLICY_SCOPES))
        ]

    def set_policies(self, policies: list, auth_user="admin"):
        for pol in policies:
            response = self.make_system_request(
                action="setPolicy", params=pol, auth_user=auth_user
            )
            assert response.json["result"]["status"], response
            assert response.json["result"]["value"]["setPolicy %s" % pol["name"]], (
                response
            )

    def get_permissions(self, auth_user):
        response = self.make_manage_request(
            "context", auth_user=auth_user, method="GET"
        )
        return response.json["detail"]["permissions"]

    def test_permissios_no_policies(self):
        """
        if no policy is defined, users have all permissions on all realms
        """
        permissions = self.get_permissions("admin")

        assert 4 == len(permissions["inRealm"])
        for realm, realm_permissions in permissions["inRealm"].items():
            assert set(self.all_realmed_permissions) == set(realm_permissions)
        assert set(self.all_realmed_permissions) == set(permissions["anyRealm"])
        assert set(self.all_global_permissions) == set(permissions["global"])

    def test_permissios_no_permissions(self):
        all_scopes = GLOBAL_POLICY_SCOPES + REALMED_POLICY_SCOPES
        policies = [
            {
                "name": f"policy_{i}",
                "scope": f"{scope}",
                "realm": "*",
                "action": "*",
                "user": "admin",
                "client": "",
            }
            for i, scope in enumerate(all_scopes)
        ]
        self.set_policies(policies)

        permissions = self.get_permissions("adminR1")

        assert 4 == len(permissions["inRealm"])
        for realm, realm_permissions in permissions["inRealm"].items():
            assert [] == realm_permissions
        assert [] == permissions["anyRealm"]
        assert [] == permissions["global"]

    def test_permissions_implicit_admin_show(self):
        policies = [
            {
                "name": "admin_show_myDefRealm",
                "scope": "admin",
                "realm": "myDefRealm",
                "action": "userlist",
                "user": "adminR1",
                "client": "",
            }
        ]
        self.set_policies(policies)

        # for admin
        permissions = self.get_permissions("admin")
        assert 4 == len(permissions["inRealm"])
        expected_permissions = [
            perm
            for perm in self.all_realmed_permissions
            if not perm.startswith("admin")
        ]
        for realm, realm_permissions in permissions["inRealm"].items():
            assert set(expected_permissions) == set(realm_permissions)
        assert set(expected_permissions) == set(permissions["anyRealm"])
        assert set(self.all_global_permissions) == set(permissions["global"])

        # for adminR1
        permissions = self.get_permissions("adminR1")
        assert 4 == len(permissions["inRealm"])
        expected_permissions = [
            perm
            for perm in self.all_realmed_permissions
            if not perm.startswith("admin")
        ]
        for realm, realm_permissions in permissions["inRealm"].items():
            if realm in ["mydefrealm"]:
                assert set(
                    expected_permissions + ["admin/show", "admin/userlist"]
                ) == set(realm_permissions)
            else:
                assert set(expected_permissions) == set(realm_permissions)
        assert set(expected_permissions) == set(permissions["anyRealm"])
        assert set(self.all_global_permissions) == set(permissions["global"])

    def test_permissions_explicit_policy(self):
        policies = [
            {
                "name": "admin_show_myDefRealm",
                "scope": "admin",
                "realm": "myDefRealm",
                "action": "show",
                "user": "adminR1",
                "client": "",
            }
        ]
        self.set_policies(policies)

        # for admin
        permissions = self.get_permissions("admin")
        assert 4 == len(permissions["inRealm"])
        expected_permissions = [
            perm
            for perm in self.all_realmed_permissions
            if not perm.startswith("admin")
        ]
        for realm, realm_permissions in permissions["inRealm"].items():
            assert set(expected_permissions) == set(realm_permissions)
        assert set(expected_permissions) == set(permissions["anyRealm"])
        assert set(self.all_global_permissions) == set(permissions["global"])

        # for adminR1
        permissions = self.get_permissions("adminR1")
        assert 4 == len(permissions["inRealm"])
        for realm, realm_permissions in permissions["inRealm"].items():
            if realm in ["mydefrealm"]:
                assert set(expected_permissions + ["admin/show"]) == set(
                    realm_permissions
                )
            else:
                assert set(expected_permissions) == set(realm_permissions)
        assert set(expected_permissions) == set(permissions["anyRealm"])
        assert set(self.all_global_permissions) == set(permissions["global"])

    def test_permissions_multiple_policies(self):
        policies = [
            {
                "name": "admin_show_myDefRealm",
                "scope": "admin",
                "realm": "myDefRealm",
                "action": "show",
                "user": "adminR1",
                "client": "",
            },
            {
                "name": "admin_show_myMixRealm",
                "scope": "admin",
                "realm": "myMixRealm",
                "action": "show",
                "user": "adminR2",
                "client": "",
            },
            {
                "name": "admin_show_linotp_admins",
                "scope": "admin",
                "realm": "linotp_admins",
                "action": "show",
                "user": "*",
                "client": "",
            },
            {
                "name": "admin_show_all",
                "scope": "admin",
                "realm": "*",
                "action": "show",
                "user": "adminR3",
                "client": "",
            },
        ]
        self.set_policies(policies)

        # for user `admin`
        # has all non-admin permissions for all/any realms
        permissions = self.get_permissions("admin")
        assert 4 == len(permissions["inRealm"])
        expected_permissions = [
            perm
            for perm in self.all_realmed_permissions
            if not perm.startswith("admin")
        ]

        for realm, realm_permissions in permissions["inRealm"].items():
            if realm in ["linotp_admins"]:
                assert set(expected_permissions + ["admin/show"]) == set(
                    realm_permissions
                )
            else:
                assert set(expected_permissions) == set(realm_permissions)
        assert set(expected_permissions) == set(permissions["anyRealm"])

        # for user `adminR2
        # has all non-admin permissions for all/any realms
        # additionally has "admin/show" for "linotp_admins", "mymixrealm"
        permissions = self.get_permissions("adminR2")
        assert 4 == len(permissions["inRealm"])
        expected_permissions = [
            perm
            for perm in self.all_realmed_permissions
            if not perm.startswith("admin")
        ]
        for realm, realm_permissions in permissions["inRealm"].items():
            if realm in ["linotp_admins", "mymixrealm"]:
                assert set(expected_permissions + ["admin/show"]) == set(
                    realm_permissions
                )
            else:
                assert set(expected_permissions) == set(realm_permissions)
        assert set(expected_permissions) == set(permissions["anyRealm"])

        # for user `adminR3
        # has all non-admin permissions and "admin/show"
        # for all/any realms
        permissions = self.get_permissions("adminR3")
        assert 4 == len(permissions["inRealm"])
        expected_permissions = set(
            [
                perm
                for perm in self.all_realmed_permissions
                if not perm.startswith("admin") or perm == "admin/show"
            ]
        )
        for realm, realm_permissions in permissions["inRealm"].items():
            assert expected_permissions == set(realm_permissions)
        assert expected_permissions == set(permissions["anyRealm"])

    def test_permissions_global_audit(self):
        policies = [
            {
                "name": "audit_view",
                "scope": "audit",
                "action": "view",
                "realm": "myDefRealm",
                "user": "adminR1",
                "client": "",
            }
        ]
        self.set_policies(policies)

        # for admin
        permissions = self.get_permissions("admin")
        assert 4 == len(permissions["inRealm"])
        for realm, realm_permissions in permissions["inRealm"].items():
            assert set(self.all_realmed_permissions) == set(realm_permissions)
        assert set(self.all_realmed_permissions) == set(permissions["anyRealm"])
        expected_global_permissions = set(
            [
                perm
                for perm in self.all_global_permissions
                if not perm.startswith("audit")
            ]
        )
        assert expected_global_permissions == set(permissions["global"])

        # for adminR1
        permissions = self.get_permissions("adminR1")
        assert 4 == len(permissions["inRealm"])
        for realm, realm_permissions in permissions["inRealm"].items():
            assert set(self.all_realmed_permissions) == set(realm_permissions)
        assert set(self.all_realmed_permissions) == set(permissions["anyRealm"])
        assert set(self.all_global_permissions) == set(permissions["global"])

    def test_permissions_deactivated_policies(self):
        policies = [
            {
                "name": "admin_show_deactivated",
                "scope": "admin",
                "realm": "myDefRealm",
                "action": "show",
                "user": "adminR1",
                "client": "",
                "active": False,
            }
        ]
        self.set_policies(policies)

        # for admin
        permissions = self.get_permissions("admin")
        assert 4 == len(permissions["inRealm"])
        for realm, realm_permissions in permissions["inRealm"].items():
            assert set(self.all_realmed_permissions) == set(realm_permissions)
        assert set(self.all_realmed_permissions) == set(permissions["anyRealm"])
        assert set(self.all_global_permissions) == set(permissions["global"])

        # for adminR1
        permissions = self.get_permissions("adminR1")
        assert 4 == len(permissions["inRealm"])
        for realm, realm_permissions in permissions["inRealm"].items():
            assert set(self.all_realmed_permissions) == set(realm_permissions)
        assert set(self.all_realmed_permissions) == set(permissions["anyRealm"])
        assert set(self.all_global_permissions) == set(permissions["global"])

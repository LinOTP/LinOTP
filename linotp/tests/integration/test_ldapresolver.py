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

import contextlib

import integration_data
import pytest
import requests
from linotp_selenium_helper.auth_ui import AuthUi
from linotp_selenium_helper.helper import BackendException
from linotp_selenium_helper.policy import Policy
from linotp_selenium_helper.test_case import TestCase
from requests.auth import HTTPDigestAuth


class TestLdapResolver:
    """Test class for LDAP resolver functionality"""

    # Test constants
    TEST_USER = "Johann.Bach"
    TEST_PASSWORD = "geheim1"
    AUTH_PASSWORD = "Test123!"
    # User identifiers for API tests
    DN_USER_ID = "cn=Johann%20Sebastian%20Bach,cn=Users,dc=corp,dc=lsexperts,dc=de"
    GUID_USER_ID = "595474e4-8fca-454b-b08e-ec3c275a52bd"

    # Test realm names
    DN_REALM = integration_data.samba_dn_resolver["name"]
    GUID_REALM = integration_data.samba_guid_resolver["name"]

    # Expected user counts
    EXPECTED_USER_COUNT_API = 5570
    EXPECTED_USER_COUNT_UI = 500  # UI can only show 500 out of 5570 users

    @pytest.fixture(autouse=True)
    def setup(self, testcase: TestCase):
        """Auto-setup fixture that runs before each test method"""
        self.testcase = testcase

        # Create both LDAP resolvers and realms
        self._create_ldap_resolver_and_realm(
            resolver_data=integration_data.samba_dn_resolver,
            realm_name=self.DN_REALM,
        )
        self._create_ldap_resolver_and_realm(
            resolver_data=integration_data.samba_guid_resolver,
            realm_name=self.GUID_REALM,
        )

        yield

        # Cleanup - Delete realms and resolvers
        self._cleanup_resolver_and_realm(
            integration_data.samba_dn_resolver["name"], self.DN_REALM
        )
        self._cleanup_resolver_and_realm(
            integration_data.samba_guid_resolver["name"], self.GUID_REALM
        )

    def make_api_v2_request(self, url, params=None):
        """Make an API v2 request with proper authentication"""
        auth = HTTPDigestAuth(self.testcase.http_username, self.testcase.http_password)
        response = requests.get(
            params=params,
            url=url,
            cookies={"access_token_cookie": self.testcase.manage_ui._jwt_session},
            headers={"X-CSRF-TOKEN": self.testcase.manage_ui._jwt_csrf_token},
            auth=auth,
        )
        response.raise_for_status()
        json_response = response.json()

        if not response.ok or json_response["result"]["status"] is False:
            raise BackendException(response, url=url)
        return json_response

    def _create_ldap_resolver_and_realm(self, resolver_data: dict, realm_name: str):
        """Helper function to create LDAP resolver and realm"""
        resolver_name = resolver_data["name"]
        resolver_list = ["useridresolver.LDAPIdResolver.IdResolver." + resolver_name]

        # Create resolver if it doesn't exist
        resolver_manager = self.testcase.useridresolver_manager
        existing_resolver = resolver_manager.get_resolver_params_via_api(resolver_name)
        resolver_exists = existing_resolver and existing_resolver["type"]
        if not resolver_exists:
            resolver_manager.create_resolver_via_api(resolver_data)

        # Create realm if it doesn't exist
        realm_manager = self.testcase.manage_ui.realm_manager
        existing_realms = realm_manager.get_realms_via_api()
        if realm_name not in existing_realms:
            realm_manager.create_via_api(realm_name, resolver_list)

    def _cleanup_resolver_and_realm(self, resolver_name: str, realm_name: str):
        """Helper function to cleanup LDAP resolver and realm"""
        # Delete realm
        realm_manager = self.testcase.manage_ui.realm_manager
        with contextlib.suppress(Exception):
            realm_manager.delete_realm_via_api(realm_name)

        # Delete resolver
        resolver_manager = self.testcase.useridresolver_manager
        with contextlib.suppress(Exception):
            resolver_manager.delete_resolver_via_api(resolver_name)

    @pytest.mark.parametrize("realm_name", [DN_REALM, GUID_REALM])
    def test_ldap_auth(self, realm_name):
        """Test LDAP resolver"""
        user_view = self.testcase.manage_ui.user_view

        # Verify user count and existence
        # there are actually 5570 users, but the UI can only show 500
        assert user_view.get_num_users(realm_name) == self.EXPECTED_USER_COUNT_UI
        assert user_view.user_exists(username=self.TEST_USER)

        # Create and assign token
        serial = self.testcase.manage_ui.token_enroll.create_static_password_token(
            password=self.TEST_PASSWORD
        )
        user_view.select_user(self.TEST_USER)
        self.testcase.manage_ui.token_view.assign_token(serial, pin=self.TEST_PASSWORD)

        # Set authentication policy
        Policy(
            self.testcase.manage_ui,
            "pin_policy",
            "authentication",
            "otppin=password",
            "*",
            "*",
        )

        # Test authentication
        auth = AuthUi(self.testcase)
        assert (
            auth.auth_using_index(
                f"{self.TEST_USER}@{realm_name}", self.AUTH_PASSWORD, self.TEST_PASSWORD
            )
            == auth.AUTH_SUCCESS
        )

    @pytest.mark.parametrize(
        "realm_name,user_id",
        [(DN_REALM, DN_USER_ID), (GUID_REALM, GUID_USER_ID)],
        ids=["DN_resolver", "GUID_resolver"],
    )
    def test_user_of_LDAP_resolver_by_uid_type(self, realm_name, user_id):
        """Test retrieving user by different UID types from LDAP resolver"""
        url = f"{self.testcase.base_url}/api/v2/resolvers/{realm_name}/users/{user_id}"
        json = self.make_api_v2_request(url=url)
        username = json["result"]["value"]["username"]
        assert username == self.TEST_USER, f"Expected {self.TEST_USER}, got {username}"

    @pytest.mark.parametrize("realm_name", [DN_REALM, GUID_REALM])
    def test_user_of_LDAP_resolver_with_searchTerm(self, realm_name):
        """Test searching users in LDAP resolver with search term"""
        json = self.make_api_v2_request(
            url=f"{self.testcase.base_url}/api/v2/resolvers/{realm_name}/users",
            params={"searchTerm": "Elinor"},
        )
        username_list = [
            user["username"] for user in json["result"]["value"]["pageRecords"]
        ]
        assert username_list == [
            "Elinor.Jaurigui",
            "Elinor.Kozlik",
            "Elinor.Landquist",
        ], str(username_list)

    @pytest.mark.parametrize("realm_name", [DN_REALM, GUID_REALM])
    def test_realm_user_count_via_api_v2(self, realm_name):
        """Test checking user count via API v2 realms endpoint"""
        json = self.make_api_v2_request(
            url=f"{self.testcase.base_url}/api/v2/realms/{realm_name}/users"
        )
        user_list = json["result"]["value"]
        user_count = len(user_list)

        assert user_count == self.EXPECTED_USER_COUNT_API

        # Verify we get a list of user objects
        assert isinstance(user_list, list), "User list should be a list"
        if user_list:
            # Verify user object structure (check first user has expected fields)
            first_user = user_list[0]
            expected_fields = {"userId", "username", "resolverName", "resolverClass"}
            assert expected_fields.issubset(first_user.keys()), (
                f"User object missing expected fields. Got: {list(first_user.keys())}"
            )

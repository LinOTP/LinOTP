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

import integration_data
import pytest
import requests
from linotp_selenium_helper.auth_ui import AuthUi
from linotp_selenium_helper.helper import BackendException
from linotp_selenium_helper.policy import Policy
from linotp_selenium_helper.test_case import TestCase
from requests.auth import HTTPDigestAuth


def make_api_v2_request(testcase, url, params=None):
    auth = HTTPDigestAuth(testcase.http_username, testcase.http_password)
    response = requests.get(
        params=params,
        url=url,
        cookies={"access_token_cookie": testcase.manage_ui._jwt_session},
        headers={"X-CSRF-TOKEN": testcase.manage_ui._jwt_csrf_token},
        auth=auth,
    )
    response.raise_for_status()
    json = response.json()

    if not response.ok or json["result"]["status"] is False:
        raise BackendException(response, url=url)
    return json


def _create_ldap_realm(testcase: TestCase, resolver_data: dict, realm_name: str):
    """Helper function to create LDAP resolver and realm"""
    resolver_name = resolver_data["name"]
    resolver_list = ["useridresolver.LDAPIdResolver.IdResolver." + resolver_name]

    # Create resolver if it doesn't exist
    resolver_manager = testcase.useridresolver_manager
    existing_resolver = resolver_manager.get_resolver_params_via_api(resolver_name)
    resolver_exists = existing_resolver and existing_resolver["type"]
    if not resolver_exists:
        resolver_manager.create_resolver_via_api(resolver_data)

    # Create realm if it doesn't exist
    realm_manager = testcase.manage_ui.realm_manager
    existing_realms = realm_manager.get_realms_via_api()
    if realm_name not in existing_realms:
        realm_manager.create_via_api(realm_name, resolver_list)


def _test_ldap_authentication(
    testcase: TestCase, realm: str, user: str = "Johann.Bach"
):
    """Helper function to test LDAP authentication"""
    user_view = testcase.manage_ui.user_view

    # Verify user count and existence
    # there are actually 5570 users, but the UI can only show 500
    assert user_view.get_num_users(realm) == 500
    assert user_view.user_exists(username=user)

    # Create and assign token
    serial = testcase.manage_ui.token_enroll.create_static_password_token(
        password="geheim1"
    )
    user_view.select_user(user)
    testcase.manage_ui.token_view.assign_token(serial, pin="geheim1")

    # Set authentication policy
    Policy(
        testcase.manage_ui,
        "pin_policy",
        "authentication",
        "otppin=password",
        "*",
        "*",
    )

    # Test authentication
    auth = AuthUi(testcase)
    assert (
        auth.auth_using_index(f"{user}@{realm}", "Test123!", "geheim1")
        == auth.AUTH_SUCCESS
    )


@pytest.fixture
def ldap_realm_test(testcase: TestCase):
    """Fixture to provide a test LDAP resolver in realm 'test'"""
    _create_ldap_realm(
        testcase=testcase,
        resolver_data=integration_data.samba_dn_resolver,
        realm_name="test",
    )


@pytest.fixture
def ldap_realm_corp(testcase: TestCase):
    """Fixture to provide a test LDAP resolver in realm 'corp' with uidType: objectGUID"""
    _create_ldap_realm(
        testcase=testcase,
        resolver_data=integration_data.samba_guid_resolver,
        realm_name="corp",
    )


@pytest.mark.usefixtures("ldap_realm_test")
def test_ldap_dn(testcase: TestCase):
    """Test LDAP resolver with DN type uid"""
    _test_ldap_authentication(testcase=testcase, realm="test")


@pytest.mark.usefixtures("ldap_realm_corp")
def test_ldap_objectGUID(testcase: TestCase):
    """Test LDAP resolver with objectGUID type uid"""
    _test_ldap_authentication(testcase=testcase, realm="corp")


@pytest.mark.usefixtures("ldap_realm_test")
def test_user_of_LDAP_resolver_with_DN_type_uid(testcase: TestCase):
    url = f"{testcase.base_url}/api/v2/resolvers/test/users/cn=Johann%20Sebastian%20Bach,cn=Users,dc=corp,dc=lsexperts,dc=de"
    json = make_api_v2_request(testcase=testcase, url=url)
    username = json["result"]["value"]["username"]
    assert username == "Johann.Bach", username


@pytest.mark.usefixtures("ldap_realm_corp")
def test_user_of_LDAP_resolver_with_GUID_type_uid(testcase: TestCase):
    url = f"{testcase.base_url}/api/v2/resolvers/corp/users/595474e4-8fca-454b-b08e-ec3c275a52bd"
    json = make_api_v2_request(testcase=testcase, url=url)
    username = json["result"]["value"]["username"]
    assert username == "Johann.Bach", username


@pytest.mark.usefixtures("ldap_realm_test")
def test_user_of_LDAP_resolver_with_searchTerm(testcase: TestCase):
    json = make_api_v2_request(
        testcase=testcase,
        url=f"{testcase.base_url}/api/v2/resolvers/test/users",
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

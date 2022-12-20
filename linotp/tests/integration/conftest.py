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
Pytest fixtures for linotp integration tests
"""

# pylint: disable=redefined-outer-name

from datetime import datetime
from pathlib import Path
from typing import Dict

import integration_data as data
import pytest

from linotp_selenium_helper.manage_ui import ManageUi
from linotp_selenium_helper.test_case import TestCase


@pytest.fixture(scope="module")
def testcase():
    """Testcase, which manages the driver and test configuration."""
    # TestCase is a unittest based class. We simulate the unittest
    # setup and teardown here so we can use it as a fixture
    t = TestCase()
    t.setup_class()
    yield t
    t.teardown_class()


@pytest.fixture
def musicians_resolver(testcase: TestCase) -> Dict[str, str]:
    """Create the musicians LDAP resolver and remove it after test.

    manage a resolver for a test:
    - create it, if needed
    - yield to the test
    - remove it, if it was created

    Returns a dict containing
        name: visible name
        type: type of resolver
        fullname: type.name
    """

    music_resolver = data.musicians_ldap_resolver

    useridresolver_manager = testcase.useridresolver_manager

    resolver = useridresolver_manager.get_resolver_params_via_api(
        music_resolver["name"]
    )

    existing = resolver and resolver["type"]

    if not existing:
        useridresolver_manager.create_resolver_via_api(
            data.musicians_ldap_resolver
        )

    yield dict(
        name=music_resolver["name"],
        type=music_resolver["type"],
        fullname=music_resolver["type"] + "." + music_resolver["name"],
    )

    if not existing:
        useridresolver_manager.delete_resolver_via_api(music_resolver["name"])


@pytest.fixture
def musicians_realm(
    testcase: TestCase, musicians_resolver: Dict[str, str]
) -> str:
    """Create the musician realm and remove it after the test.

    manage a realm for a test:
    - create it, if needed
    - yield to the test
    - remove it, if it was created

    """
    realm_name = "SE_realm_musicians"
    realm_manager = testcase.manage_ui.realm_manager

    realms = realm_manager.get_realms_via_api()

    existing = realm_name.lower() in realms

    if not existing:
        realm_manager.create_via_api(
            realm_name, musicians_resolver["fullname"]
        )

    yield realm_name

    if not existing:
        realm_manager.delete_realm_via_api(realm_name)


@pytest.fixture(autouse=True, scope="session")
def prepare_screenshot_artifacts():
    """Prepare directory to store current test result screenshots"""

    screenshots_dir = Path("Screenshots")
    screenshots_dir.mkdir(exist_ok=True)
    for f in screenshots_dir.glob("*"):
        f.unlink()


@pytest.fixture(autouse=True)
def create_debugging_screenshots(
    request: pytest.FixtureRequest,
    testcase: TestCase,
):
    """Create screenshots after test to improve debugging of failed tests"""
    yield
    testname = request.node.name
    timestamp = int(datetime.utcnow().timestamp() * 1000)
    filename = f"Screenshots/Screenshot_{testname}_{timestamp}.png"

    testcase.driver.save_screenshot(filename)

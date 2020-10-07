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
Pytest fixtures for linotp integration tests
"""

# pylint: disable=redefined-outer-name

from typing import Dict
import pytest

from linotp_selenium_helper.test_case import TestCase
from linotp_selenium_helper.manage_ui import ManageUi

@pytest.fixture(scope='module')
def testcase():
    """
    Testcase, which manages the driver and test configuration
    """

    # TestCase is a unittest based class. We simulate the unittest
    # setup and teardown here so we can use it as a fixture
    t = TestCase()
    t.setup_class()
    yield t
    t.teardown_class()

@pytest.fixture(scope='module')
def manage_ui(testcase) -> ManageUi:
    """
    Manage interface
    """
    return ManageUi(testcase)

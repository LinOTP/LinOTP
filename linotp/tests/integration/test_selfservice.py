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
"""LinOTP Selenium Test that tests the selfservice in the WebUI"""

import os

import pytest
from linotp_selenium_helper import (
    AngularSelfService,
    Policy,
    SelfService,
    TestCase,
)


def get_services_to_test():
    skip_angular = os.environ.get("SKIP_ANGULAR_SELF_SERVICE_TEST", "") != ""
    if skip_angular:
        # TODO enable for `AngularSelfService` once we test it
        return [SelfService]
    return [SelfService, AngularSelfService]


class TestSelfservice:
    """TestCase class that tests the minimal compatiblity between the two
    selfservice alternatives legacy mako-based selfservice and the new
    angular-based selfservice.
    """

    @pytest.fixture(autouse=True)
    def setUp(self, testcase):
        self.testcase = testcase

    @pytest.fixture(scope="module", params=get_services_to_test())
    def selfservice(self, testcase, request):
        # for each of the params in fixture params:
        current_selfservice_class = request.param
        # initiate it
        return current_selfservice_class(testcase)

    def test_selfservice(self, musicians_realm, selfservice):
        """Creates User-Id-Resolvers"""
        self.testcase.manage_ui.policy_view.clear_policies_via_api()
        Policy(
            self.testcase.manage_ui,
            "SE_policy_selfservice",
            "selfservice",
            "setOTPPIN, enrollPW, enrollHMAC",
            musicians_realm,
        )

        selfservice.open()

        login_user = "郎"
        login_password = "Test123!"
        selfservice.login(login_user, login_password, musicians_realm)

        selfservice.expect_ui_state(tokens=0, enrollment_options=2)

        selfservice.logout()

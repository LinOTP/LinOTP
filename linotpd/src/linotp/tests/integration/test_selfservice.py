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
"""LinOTP Selenium Test that tests the selfservice in the WebUI"""

import pytest
from linotp_selenium_helper import TestCase, Policy, SelfService, AngularSelfService


class TestSelfservice(TestCase):
    """TestCase class that tests the minimal compatiblity between the two
       selfservice alternatives legacy mako-based selfservice and the new
       angular-based selfservice.
    """

    @pytest.fixture(scope="module", params=[SelfService, AngularSelfService])
    def selfservice(self, request):
        return request.param(self)

    def test_selfservice(self, musicians_realm, selfservice):
        """Creates User-Id-Resolvers"""
        self.manage_ui.policy_view.clear_policies_via_api()
        Policy(self.manage_ui,
               "SE_policy_selfservice",
               "selfservice", "setOTPPIN, enrollPW, enrollHMAC",
               musicians_realm)

        selfservice.open()

        login_user = "郎"
        login_password = "Test123!"
        selfservice.login(
            login_user, login_password, musicians_realm)

        selfservice.expect_ui_state(
            tokens=0, enrollment_options=2)

        selfservice.logout()

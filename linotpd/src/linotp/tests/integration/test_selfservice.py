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
"""LinOTP Selenium Test that tests the selfservice in the WebUI"""

from linotp_selenium_helper import TestCase, Policy, SelfService

import integration_data as data


class TestSelfservice(TestCase):
    """TestCase class that tests the selfservice by first creating a policy
       that allows users to access the selfservice and change their OTP Pin
       and then logging in and verifying the text "set PIN" is present.
    """

    def setUp(self):
        TestCase.setUp(self)

        self.realm_name = "SE_realm_selfservice"
        self.reset_resolvers_and_realms(
            data.musicians_ldap_resolver, self.realm_name)
        self.selfservice = SelfService(self.driver, self.base_url)

    def test_selfservice(self):
        """Creates User-Id-Resolvers"""
        self.manage_ui.policy_view.clear_policies_via_api()
        Policy(self.manage_ui, "SE_policy_selfservice",
               "selfservice", "setOTPPIN, ", self.realm_name.lower())

        login_user = u"郎"
        login_password = "Test123!"

        self.selfservice.login(
            login_user, login_password, self.realm_name.lower())

        self.selfservice.select_tab(self.selfservice.tab_set_pin)

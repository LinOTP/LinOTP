# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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

from linotp_selenium_helper import TestCase, Policy

import integration_data as data

class TestSelfservice(TestCase):
    """TestCase class that tests the selfservice by first creating a policy
       that allows users to access the selfservice and change their OTP Pin
       and then logging in and verifying the text "set PIN" is present.
    """

    def setUp(self):
        TestCase.setUp(self)

        self.realm_name = "SE_realm_selfservice"
        self.reset_resolvers_and_realms(data.musicians_ldap_resolver, self.realm_name)

    def test_selfservice(self):
        """Creates User-Id-Resolvers"""
        self.manage_ui.policy_view.clear_policies()
        Policy(self.manage_ui, "SE_policy_selfservice",
               "selfservice", "setOTPPIN, ", self.realm_name.lower())

        login_user = u"郎"
        login_password = "Test123!"

        driver = self.driver
        driver.get(self.base_url + "/account/login")
        driver.find_element_by_id("login").clear()
        driver.find_element_by_id("login").send_keys(login_user + "@" + self.realm_name.lower())
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys(login_password)
        driver.find_element_by_css_selector("input[type=\"submit\"]").click()
        self.assertRegexpMatches(driver.find_element_by_css_selector("BODY").text,
                                 r"^[\s\S]*set PIN[\s\S]*$")

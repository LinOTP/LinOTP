# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2015 - 2018 KeyIdentity GmbH
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

from linotp_selenium_helper.helper import fill_form_element
import logging

"""
This file contains classes for interacting with the auth pages
in the Selenium tests
"""


class AuthUi(object):
    """Base for managing parts of the manage page """

    URL = "/auth/index"

    testcase = None
    """The UnitTest class that is running the tests"""

    driver = None
    """The Selenium driver"""

    # Result values
    AUTH_SUCCESS = 1
    "The authorisation was successful"

    AUTH_FAIL = 2
    "Failed to authorise"

    def __init__(self, testcase):
        """
        Create a new ManageUi instance. Normally this will be called
        from a derived class

        :param testcase: The test case that is controlling the UI
        """
        self.testcase = testcase
        self.driver = testcase.driver
        self.base_url = testcase.base_url

    CSS_AUTH_SUBMIT = "input[type=\"submit\"]"

    def open_page(self, page):
        self.driver.get(self.base_url + page)

    def fill_form_element(self, field_id, value):
        return fill_form_element(self.driver, field_id, value)

    def auth_using_index(self, user, pin, otp=''):
        self.open_page('/auth/index')

        self.fill_form_element('user', user)
        password = pin + otp
        self.fill_form_element('pass', password)
        self.driver.find_element_by_css_selector(self.CSS_AUTH_SUBMIT).click()
        return self._get_result()

    def auth_using_index3(self, user, pin, otp):
        self.open_page('/auth/index3')

        self.fill_form_element('user3', user)
        self.fill_form_element('pass3', pin)
        self.fill_form_element('otp3', otp)
        self.driver.find_element_by_css_selector(self.CSS_AUTH_SUBMIT).click()
        return self._get_result()

    def _get_result(self):
        '''
        Parse alert box text and return result code
        '''
        alert = self.driver.switch_to_alert()
        alert_text = alert.text
        logging.debug("Auth result: %s" % alert_text)
        alert.accept()
        if alert_text == "User successfully authenticated!":
            return self.AUTH_SUCCESS
        elif alert_text == 'User failed to authenticate!':
            return self.AUTH_FAIL

        raise RuntimeError("Unknown auth result received: %s" % alert_text)

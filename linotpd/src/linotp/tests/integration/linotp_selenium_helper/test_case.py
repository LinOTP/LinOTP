# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
"""Basic LinOTP Selenium Test-Case"""

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
import unittest
import warnings

from helper import get_from_tconfig


class TestCase(unittest.TestCase):
    """Basic LinOTP TestCase class"""

    def setUp(self):
        """Initializes the base_url and sets the driver"""
        self.http_username = get_from_tconfig(['linotp', 'username'], required=True)
        self.http_password = get_from_tconfig(['linotp', 'password'], required=True)
        self.http_host = get_from_tconfig(['linotp', 'host'], required=True)
        self.http_protocol = get_from_tconfig(['linotp', 'protocol'], default="https")
        self.base_url = self.http_protocol + "://" + self.http_username + \
                        ":" + self.http_password + "@" + self.http_host
        self.driver = None
        selenium_driver = get_from_tconfig(['selenium', 'driver'],
                                           default="firefox").lower()
        if selenium_driver == 'chrome':
            try:
                self.driver = webdriver.Chrome()
            except WebDriverException:
                warnings.warn("Error creating Chrome driver. Maybe you forgot installing"
                              " 'chromedriver'. If you wanted to use another Browser please"
                              " adapt your config file.")
        elif selenium_driver == 'firefox':
            self.driver = webdriver.Firefox()
        if self.driver is None:
            warnings.warn("Falling back to Firefox driver.")
            self.driver = webdriver.Firefox()
        self.driver.implicitly_wait(30)
        self.verification_errors = []
        self.accept_next_alert = True

    def tearDown(self):
        """Closes the driver and displays all errors"""
        self.driver.quit()
        self.assertEqual([], self.verification_errors)


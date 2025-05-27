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
from typing import TYPE_CHECKING, List, Union

from selenium.webdriver import Chrome, Firefox
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebElement
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait

from .helper import find_all_by_css, find_by_css, find_by_xpath

if TYPE_CHECKING:
    from .test_case import TestCase


class AngularSelfService(object):
    URL = "/selfservice"

    def __init__(self, testcase: "TestCase"):
        """
        Initialise the helper for the angular based self service

        """
        self.testcase: "TestCase" = testcase
        "The UnitTest class that is running the tests"

    @property
    def selfservice_url(self) -> str:
        """
        The base URL of the selfservice
        """
        return self.testcase.base_url + self.URL

    @property
    def driver(self) -> Union[Chrome, Firefox]:
        """
        Return a reference to the selenium driver
        """
        return self.testcase.driver

    def open(self):
        self.driver.get(self.selfservice_url)

    def login(self, user, password, realm=None):
        """
        Log in to selfservice

        @param realm: Realm name will be appended to username if given
        """
        if realm:
            login = "%s@%s" % (user, realm)
        else:
            login = user

        find_by_css(self.driver, "input[name='username']").send_keys(login)
        find_by_css(self.driver, "input[name='password']").send_keys(password)
        find_by_css(self.driver, "input[name='password']").submit()

        assert find_by_css(self.driver, "app-token-list")

    def expect_ui_state(self, tokens, enrollment_options):
        if tokens == 0 and enrollment_options == 0:
            assert find_by_css(self.driver, "#emptyStateSection"), (
                "Expected the section informing the user of no options being available"
            )

        if tokens > 0:
            token_cards = (
                find_all_by_css(self.driver, "#activeAuthSection > app-token-card")
                or []
            )
            assert len(token_cards) == tokens, (
                f"Expected {tokens} active tokens to be visible "
                f"but found {len(token_cards)}."
            )

        if enrollment_options > 0:
            enrollment_cards = (
                find_all_by_css(self.driver, "app-enrollment-grid > mat-card") or []
            )
            assert len(enrollment_cards) == enrollment_options, (
                f"Expected {enrollment_options} enrollment options "
                f"to be visible but found {len(enrollment_cards)}."
            )

    def logout(self):
        find_by_xpath(self.driver, "//button[contains(., 'Logout')]").click()
        assert find_by_css(self.driver, "app-login")

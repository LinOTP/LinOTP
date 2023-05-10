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

import time

import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.manage_ui import ManageUi


class TestManage:
    """
    TestCase class that tests the manage page
    """

    @pytest.fixture(autouse=True)
    def setUp(self, testcase):
        self.testcase = testcase
        # self.manage = ManageUi(self)
        # WIP:
        # The above line should not be different from this one:
        self.manage = self.testcase.manage_ui
        # if this ^ proposal succeeds,
        # 1- remove the comment
        # 2- replace all self.manage with self.testcase.manage_ui

    def test_manage_open(self):
        self.manage.open_manage()
        self.manage.check_manage_is_open()

    def test_close_menus(self):
        """
        Verify that the manage class is able to close an open menu
        """
        self.manage.open_manage()
        menu = self.manage.find_by_css(self.manage.MENU_LINOTP_CONFIG_CSS)
        menu_item_id = "menu_edit_resolvers"

        menu.click()
        WebDriverWait(self.testcase.driver, self.testcase.ui_wait_time).until(
            EC.element_to_be_clickable((By.ID, menu_item_id))
        )

        # without this pause the attribute is not yet ready
        # for clossing the menus
        time.sleep(0.1)
        self.manage.close_all_menus()
        WebDriverWait(
            self.testcase.driver, self.testcase.ui_wait_time
        ).until_not(EC.element_to_be_clickable((By.ID, menu_item_id)))

    def test_login_logout(self):
        self.testcase.driver.delete_all_cookies()

        self.testcase.driver.get(self.manage.manage_url)

        assert self.manage.is_login_open()
        assert not self.manage.is_manage_open()

        self.manage.login()

        assert self.manage.is_manage_open()
        assert not self.manage.is_login_open()

        self.manage.logout()

        assert self.manage.is_login_open()
        assert not self.manage.is_manage_open()

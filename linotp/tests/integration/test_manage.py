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

import pytest

from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.manage_ui import ManageUi


class TestManage(TestCase):
    """
    TestCase class that tests the manage page
    """

    @pytest.fixture(autouse=True)
    def setUp(self):
        self.manage = ManageUi(self)

    def test_manage_open(self):

        self.manage.open_manage()
        self.manage.check_url()

    def test_close_menus(self):
        """
        Verify that the manage class is able to close an open menu
        """
        self.manage.open_manage()
        menu = self.manage.find_by_css(self.manage.MENU_LINOTP_CONFIG_CSS)
        menu_item_id = "menu_edit_resolvers"

        menu.click()
        WebDriverWait(self.driver, self.ui_wait_time).until(
            EC.element_to_be_clickable((By.ID, menu_item_id))
        )
        self.manage.close_all_menus()
        WebDriverWait(self.driver, self.ui_wait_time).until_not(
            EC.element_to_be_clickable((By.ID, menu_item_id))
        )

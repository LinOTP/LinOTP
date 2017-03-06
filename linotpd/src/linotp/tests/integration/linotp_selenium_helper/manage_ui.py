# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2015 - 2017 KeyIdentity GmbH
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

import logging
import helper

from operator import methodcaller

from selenium.common.exceptions import WebDriverException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from manage_elements import ManageDialog
from realm import RealmManager
from policy import PolicyManager
from user_id_resolver import UserIdResolverManager
from user_view import UserView
from token_view import TokenView

"""
This file contains the main manage page class
"""


class ManageUi(object):
    """Object for representing the manage page itself. There should be
       a single ManageUi object to represent the browser page
    """

    URL = "/manage"

    testcase = None
    "The UnitTest class that is running the tests"

    welcome_screen = None
    "Welcome screen dialog"

    useridresolver_manager = None
    "UserIdResolver manager dialog"

    realm_manager = None
    "Realm manager dialog"
    token_view = None
    "Tokens tab"

    user_view = None
    "Users tab"

    policy_view = None
    "Policy tab"

    # CSS selectors
    CSS_TOOLS = 'link=Tools'
    CSS_IMPORT_TOKEN = 'link=Import Token File'

    # Menu entries
    MENU_LINOTP_CONFIG_CSS = '#menu > li'
    "CSS of the LinOTP Config menu"

    def __init__(self, testcase):
        """
        Create a new ManageUi instance. Normally this will be called
        from a derived class

        :param testcase: The test case that is controlling the UI
        """
        self.testcase = testcase

        self.welcome_screen = ManageDialog(
            self, 'welcome_screen', 'welcome_screen_close')

        self.useridresolver_manager = UserIdResolverManager(self)
        self.realm_manager = RealmManager(self)
        self.token_view = TokenView(self)
        self.user_view = UserView(self)
        self.policy_view = PolicyManager(self)

    def _is_url_open(self):
        possible_urls = (self.URL, self.URL + '/', self.URL + '/#')
        return self.driver.current_url.endswith(possible_urls)

    @property
    def manage_url(self):
        "The URL of the page"
        return self.testcase.base_url + self.URL

    @property
    def driver(self):
        "Return a reference to the selenium driver"
        return self.testcase.driver

    def check_url(self):
        """Check we are on the right page"""
        assert self._is_url_open(), \
            'URL %s should end with %s - page not loaded?' % \
            (self.driver.current_url, self.URL)
        self.testcase.assertEquals(self.driver.title, 'LinOTP 2 Management')

    def find_by_css(self, css_value):
        """Return the element indicated by CSS selector"""
        self.check_url()
        return helper.find_by_css(self.driver, css_value)

    def find_all_by_css(self, css_value):
        """Return a list of elements indicated by CSS selector"""
        self.check_url()
        return self.driver.find_elements_by_css_selector(css_value)

    def find_by_id(self, id_value):
        """Return the element by ID"""
        self.check_url()
        return helper.find_by_id(self.driver, id_value)

    def open_manage(self):
        if not self._is_url_open():
            self.driver.get(self.manage_url)

            self.welcome_screen.close_if_open()

    def activate_menu_item(self, menu_css, menu_item_id):
        """
        Open the manage UI and select the given menu item.

        If there are open dialogs in the UI, these will be
        closed first.

        Throws an assertion if this dialog does not have an associated menu entry
        """
        assert menu_item_id, "Open dialog requested but no menu id specified (menu_item_id"
        assert menu_css, "Open dialog requested but no toplevel menu specified (menu_css)"

        self.open_manage()

        menu_element = self.find_by_css(menu_css)
        #helper.hover(self.driver, menu_element)

        self.close_dialogs_and_click(menu_element)

        self.find_by_id(menu_item_id).click()

    def close_dialogs_and_click(self, element):
        """
        Click the given element. If it fails, close
        all dialogs and then retry
        """
        try:
            element.click()
        except WebDriverException:
            self.close_all_dialogs()
            # Retry
            element.click()

    def close_all_dialogs(self):
        """
        Close all active dialogs down
        """

        # Find all open dialogs
        dialogs = self.find_all_by_css('.ui-dialog[style*="display: block"]')

        # Sort by depth (the z-index attribute in reverse order)
        dialogs.sort(
            key=methodcaller('get_attribute', 'z-index'), reverse=True)

        # Close them
        for dialog in dialogs:
            logging.debug('Closing dialog %s' %
                          dialog.get_attribute('aria-describedby'))
            dialog.find_element_by_css_selector(
                ManageDialog.CLOSEBUTTON_CSS).click()

    def check_alert(self, expected_text=None, click_accept=False, click_dismiss=False):

        assert not click_accept or not click_dismiss, "check_alert cannot click both accept and dismiss"

        alert = self.driver.switch_to_alert()
        alert_text = alert.text

        if click_accept:
            alert.accept()
        elif click_dismiss:
            alert.dismiss()

        if expected_text:
            assert alert_text == expected_text, "Expecting alert text:%s found:%s" % (
                expected_text, alert_text)

    def wait_for_waiting_finished(self):
        """
        Some elements, e.g. the realms dialog, take some time for network communication.
        During this period, the do_waiting is displayed. Wait for this to disappear
        """
        WebDriverWait(self.driver, 10).until_not(
            EC.visibility_of_element_located((By.ID, "do_waiting")))

    def is_element_visible(self, css):
        """
        Check whether a given element is visible without waiting
        """
        if not self._is_url_open():
            return False

        try:
            self.testcase.disableImplicitWait()
            element = EC.visibility_of_element_located(
                (By.CSS_SELECTOR, css))(self.driver)
            self.testcase.enableImplicitWait()
        except Exception:
            return False

        is_visible = (element is not False)
        return is_visible

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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

import helper

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC

"""
This file contains classes for interacting with the manage page
in the Selenium tests
"""
class ManageUi(object):
    """Base for managing parts of the manage page """

    URL = "/manage"

    testcase = None
    """The UnitTest class that is running the tests"""

    driver = None
    """The Selenium driver"""

    # CSS selectors
    CSS_LINOTP_CONFIG = '#menu > li'
    CSS_TOOLS = 'link=Tools'
    CSS_IMPORT_TOKEN = 'link=Import Token File'

    def __init__(self, testcase):
        """
        Create a new ManageUi instance. Normally this will be called
        from a derived class

        :param testcase: The test case that is controlling the UI
        """
        self.testcase = testcase
        self.driver = testcase.driver
        self.base_url = testcase.base_url

    def _is_url_open(self):
        possible_urls = (self.URL, self.URL + '/', self.URL + '/#')
        return self.driver.current_url.endswith(possible_urls)

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

    def find_by_id(self, id_value):
        """Return the element by ID"""
        self.check_url()
        return helper.find_by_id(self.driver, id_value)

    def open_manage(self):
        driver = self.driver
        driver.get(self.base_url + self.URL)

    def open_tab(self, position):
        if not self._is_url_open():
            self.open_manage()

        tab_css = 'div#tabs > ul[role=tablist] > li[role=tab]:nth-of-type(%s) > a > span' % (position)
        tabpane_css = 'div#tabs > div.ui-tabs-panel:nth-of-type(%s)' % (position)

        tab_button = self.find_by_css(tab_css)
        tabpane_css = self.find_by_css(tabpane_css)

        tab_button.click()

    def _activate_dialog(self, reload_page, toplevel_selector, menu_id, dialog_id):
        """
        Activate the given menu item and check the dialog id.

        :param toplevel_selector: The CSS selector of the first menu.
        :param menu_id: The ID of the menu element
        :param dialog_id: The ID of the dialog that pops up
        """
        if reload_page or not self._is_url_open():
            self.open_manage()
        menu_element = self.find_by_css(toplevel_selector)
        helper.hover(self.driver, menu_element)
        self.find_by_id(menu_id).click()

        assert self.driver.find_element_by_id(dialog_id), 'Dialog id needs to be present: %s' % (dialog_id,)

    def activate_linotp_config_dialog(self, menu_id, dialog_id, reload_page=False):
        return self._activate_dialog(reload_page, self.CSS_LINOTP_CONFIG, menu_id, dialog_id)

    def _activate_tab(self, tab_id, reload_page=False):
        if reload_page or not self._is_url_open():
            self.open_manage()

    def check_alert(self, expected_text=None, click_accept=False, click_dismiss=False):

        assert not click_accept or not click_dismiss, "check_alert cannot click both accept and dismiss"

        alert = self.driver.switch_to_alert()
        alert_text = alert.text

        if click_accept:
            alert.accept()
        elif click_dismiss:
            alert.dismiss()

        if expected_text:
            assert alert_text == expected_text, "Expecting alert text:%s found:%s" % (expected_text, alert_text)

    def wait_for_waiting_finished(self):
        """
        Some elements, e.g. the realms dialog, take some time for network communication.
        During this period, the do_waiting is displayed. Wait for this to disappear
        """
        WebDriverWait(self.driver, 10).until_not(
                EC.visibility_of_element_located((By.ID, "do_waiting")))

class ManageConfigList(ManageUi):
    """
    Base class for dialogs based on manage ui and a list

    ie UserIdResolver, Realms dialog
    """

    menu_id = None
    dialog_id = None
    new_button_id = None
    close_button_id = None

    def open(self, reload_page=False):

        if reload_page or not self._is_url_open() or not self._is_dialog_open():
            activate = True
        else:
            # Dialog is already open and reload_page was not requested
            activate = False

        if activate:
            self.activate_linotp_config_dialog(self.menu_id, self.dialog_id, reload_page=True)

        self._parse_config_list()

    def _is_dialog_open(self):

        visibility = False

        try:
            self.testcase.disableImplicitWait()
            visibility = EC.visibility_of_element_located((By.ID, self.dialog_id))(self.driver)
            self.testcase.enableImplicitWait()
        except Exception:
            pass

        return (visibility is not False)  # Convert to true/false answer


    def check_dialog_is_open(self):
        for i in self.dialog_id, self.close_button_id:
            assert self.find_by_id(i), "Checking for dialog element (id=%s)" % (i,)
        self.wait_for_waiting_finished()


    def close(self):
        self.find_by_id(self.close_button_id).click()


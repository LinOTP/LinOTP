# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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

from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from linotp_selenium_helper.helper import (
    fill_form_element, close_alert_and_get_its_text)
from selenium.common.exceptions import TimeoutException

logger = logging.getLogger(__name__)


class SelfService(object):
    tab_register_motp = 'Register mOTP'
    tab_disable_token = 'Disable Token'
    tab_resync_token = 'Resync Token'
    tab_set_pin = 'set PIN'
    tab_set_motp_pin = 'set mOTP PIN'

    selected_token_css = 'div[role="tabpanel"][style="display: block;"] input.selectedToken'

    def __init__(self, driver, base_url):
        """
        Initialise the self service helper

        @param base_url: URL of the LinOTP service
        """
        self.base_url = base_url
        self.driver = driver

    def _find_by_id(self, id_value):
        """Return the element by ID"""
        return self.driver.find_element_by_id(id_value)

    def find_by_class(self, class_name):
        """Return the element by its class name"""
        return WebDriverWait(self.driver, 10).until(
            EC.visibility_of_element_located((By.CLASS_NAME, class_name)))

    def find_by_xpath(self, xpath):
        """Return the element by its xpath"""
        return WebDriverWait(self.driver, 10).until(
            EC.visibility_of_element_located((By.XPATH, xpath)))

    def login(self, user, password, realm=None):
        """
        Log in to self service via /account/login

        @param realm: Realm name will be appended to username if given
        """
        driver = self.driver
        driver.get(self.base_url + "/account/login")
        if realm:
            login = '%s@%s' % (user, realm)
        else:
            login = user

        fill_form_element(driver, "login", login)
        fill_form_element(driver, "password", password)
        self._find_by_id("password").submit()

    def wait_for_element_visibility(self, element_id, delay=5):
        WebDriverWait(self.driver, delay).until(
            EC.visibility_of_element_located((By.ID, element_id)))

    def select_tab(self, text):
        """
        Select a tab using the tab name

        @return: The ID of the tab pane
        """
        driver = self.driver
        tab = driver.find_element_by_xpath(
            "//div[@id='tabs']/ul/li/a/span[text()='%s']/ancestor::*[@role='tab']" % text)

        tab_pane_id = tab.get_attribute('aria-controls')

        assert tab_pane_id is not None, 'Tab pane ID could not be found'
        if tab.get_attribute('aria-expanded') == 'false':
            tab.click()

        # Wait for tab pane to be shown
        self.wait_for_element_visibility(tab_pane_id, 5)

        return tab_pane_id

    def select_tab_and_token(self, tabname, token):
        """
        Select a tab and then select a token by serial
        """
        self.select_tab(tabname)
        # Now wait for token field to be visible
        WebDriverWait(self.driver, 5).until(
            EC.visibility_of_element_located((By.CSS_SELECTOR, self.selected_token_css)))
        self.driver.find_element_by_id('tokenDiv').find_element_by_partial_link_text(
            token).click()

        # Wait for token field value to update
        try:
            WebDriverWait(self.driver, 5).until(
                EC.text_to_be_present_in_element_value((By.CSS_SELECTOR, self.selected_token_css), token))
        except TimeoutException:
            logger.error(
                'selfservice was not able to activate tab:%s token:%s', tabname, token)
            raise

    def set_pin(self, token, pin):
        """
        Test the pin setting screen by supplying
        the given PINs and checking for a given
        message
        """
        self.fill_pin_form(token, self.tab_set_pin, "pin1", "pin2",
                           "button_setpin", pin, pin, "PIN set successfully")

    def set_motp_pin(self, token, pin):
        self.fill_pin_form(token, self.tab_set_motp_pin, "mpin1", "mpin2",
                           "button_setmpin", pin, pin, "mOTP PIN set successfully")

    def fill_pin_form(self, token, tabname, pin1_id, pin2_id, button_id, pin1, pin2, expected_msg):
        """
        set PIN / set mOTP PIN form
        Select tab and token, fill in form and check message
        """
        driver = self.driver
        self.select_tab_and_token(tabname, token)

        fill_form_element(driver, pin1_id, pin1)
        fill_form_element(driver, pin2_id, pin2)
        driver.find_element_by_id(button_id).click()
        msg = close_alert_and_get_its_text(self.driver)
        assert msg == expected_msg, \
            "Unexpected message - Expected:%s - Found:%s" % (expected_msg, msg)

    def resync_token(self, token, otp1, otp2):
        """
        set PIN / set mOTP PIN form
        Select tab and token, fill in form and check message
        """
        driver = self.driver
        self.select_tab_and_token(self.tab_resync_token, token)
        fill_form_element(driver, "otp1", otp1)
        fill_form_element(driver, "otp2", otp2)
        driver.find_element_by_id("button_resync").click()
        msg = close_alert_and_get_its_text(self.driver)
        expected_msg = "Token resynced successfully"
        assert msg == expected_msg, \
            "Unexpected message - Expected:%s - Found:%s" % (expected_msg, msg)

    def disable_token(self, token):
        """
        set PIN / set mOTP PIN form
        Select tab and token, fill in form and check message
        """
        driver = self.driver
        self.select_tab_and_token(self.tab_disable_token, token)
        driver.find_element_by_id("button_disable").click()
        msg = close_alert_and_get_its_text(self.driver)
        expected_msg = "Token disabled successfully"
        assert msg == expected_msg, \
            "Unexpected message - Expected:%s - Found:%s" % (expected_msg, msg)

    def logout(self):
        self.driver.find_element_by_link_text("Logout").click()

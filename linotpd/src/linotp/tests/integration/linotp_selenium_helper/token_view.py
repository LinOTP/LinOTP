# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
"""Contains TokenView class"""

import time
import logging

from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import StaleElementReferenceException, NoSuchElementException

from helper import fill_form_element, find_by_css, find_by_id
from manage_ui import ManageUi

logger = logging.getLogger(__name__)

class TokenViewException(Exception):
    pass


class TokenView(ManageUi):
    """Represents the 'Token View' tab in the LinOTP WebUI"""

    token_tabpane_css = 'div#tabs > div.ui-tabs-panel:nth-of-type(1)'
    token_lines_css = "#token_table tr td:first-child div"
    delete_button_id = 'button_delete'
    token_table_css = 'table#token_table'
    stat_css = token_tabpane_css + " > div.flexigrid span.pPageStat"  # Information text about number of tokens shown
    flexigrid_reload_button_css = "div#tabs div.flexigrid div.pReload"

    def _is_tab_open(self):

        if not self._is_url_open():
            return False

        try:
            self.testcase.disableImplicitWait()
            element = EC.visibility_of_element_located((By.CSS_SELECTOR, self.token_tabpane_css))(self.driver)
            self.testcase.enableImplicitWait()
        except Exception, e:
            pass
            #return False

        return (element is not False) # Convert to true/false answer

    def _wait_for_loading_complete(self):
        # Wait for flexigrid to become available
        WebDriverWait(self.driver, 4).until(
                     EC.element_to_be_clickable((By.CSS_SELECTOR, self.flexigrid_reload_button_css))
                )

        # While the flexigrid is relaoding the tokens, the reload button is set with class 'loading'.
        # Wait for this to disappear
        flexigrid_reloading_css = self.flexigrid_reload_button_css + ".loading"
        self.testcase.disableImplicitWait()
        WebDriverWait(self.driver, 10, ignored_exceptions=NoSuchElementException).until_not(
                     EC.presence_of_element_located((By.CSS_SELECTOR, flexigrid_reloading_css))
                )
        self.testcase.enableImplicitWait()

    def _open_tab_token_view(self):
        """Select the 'Token View' tab"""
        self.open_tab(1)

        self._wait_for_loading_complete()
        self.driver.find_element_by_css_selector("option[value=\"100\"]").click()  # Show 100 tokens in view

        self._wait_for_loading_complete()

    def open(self):
        self._open_tab_token_view()

    def _get_status_text(self):
        e = self.find_by_css(self.stat_css)
        return e.text

    def _get_token_list(self):
        "Open list and return all tokens shown in the view"
        self._open_tab_token_view()

        # In order to avoid long timeouts if the token list is empty, check how many are shown
        text = self._get_status_text()

        if text == "No items":
            return []

        e = self.driver.find_elements_by_css_selector(self.token_lines_css)
        return e

    def select_all_tokens(self):
        tokens = self._get_token_list()

        for t in tokens:
            t.click()

    def _delete_selected_tokens(self):
        tokens_before = [t.text for t in self._get_token_list()]
        if not len(tokens_before):
            return

        find_by_id(self.driver, self.delete_button_id).click()
        deletetok_confirm_dialog_css = "div[aria-describedby='dialog_delete_token'] span.ui-dialog-title"
        self.testcase.assertEquals("Delete selected tokens?", self.find_by_css(deletetok_confirm_dialog_css).text)

        t = find_by_css(self.driver, "#dialog_delete_token").text
        assert t.startswith(r"The following tokens will be permanently deleted")

        find_by_id(self.driver, "button_delete_delete").click()

        self.wait_for_waiting_finished()  # Wait for delete API call
        self._wait_for_loading_complete()  # Wait for flexigrid to refresh

        tokens_after = [t.text for t in self._get_token_list()]

        if len(tokens_before) <= len(tokens_after):
            logging.warn("Number of tokens did not reduce as expected. from=%s to=%s",
                         tokens_before, tokens_after)
            assert len(tokens_before) > len(tokens_after), \
                    "The token list should be shorter. Before:%s After:%s" % (len(tokens_before), len(tokens_after))

    def delete_all_tokens(self):
        self.select_all_tokens()
        self._delete_selected_tokens()


    def select_token(self, token_serial):
        """Selects (clicks on) a token in the WebUI. This function does not reload
           the page (because otherwise the selection would be lost) neither before
           nor after the selection.
        """
        token_serials = self._get_token_list()

        for token in token_serials:
            if token.text == token_serial:
                token.click()

    def delete_token(self, token_serial):
        self.select_token(token_serial)
        self._delete_selected_tokens()

    def assign_token(self, token_serial, pin):
        driver = self.driver

        self.select_token(token_serial)

        assign_id = "button_assign"
        WebDriverWait(self.driver, 4).until(
                     EC.element_to_be_clickable((By.ID, assign_id))
                )
        driver.find_element_by_id(assign_id).click()

        self.wait_for_waiting_finished()
        fill_form_element(driver, "pin1", pin)
        fill_form_element(driver, "pin2", pin)
        driver.find_element_by_id("button_setpin_setpin").click()
        self.wait_for_waiting_finished()  # Wait for delete API call

    def get_token_info(self, token_serial):
        """
        Extracts the token info from the WebUI and returns it as a dictionary.
        """
        keys_with_subtable = ['LinOtp.TokenInfo', 'LinOtp.RealmNames']
        self.select_token(token_serial)
        self.driver.find_element_by_id("button_tokeninfo").click()
        token_info = {}
        rows = self.driver.find_elements_by_css_selector("#dialog_token_info > table >tbody > tr")

        self.testcase.disableImplicitWait() # Some rows do not contain all elements

        for row in rows:
            tds = row.find_elements_by_css_selector("td.tokeninfoOuterTable")
            key = tds[0].text
            value_element = tds[1]
            if key in keys_with_subtable:
                inner_rows = value_element.find_elements_by_css_selector('table.tokeninfoInnerTable tr')
                if key == 'LinOtp.RealmNames':
                    token_info[key] = []
                else:
                    token_info[key] = {}
                for inner_row in inner_rows:
                    inner_tds = inner_row.find_elements_by_css_selector("td.tokeninfoInnerTable")
                    if key == 'LinOtp.RealmNames':
                        inner_value = inner_tds[0].text
                        token_info[key].append(inner_value)
                    else:
                        inner_key = inner_tds[0].text
                        inner_value = inner_tds[1].text
                        token_info[key][inner_key] = inner_value
            else:
                token_info[key] = value_element.text
        self.testcase.enableImplicitWait()
        return token_info

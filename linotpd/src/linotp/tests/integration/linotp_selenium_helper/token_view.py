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
"""Contains TokenView class"""

import logging

from manage_elements import ManageTab, ManageDialog
from helper import fill_form_element, find_by_css, find_by_id

logger = logging.getLogger(__name__)


class TokenViewException(Exception):
    pass


class TokenView(ManageTab):
    """Represents the 'Token View' tab in the LinOTP WebUI"""

    TAB_INDEX = 1

    token_lines_css = "#token_table tr td:first-child div"
    delete_button_id = 'button_delete'
    token_table_css = 'table#token_table'

    alert_dialog = None
    "Access to the alert dialog"

    delete_confirm_dialog = None
    "Dialog box shown when tokens are deleted"

    def __init__(self, manage_ui):
        super(TokenView, self).__init__(manage_ui)
        self.alert_dialog = ManageDialog(manage_ui, 'alert_box_text')
        self.delete_confirm_dialog = ManageDialog(
            manage_ui, 'dialog_delete_token')

    def open(self):
        """Select the 'Token View' tab"""
        self.open_tab()

        self.driver.find_element_by_css_selector(
            "option[value=\"100\"]").click()  # Show 100 tokens in view

        self.wait_for_grid_loading()
        # self.manage.wait_for_waiting_finished()

    def _get_status_text(self):
        # Information text about number of tokens shown
        stat_css = self.flexigrid_css + " span.pPageStat"
        e = self.find_by_css(stat_css)
        return e.text

    def _get_token_list(self):
        "Open list and return all tokens shown in the view"
        self.open()

        # In order to avoid long timeouts if the token list is empty, check how
        # many are shown
        text = self._get_status_text()

        if text == "No items":
            return []

        e = self.driver.find_elements_by_css_selector(self.token_lines_css)
        return e

    def select_all_tokens(self):
        tokens = self._get_token_list()

        selected_tokens = self.get_selected_tokens()

        for t in tokens:
            if t.text not in selected_tokens:
                t.click()

    def _delete_selected_tokens(self):
        tokens_before = [t.text for t in self._get_token_list()]
        if not len(tokens_before):
            return

        find_by_id(self.driver, self.delete_button_id).click()

        delete_dialog = self.delete_confirm_dialog

        # The delete confirm dialog will open now
        delete_dialog.check_title("Delete selected tokens?")

        t = delete_dialog.get_text()
        assert t.startswith(
            r"The following tokens will be permanently deleted")

        delete_dialog.click_button('button_delete_delete')

        self.manage.wait_for_waiting_finished()  # Wait for delete API call
        self.wait_for_grid_loading()  # Wait for flexigrid to refresh

        tokens_after = [t.text for t in self._get_token_list()]

        if len(tokens_before) <= len(tokens_after):
            logging.warn("Number of tokens did not reduce as expected. from=%s to=%s",
                         tokens_before, tokens_after)
            assert len(tokens_before) > len(tokens_after), \
                "The token list should be shorter. Before:%s After:%s" % (
                    len(tokens_before), len(tokens_after))

    def delete_all_tokens(self):
        self.open()
        self.select_all_tokens()
        self._delete_selected_tokens()

    def get_selected_tokens(self):
        """
        Retrieve a list of currently selected token serials in the UI
        """
        selected_tokens = find_by_id(self.driver, "selected_tokens").text

        return selected_tokens.split(', ')

    def token_click(self, token_serial):
        """
        Click on the given token. This toggles its selected state.
        """
        token_serials = self._get_token_list()

        for token in token_serials:
            if token.text == token_serial:
                token.click()
                return

    def select_token(self, token_serial):
        """Selects (clicks on) a token in the WebUI. This function does not reload
           the page (because otherwise the selection would be lost) neither before
           nor after the selection.

           If the token is already selected, this does nothing
        """
        if token_serial not in self.get_selected_tokens():
            self.token_click(token_serial)

    def deselect_token(self, token_serial):
        """
        Deselect a token if it is already selected
        """
        if token_serial in self.get_selected_tokens():
            self.token_click(token_serial)

    def delete_token(self, token_serial):
        self.select_token(token_serial)
        self._delete_selected_tokens()

    def assign_token(self, token_serial, pin):
        driver = self.driver

        self.select_token(token_serial)

        assign_id = "button_assign"
        # WebDriverWait(self.driver, 4).until(
        #             EC.element_to_be_clickable((By.ID, assign_id))
        #        )
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
        rows = self.driver.find_elements_by_css_selector(
            "#dialog_token_info > table >tbody > tr")

        # Some rows do not contain all elements
        self.testcase.disableImplicitWait()

        for row in rows:
            tds = row.find_elements_by_css_selector("td.tokeninfoOuterTable")
            key = tds[0].text
            value_element = tds[1]
            if key in keys_with_subtable:
                inner_rows = value_element.find_elements_by_css_selector(
                    'table.tokeninfoInnerTable tr')
                if key == 'LinOtp.RealmNames':
                    token_info[key] = []
                else:
                    token_info[key] = {}
                for inner_row in inner_rows:
                    inner_tds = inner_row.find_elements_by_css_selector(
                        "td.tokeninfoInnerTable")
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

        self.driver.find_element_by_id("button_ti_close").click()
        return token_info

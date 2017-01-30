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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""Contains UserView class"""

import time

from user_id_resolver import UserIdResolver
from helper import select

class UserViewException(Exception):
    pass

class UserView:
    """Represents the 'User View' tab in the LinOTP WebUI"""

    def __init__(self, driver, base_url, realm_name):
        """"""
        self.driver = driver
        self.base_url = base_url
        self.realm_name = realm_name.lower()

    def _select_realm(self):
        """We assume we are one the main page /manage and then select
           the realm from the <select> dropdown on the left
        """
        realm_select = self.driver.find_element_by_id('realm')
        select(self.driver, realm_select, self.realm_name)

    def _open_tab_user_view(self):
        """
        Select the 'User View' tab
        Returns the #id of the "User View" tab.
        """
        user_view_tab = self.driver.find_element_by_xpath(
            u"//div[@id='tabs']/ul/li/a/span[text()='User View']"
            )
        tab_id = user_view_tab.find_element_by_xpath("../..").get_attribute("aria-controls")
        user_view_tab.click()
        time.sleep(1)
        return tab_id

    def get_num_users(self):
        """Return the number of users in the current realm"""
        self.driver.get(self.base_url + "/manage")
        self._select_realm()
        tab_id = self._open_tab_user_view()
        time.sleep(2)
        pPageStat = self.driver.find_element_by_css_selector("#%s > div.flexigrid "
            "> div.pDiv > div.pDiv2 > div.pGroup > span.pPageStat" % tab_id).text
        if pPageStat == "No items":
            return 0
        numbers = [int(s) for s in pPageStat.split() if s.isdigit()]
        if len(numbers) != 3:
            raise UserViewException("Could not determine number of users. "
                                     "Missing: 'Displaying N1 to N2 of N3'")
        return numbers[2]

    def user_exists(self, username):
        """Return True if users exists in the current realm"""
        self.driver.get(self.base_url + "/manage")
        self._select_realm()
        tab_id = self._open_tab_user_view()
        search_box = self.driver.find_element_by_css_selector("#%s > div.flexigrid "
            "> div.sDiv > div.sDiv2 > input[name=\"q\"]" % tab_id)
        search_box.send_keys(username)

        select_type = self.driver.find_element_by_css_selector(
                    "#%s > div.flexigrid > div.sDiv > div.sDiv2 > "
                    "select[name=\"qtype\"]" % tab_id
                )
        select(self.driver, select_type, "in username")

        time.sleep(1)
        submit_button = self.driver.find_element_by_css_selector(
                    "#%s > div.flexigrid > div.sDiv > div.sDiv2 > "
                    "input[name=\"search_button\"]" % tab_id
                )
        submit_button.click()
        time.sleep(2)

        usernames = self.driver.find_elements_by_css_selector("#user_table tr "
                                                              "td:first-child div")
        for user in usernames:
            if user.text == username:
                return True
        return False

    def select_user(self, username):
        """Selects (clicks on) a user in the WebUI. This function does not reload
           the page (because otherwise the selection would be lost) neither before
           nor after the selection.
        """
        self._select_realm()
        tab_id = self._open_tab_user_view()
        search_box = self.driver.find_element_by_css_selector("#%s > div.flexigrid "
            "> div.sDiv > div.sDiv2 > input[name=\"q\"]" % tab_id)
        search_box.clear()
        search_box.send_keys(username)

        select_type = self.driver.find_element_by_css_selector(
                    "#%s > div.flexigrid > div.sDiv > div.sDiv2 > "
                    "select[name=\"qtype\"]" % tab_id
                )
        select(self.driver, select_type, "in username")

        time.sleep(1)
        submit_button = self.driver.find_element_by_css_selector(
                    "#%s > div.flexigrid > div.sDiv > div.sDiv2 > "
                    "input[name=\"search_button\"]" % tab_id
                )
        submit_button.click()
        time.sleep(2)

        usernames = self.driver.find_elements_by_css_selector("#user_table tr "
                                                              "td:first-child div")
        for user in usernames:
            if user.text == username:
                user.click()


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
"""Contains UserView class"""


from user_id_resolver import UserIdResolver
from manage_ui import ManageUi
from helper import select

class UserViewException(Exception):
    pass

class UserView(ManageUi):
    """Represents the 'User View' tab in the LinOTP WebUI"""

    def __init__(self, testcase, realm_name):
        super(UserView, self).__init__(testcase)
        self.realm_name = realm_name.lower()

    def select_realm(self, realm_name=None):
        """We assume we are one the main page /manage and then select
           the realm from the <select> dropdown on the left
        """
        if realm_name:
            self.realm_name = realm_name.lower()

        realm_select = self.driver.find_element_by_id('realm')
        select(self.driver, realm_select, self.realm_name)

    def _open_tab_user_view(self):
        """
        Select the 'User View' tab and the realm

        Returns the element containing the user view
        """
        tab = self.open_tab(2)
        self.select_realm()
        self.wait_for_waiting_finished()
        return tab

    def get_num_users(self):
        """Return the number of users in the current realm"""
        usertab = self._open_tab_user_view()

        pPageStat = usertab.find_element_by_css_selector("div.flexigrid "
            "> div.pDiv > div.pDiv2 > div.pGroup > span.pPageStat").text
        if pPageStat == "No items":
            return 0
        numbers = [int(s) for s in pPageStat.split() if s.isdigit()]
        if len(numbers) != 3:
            raise UserViewException("Could not determine number of users. "
                                     "Missing: 'Displaying N1 to N2 of N3'. Found:<%s>" % pPageStat)
        return numbers[2]

    def get_user_element(self, username):
        """Return element for the user in question
        """

        usertab = self._open_tab_user_view()
        usertab_id = usertab.get_attribute("id")

        search_box = usertab.find_element_by_css_selector("div.flexigrid "
            "> div.sDiv > div.sDiv2 > input[name=\"q\"]")
        search_box.clear()
        search_box.send_keys(username)

        select_type = usertab.find_element_by_css_selector(
                    "div.flexigrid > div.sDiv > div.sDiv2 > "
                    "select[name=\"qtype\"]"
                )
        select(self.driver, select_type, "in username")

        submit_button = usertab.find_element_by_css_selector(
                    "div.flexigrid > div.sDiv > div.sDiv2 > "
                    "input[name=\"search_button\"]"
                )
        submit_button.click()
        self.wait_for_grid_loading()

        usernames = self.driver.find_elements_by_css_selector(
            '#%s #user_table [abbr="username"] div' % usertab_id)

        for user in usernames:
            if user.text == username:
                return user
        return None

    def user_exists(self, username):
        """Return True if users exists in the current realm"""
        user = self.get_user_element(username)

        return user is not None

    def select_user(self, username):
        """Selects (clicks on) a user in the WebUI. This function does not reload
           the page (because otherwise the selection would be lost) neither before
           nor after the selection.
        """
        user = self.get_user_element(username)

        assert user
        user.click()

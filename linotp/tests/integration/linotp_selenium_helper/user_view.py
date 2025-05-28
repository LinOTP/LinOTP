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
"""Contains UserView class"""

from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from .helper import select
from .manage_elements import ManageTab


class UserViewException(Exception):
    pass


class UserView(ManageTab):
    """Represents the 'User View' tab in the LinOTP WebUI"""

    TAB_INDEX = 2

    def __init__(self, manage_ui, realm_name=None):
        super(UserView, self).__init__(manage_ui)
        if realm_name:
            # This realm will be autoselected when the view is opened
            self.realm_name = realm_name.lower()
        else:
            self.realm_name = None

    def select_realm(self, realm_name=None):
        """We assume we are one the main page /manage and then select
        the realm from the <select> dropdown on the left
        """
        if not realm_name:
            realm_name = self.realm_name
        else:
            realm_name = realm_name.lower()

        realm_select = self.driver.find_element(By.ID, "realm")

        WebDriverWait(self.driver, self.testcase.ui_wait_time).until(
            EC.visibility_of_element_located((By.ID, "realm"))
        )

        select(self.driver, realm_select, realm_name)
        self.wait_for_grid_loading()

    def _get_tab(self):
        "Return content element of the tab"
        tab = self.open_tab()
        return tab

    def _open_tab_user_view(self, realm_name=None):
        """
        Select the 'User View' tab and the realm

        Returns the element containing the user view
        """
        tab = self._get_tab()
        if realm_name is not None:
            self.select_realm(realm_name)
        return tab

    def get_num_users(self, realm_name=None):
        """
        Return the number of users in the realm

        @param realm_name If given, switch to this realm first
        """
        usertab = self._open_tab_user_view(realm_name)
        assert usertab, "User tab could not be opened for realm %s" % realm_name

        self.clear_filters(realm_name)
        pPageStat = usertab.find_element(
            By.CSS_SELECTOR,
            "div.flexigrid > div.pDiv > div.pDiv2 > div.pGroup > span.pPageStat",
        ).text
        if pPageStat == "No items":
            return 0
        numbers = [int(s) for s in pPageStat.split() if s.isdigit()]
        if len(numbers) != 3:
            raise UserViewException(
                "Could not determine number of users. "
                "Missing: 'Displaying N1 to N2 of N3'. Found:<%s>" % pPageStat
            )
        return numbers[2]

    def _get_searchbox_element(self):
        """
        Return element containing user search box
        """
        usertab = self.open_tab()
        search_box = usertab.find_element(
            By.CSS_SELECTOR,
            'div.flexigrid > div.sDiv > div.sDiv2 > input[name="q"]',
        )
        return search_box

    def clear_filters(self, realm_name=None):
        # Clear filter settings and reload
        e = self._get_searchbox_element()
        e.clear()
        self._submit_search(realm_name)
        self.wait_for_grid_loading()

    def _submit_search(self, realm_name=None):
        usertab = self._open_tab_user_view(realm_name)
        submit_button = usertab.find_element(
            By.CSS_SELECTOR,
            'div.flexigrid > div.sDiv > div.sDiv2 > input[name="search_button"]',
        )
        submit_button.click()

    def get_user_element(self, username):
        """Return element for the user in question"""

        usertab = self._open_tab_user_view()
        usertab_id = usertab.get_attribute("id")

        search_box = self._get_searchbox_element()
        search_box.clear()
        search_box.send_keys(username)

        select_type = usertab.find_element(
            By.CSS_SELECTOR,
            'div.flexigrid > div.sDiv > div.sDiv2 > select[name="qtype"]',
        )
        select(self.driver, select_type, "Username")

        self._submit_search()
        self.wait_for_grid_loading()

        usernames = self.driver.find_elements(
            By.CSS_SELECTOR,
            '#%s #user_table [abbr="username"] div' % usertab_id,
        )

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

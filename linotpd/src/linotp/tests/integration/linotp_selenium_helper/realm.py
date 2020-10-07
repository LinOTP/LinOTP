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
"""Contains Realm class"""

import logging
import time
import re
from typing import List, Union

from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from .helper import find_by_css, fill_form_element
from .manage_elements import ManageDialog
from .user_id_resolver import UserIdResolverManager

LOGGER = logging.getLogger(__name__)


class EditRealmDialog(ManageDialog):
    "Realm create / edit dialog"

    edit_save_button_id = 'button_editrealms_save'

    def __init__(self, manage):
        super(EditRealmDialog, self).__init__(
            manage, 'dialog_edit_realms')

    @property
    def realm_dialog(self):
        return self.manage.realm_manager

    def fill_and_save(self, realm_name, resolvers):
        """
        Fill in realm name, resolvers and save dialog
        """
        self.set_realm_name(realm_name)
        self.set_resolvers(resolvers)
        self.save()

    def set_realm_name(self, name):
        fill_form_element(self.driver, "realm_name", name)

    def get_resolvers(self):
        """
        Parse resolvers section of dialog

        @return: A list of UserIdResolverManager.ResolverElement
        """
        resolvers = []

        # The resolvers list could be empty, so disable implicit wait for the
        # list
        with self.implicit_wait_disabled():
            elements = self.get_body_element().find_elements_by_css_selector(
                #'#resolvers_list, #resolvers_list > ol > li')
                '#realm_edit_resolver_list, #realm_edit_resolver_list ol > li')

            for element in elements:
                # Skip dialog element - we just asked for this to workaround
                # the delay if the list is empty
                if element.get_attribute('id') == 'realm_edit_resolver_list':
                    continue

                resolvers.append(
                    UserIdResolverManager.parse_resolver_element(element))

        return resolvers

    def set_resolvers(self, linked_resolvers):
        self.raise_if_closed()

        if not linked_resolvers:
            return

        if isinstance(linked_resolvers, str):
            linked_resolvers = (linked_resolvers,)

        resolvers = self.get_resolvers()

        resolver_elements = [
            r.element for r in resolvers if r.name in linked_resolvers]

        # We should have a resolver element for each requested resolver
        assert len(linked_resolvers) == len(resolver_elements)

        for element in resolver_elements:
            # Ctrl-click on the element
            ActionChains(self.driver).key_down(Keys.CONTROL).click(
                element).key_up(Keys.CONTROL).perform()

    def save(self):
        """
        Wait for save button to be clickable, then click save
        """
        button_id = self.edit_save_button_id
        WebDriverWait(self.driver, self.testcase.backend_wait_time).until(
            EC.element_to_be_clickable(
                (By.ID, button_id))
        )

        self.find_by_id(button_id).click()
        self.manage.wait_for_waiting_finished()


class RealmManager(ManageDialog):
    menu_item_id = 'menu_edit_realms'
    body_id = 'dialog_realms'
    new_button_id = 'button_realms_new'
    close_button_id = 'button_realms_close'
    delete_button_id = 'button_realms_delete'

    list_css = "#realm_list > ol"

    alert_box_handler = None

    def __init__(self, manage_ui):
        ManageDialog.__init__(self, manage_ui, 'dialog_realms')
        self.edit_realm_dialog = EditRealmDialog(manage_ui)
        self.alert_box_handler = self.manage.alert_box_handler

    def parse_contents(self):
        """
        Read list of realms from dialog. Called from open dialog hook
        """
        class RealmListEntry:

            def __init__(self, name, element=None):
                self.name = name
                self.element = element

        elements = self.driver.find_elements_by_xpath("//div[@id='realm_list'] | //ol[@id='realms_select']/*")
        self.realms = [RealmListEntry(e.text, e) for e in elements if e.tag_name == 'li']

    def _get_realm_by_name(self, name):
        """
        Get realm given the name
        Return tuple:
         realm name
         type
         name in dialog
        """
        r = [r for r in self.realms if r.name == name]
        assert len(
            r) == 1, "realm name %s not found in current realm list" % (name,)
        realm = r[0]
        return realm

    def select_realm(self, name):
        r = self._get_realm_by_name(name)
        r.element.click()
        self.manage.wait_for_waiting_finished()
        return r

    @property
    def realm_names(self):
        return [r.name for r in self.realms]

    def get_realms_list(self) -> List[str]:
        """
        Get a list of realm names defined using Selenium

        If the dialog is not currently opened, it will be opened
        beforehand
        """

        # Open the dialog and reparse
        self.open()

        return self.realm_names

    def get_realms_via_api(self) -> List[str]:
        """
        Get all realms via API call
        """

        # Get the realms in json format
        realms: List[str] = self.manage.admin_api_call("system/getRealms")
        return realms

    def delete_realm(self, name):
        """Click on realm in list and delete it"""
        driver = self.driver
        delete_confirm_dialog_css = "div[aria-describedby='dialog_realm_ask_delete'] span.ui-dialog-title"

        realm_count = len(self.realms)

        self.select_realm(name)
        self.find_by_id(self.delete_button_id).click()
        self.manage.wait_for_waiting_finished()
        assert self.find_by_css(delete_confirm_dialog_css).text == "Deleting realm"

        t = find_by_css(driver, "#dialog_realm_ask_delete").text
        assert t.startswith(r"Do you want to delete the realm")

        self.find_by_id("button_realm_ask_delete_delete").click()
        self.manage.wait_for_waiting_finished()

        # We should be back to the realm list
        self.raise_if_closed()

        # Reload realms
        self.reparse()
        assert (len(self.realms) == realm_count - 1), (
            'The number of realms shown should decrease after deletion. Before: %s, after:%s'
            % (realm_count, len(self.realms))
        )

    def clear_realms_via_api(self) -> None:
        """
        Delete all realms using the API

        The list of realms is retrieved using the API, and then
        each realm is deleted by realm name.
        """

        realms = self.get_realms_via_api()
        if realms:
            for curr_realm in realms:
                self.manage.admin_api_call("system/delRealm",
                                           {'realm': realms[curr_realm]['realmname']})

    def clear_realms(self):
        """
        Clear all existing realms.

        The clean up will be done via
        the following steps.
        1. Clear all alert boxes in the /manage UI
        2. Open the realm dialog and get all
           realms.
        3. Delete realm x and check alert box.
        4. Repeat 3. #realms times
        """
        # /manage needs to be open for clean up
        # alert box messages.
        self.manage.open_manage()

        # Maybe /manage was already open:
        #
        # Ensure that dialogs are closed.
        # Otherwise we can not clear the old
        # alert boxes. Realm dialog blocks
        # underlying GUI elements.
        self.manage.close_all_dialogs()

        self.alert_box_handler.clear_messages()

        # Open the realms dialog itself
        self.open()

        realms = self.get_realms_list()

        while realms:
            self.delete_realm(realms[0])
            realms = self.get_realms_list()
            if not realms:
                break

        self.close()

    def click_new_realm(self, check_for_no_resolver_alert=False):
        """With the realms dialog open, click the new button"""
        self.find_by_id("button_realms_new").click()

        if check_for_no_resolver_alert:
            self.check_alert("Create UserIdResolver first", click_accept=True)

        # Let dialog open and settle down
        self.edit_realm_dialog.reparse()

        return self.edit_realm_dialog

    def create(self, name, resolvers=None):
        """Create a new realm linked to the given resolver names"""

        self.open()
        self.reparse()
        old_realms = self.get_realms_list()

        dialog = self.click_new_realm()
        dialog.fill_and_save(name, resolvers)

        new_realm_list = self.get_realms_list()

        # Check that realm is now visible
        # by looking for a realm with the given name
        assert [ True for r in new_realm_list if r.startswith(name.lower())]

        if (len(old_realms) != len(new_realm_list) - 1):
            LOGGER.warn("Realm was not sucessfully created. Previous realms:%s, New realms:%s" % (
                [r.name for r in old_realms], [r.name for r in new_realm_list]))
            assert False, "Realm was not sucessfully created"

    def create_via_api(self, name: str, resolvers: Union[List[str], str]) -> None:
        """
        Create a new realm

        @param name - The name of the new realm to create
        @param resolvers - The resolver(s) to place in the realm (type.name)
        """
        if isinstance(resolvers, list):
            resolvers = ",".join(resolvers)

        params = dict(
            realm=name,
            resolvers=resolvers
        )
        self.manage.admin_api_call("system/setRealm", params)

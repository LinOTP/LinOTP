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
"""Contains Realm class"""

import logging

from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys

from helper import find_by_css, fill_form_element
from manage_ui import ManageConfigList
from user_id_resolver import UserIdResolverManager

LOGGER = logging.getLogger(__name__)

class RealmManager(ManageConfigList):
    menu_id = 'menu_edit_realms'
    dialog_id = 'dialog_realms'
    new_button_id = 'button_realms_new'
    close_button_id = 'button_realms_close'
    delete_button_id = 'button_realms_delete'
    edit_save_button_id = 'button_editrealms_save'

    list_css = "#realm_list > ol"

    def __init__(self, testcase):
        ManageConfigList.__init__(self, testcase)

    def _parse_config_list(self):
        class RealmListEntry:
            def __init__(self, name, element=None):
                self.name = name
                self.element = element

        self.check_dialog_is_open()
        elements = self.testcase.find_children_by_id("realm_list", "li")

        self.realms = [RealmListEntry(r.text, r) for r in elements]

    def _get_realm_by_name(self, name):
        """
        Get realm given the name
        Return tuple:
         realm name
         type
         name in dialog
        """
        r = [r for r in self.realms if r.name == name]
        assert len(r)==1, "realm name %s not found in current realm list" % (name,)
        realm = r[0]
        return realm

    def select_realm(self, name):
        r = self._get_realm_by_name(name)
        r.element.click()
        return r

    def get_realms_list(self):
        """
        Get a list of realm names defined

        This assumes that the realms tab is open (using open)
        """
        self._parse_config_list()
        return [r.name for r in self.realms]

    def delete_realm(self, name):
        """Click on realm in list and delete it"""
        driver = self.driver
        delete_confirm_dialog_css = "div[aria-describedby='dialog_realm_ask_delete'] span.ui-dialog-title"
        
        realm_count = len(self.realms)
        
        self.select_realm(name)
        self.find_by_id(self.delete_button_id).click()
        self.testcase.assertEquals("Deleting realm", self.find_by_css(delete_confirm_dialog_css).text)
        
        t = find_by_css(driver, "#dialog_realm_ask_delete").text
        assert t.startswith(r"Do you want to delete the realm")

        self.find_by_id("button_realm_ask_delete_delete").click()
        
        # We should be back to the realm list
        self.check_dialog_is_open()
        
        # Reload realms
        self.open()
        assert (len(self.realms) == realm_count - 1), (
                 'The number of realms shown should decrease after deletion. Before: %s, after:%s' 
                 % (realm_count, len(self.realms))
              )

    def clear_realms(self):
        """Clear all existing realms"""
        self.open()

        while True:
            realms = self.get_realms_list()
            if not realms:
                break
            self.delete_realm(realms[0])

    def click_new_realm(self, check_for_no_resolver_alert=False):
        """With the realms dialog open, click the new button"""
        self.find_by_id("button_realms_new").click()

        if check_for_no_resolver_alert:
            self.check_alert("Create UserIdResolver first", click_accept=True)
        
    def create(self, name, resolvers=None):
        """Create a new realm linked to the given resolver names"""

        self.open()
        old_realms = self.get_realms_list()

        self.click_new_realm()
        realm = Realm(self)
        realm.create(name, resolvers)
        self.find_by_id(self.edit_save_button_id).click()

        new_realms = self.get_realms_list()

        if (len(old_realms) != len(new_realms) - 1):
            LOGGER.warn("Realm was not sucessfully created. Previous realms:%s, New realms:%s" % ([r.name for r in old_realms], [r.name for r in new_realms]))
            assert False, "Realm was not sucessfully created"

        return realm


class Realm(object):
    """Manages a LinOTP Realm"""

    def __init__(self, realm_manager):
        """"""
        self.realm_manager = realm_manager
        self.driver = realm_manager.driver

    def delete(self):
        pass

    def create(self, name, linked_resolvers=None):
        """
        Given a new realm, fill it
        """
        driver = self.driver

        fill_form_element(driver, "realm_name", name)

        if linked_resolvers:
            # Find resolvers list
            resolvers = UserIdResolverManager.parse_resolver_element(self.realm_manager.testcase, "realm_edit_resolver_list")

            resolver_elements = [r.element for r in resolvers if r.name in linked_resolvers]
            ActionChains(driver).key_down(Keys.CONTROL).perform()
            for element in resolver_elements:
                element.click()
            ActionChains(driver).key_up(Keys.CONTROL).perform()

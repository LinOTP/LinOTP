# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
"""Contains UserIdResolver class"""

import re

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC

from helper import find_by_css, find_by_id, fill_element_from_dict
from manage_ui import ManageConfigList

class UserIdResolverManager(ManageConfigList):
    """
    Management dialog for userIdResolvers
    """
    menu_id = 'menu_edit_resolvers'
    dialog_id = 'dialog_resolvers'
    new_button_id = 'button_resolver_new'
    close_button_id = 'button_resolver_close'

    def __init__(self, testcase):
        ManageConfigList.__init__(self, testcase)
        self.resolvers = None

    @staticmethod
    def get_resolver_for_type(resolver_type):
        "Return the derived class for a given resolver type"
        if resolver_type == 'ldapresolver':
            return LdapUserIdResolver
        elif resolver_type == 'sqlresolver':
            return SqlUserIdResolver
        elif resolver_type == 'passwdresolver':
            return PasswdUserIdResolver
        else:
            raise Exception("Unknown UserIdResolver type:%s" % (resolver_type))

    @staticmethod
    def parse_resolver_element(testcase, parent_id):
        # Given an element, retrieve child elements and parse out resolver names
        class ResolverElement:
            def __init__(self, name, resolverType, element=None):
                self.name = name
                self.resolverType = resolverType
                self.element = element
                self.name_in_dialog = "%s [%s]" % (name, resolverType)

        # Retrieve all elements below
        elements = testcase.find_children_by_id(parent_id, "li")
        # If there are resolvers present, there will be an ol element here, otherwise
        # it is empty
        if not len(elements):
            # No resolvers in the list
            return []

        parsed_resolvers = []

        resolver_name_re = re.compile(r'([\w\-]+) \[([\w\-]+)\]$')

        for resolver_element in elements:
            m = resolver_name_re.match(resolver_element.text)
            assert m, 'Error in resolver regexp for "%s"' % (resolver_element,)

            assert(resolver_element.get_attribute("class") in \
                   ('ui-widget-content ui-selectee', 'ui-widget-content ui-selectee ui-selected')), \
                           "Resolver element class unknown"

            parsed_resolvers.append(ResolverElement(m.group(1), m.group(2), resolver_element))  # Form a list of (resolver_name, type) tuples

        return parsed_resolvers

    def _parse_config_list(self):
        """
        Parse the resolver dialog list and build a list of resolvers
        """
        self.check_dialog_is_open()

        # Find resolvers list
        self.resolvers = self.parse_resolver_element(self.testcase, "resolvers_list")

    def _get_resolver_by_name(self, name):
        """
        Get resolver given the name
        Return tuple:
         resolver name
         type
         name in dialog
        """
        r = [r for r in self.resolvers if r.name == name]
        assert len(r) == 1, "Resolver name %s not found in current resolver list" % (name,)
        resolver = r[0]
        return resolver

    def get_defined_resolvers(self):
        """
        Return a list of currently defined resolver names
        """
        self.check_dialog_is_open()
        return [r.name for r in self.resolvers]

    def create_resolver(self, data):
        driver = self.driver
        resolver_type = data['type']

        self.open()
        oldlist = self.get_defined_resolvers()
        oldcount = len(self.get_defined_resolvers())
        self.find_by_id(self.new_button_id).click()
        create_text = "Which type of resolver do you want to create?"
        assert driver.find_element_by_id("dialog_resolver_create").text == create_text

        resolverClass = self.get_resolver_for_type(resolver_type)
        resolver = resolverClass(self)

        assert resolver.savebutton_id, "Resolver save button id is not defined"
        assert resolver.resolver_type_button_id, "Resolver type button id is not defined"

        self.find_by_id(resolver.resolver_type_button_id).click()
        resolver.fill_form(data)

        self.find_by_id(resolver.savebutton_id).click()

        # We should be back to the resolver list
        self.check_dialog_is_open()

        self.open()  # Reload resolvers
        newlist = self.get_defined_resolvers()
        newcount = len(self.get_defined_resolvers())
        if newcount != oldcount + 1:
            print "Could not create resolver!"
            assert newcount == oldcount + 1

        return data['name']

    def select_resolver(self, name):
        resolver = self._get_resolver_by_name(name)
        resolver.element.click()
        return resolver

    def edit_resolver(self, name):
        """
        return resolver, given open dialog
        """
        self.check_dialog_is_open()
        resolver = self.select_resolver(name)
        self.find_by_id("button_resolver_edit").click()
        return resolver

    def delete_resolver(self, name):
        """Click on resolver in list and delete it"""
        driver = self.driver

        resolver_count = len(self.resolvers)

        self.select_resolver(name)
        self.find_by_id("button_resolver_delete").click()
        self.testcase.assertEquals("Deleting resolver", self.find_by_id("ui-id-3").text)

        t = find_by_css(driver, "#dialog_resolver_ask_delete > p").text
        self.testcase.assertEqual(t, r"Do you want to delete the resolver?")

        self.find_by_id("button_resolver_ask_delete_delete").click()

        # We should be back to the resolver list
        self.check_dialog_is_open()

        # Reload resolvers
        self.open()
        assert (len(self.resolvers) == resolver_count - 1), (
                 'The number of resolvers shown should decrease after deletion. Before: %s, after:%s'
                 % (resolver_count, len(self.resolvers))
              )

    def clear_resolvers(self):
        """Clear all existing resolvers"""
        self.open()

        while True:
            resolvers = self.resolvers
            if not resolvers:
                break
            self.delete_resolver(resolvers[0].name)

    def test_connection(self, name, expected_users=None):
        """Test the connection with the corresponding button in the UI.
        Return the number of found users.
        """
        self.open()
        self.edit_resolver(name)
        resolver = self._get_resolver_by_name(name)

        resolver_info = self.get_resolver_for_type(resolver.resolverType)(self)
        testbutton_id = resolver_info.testbutton_id
        cancelbutton_id = resolver_info.editcancel_button_id

        if not testbutton_id:
            # This resolver type does not have a test button (passwd)
            return -1

        self.find_by_id(testbutton_id).click()

        # Wait for alert box to be shown
        alert_id = "alert_box_text"
        WebDriverWait(self.driver, 10).until(
                EC.text_to_be_present_in_element((By.ID, alert_id), "Number of users found"))
        alert_box = self.find_by_id(alert_id)
        alert_box_text = alert_box.text

        m = re.search("Number of users found: (?P<nusers>\d+)", alert_box_text)
        if m is None:
            raise Exception("test_connection for %s failed: %s" % (name, alert_box_text))
        num_found = int(m.group('nusers'))

        if expected_users:
            assert num_found == expected_users, "Expected number of users:%s, found:%s" % (expected_users, num_found)

        # Close the popup
        alert_box.find_element_by_xpath('../..//button').click()

        # Close the resolver edit box
        self.find_by_id(cancelbutton_id).click()

        return num_found

class UserIdResolver:
    """
    Base-Class for creation of UserIdResolvers
    """

    # Ids of various buttons in the UI - will be set during object init
    resolver_type_button_id = None  # The button to click to select the correct resolver type
    savebutton_id = None  # Save button on creation form
    testbutton_id = None  # Test button on edit form, if available
    editcancel_button_id = None  # Cancel button on edit form

    def __init__(self, manage_ui):
        self.manage_ui = manage_ui

        resolver_type = self.resolvertype
        self.resolver_type_button_id = 'button_new_resolver_type_' + resolver_type
        self.savebutton_id = 'button_' + resolver_type + '_resolver_save'
        self.testbutton_id = 'button_test_' + resolver_type
        self.editcancel_button_id = 'button_' + resolver_type + '_resolver_cancel'

class LdapUserIdResolver(UserIdResolver):
    """Creates a LDAP User-Id-Resolver in the LinOTP WebUI"""

    resolvertype = 'ldap'

    def fill_form(self, data):
        driver = self.manage_ui.driver
        preset_ldap = data.get('preset_ldap')

        if preset_ldap:
            find_by_id(driver, "button_preset_ldap").click()
        else:
            find_by_id(driver, "button_preset_ad").click()

        fill_element_from_dict(driver, 'ldap_resolvername', 'name', data)
        fill_element_from_dict(driver, 'ldap_uri', 'uri', data)
        if data['uri'].startswith("ldaps:"):
            fill_element_from_dict(driver, 'ldap_certificate', 'certificate', data)
        fill_element_from_dict(driver, 'ldap_basedn', 'basedn', data)
        fill_element_from_dict(driver, 'ldap_binddn', 'binddn', data)
        fill_element_from_dict(driver, 'ldap_password', 'password', data)

class SqlUserIdResolver(UserIdResolver):
    """Creates a Sql User-Id-Resolver in the LinOTP WebUI"""

    resolvertype = 'sql'

    def __init__(self, manage_ui):
        UserIdResolver.__init__(self, manage_ui)
        self.savebutton_id = 'button_resolver_sql_save'
        self.editcancel_button_id = 'button_resolver_sql_cancel'


    def fill_form(self, data):
        driver = self.manage_ui.driver

        fill_element_from_dict(driver, 'sql_resolvername', 'name', data)

        for field in ('server', 'database', 'user', 'password',
                      'table', 'limit', 'encoding'):
            fill_element_from_dict(driver, 'sql_' + field, field, data)


class PasswdUserIdResolver(UserIdResolver):
    """Creates a file(Passwd) User-Id-Resolver in the LinOTP WebUI"""

    resolvertype = 'passwd'

    def __init__(self, manage_ui):
        UserIdResolver.__init__(self, manage_ui)
        self.savebutton_id = 'button_resolver_file_save'
        self.resolver_type_button_id = 'button_new_resolver_type_file'
        self.testbutton_id = None  # There is no test button for file resolver

    def fill_form(self, data):
        driver = self.manage_ui.driver

        fill_element_from_dict(driver, 'file_resolvername', 'name', data)
        fill_element_from_dict(driver, 'file_filename', 'filename', data)

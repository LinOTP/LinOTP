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
"""Contains UserIdResolver class"""

import logging
import re
from typing import Dict, List

from selenium.webdriver.common.by import By

from .helper import (
    fill_element_from_dict,
    find_by_css,
    find_by_id,
    get_default_app_setting,
)
from .manage_elements import ManageDialog


class UserIdResolverException(Exception):
    pass


class NewResolverDialog(ManageDialog):
    "New resolver dialog"

    def __init__(self, manage_ui):
        super(NewResolverDialog, self).__init__(manage_ui, "dialog_resolver_create")


class UserIdResolverManager(ManageDialog):
    """
    Management dialog for userIdResolvers
    """

    new_button_id = "button_resolver_new"
    close_button_id = "button_resolver_close"
    menu_item_id = "menu_edit_resolvers"

    alert_box_handler = None

    def __init__(self, manage_ui):
        ManageDialog.__init__(self, manage_ui, "dialog_resolvers")
        self.resolvers = None

        self.new_resolvers_dialog = NewResolverDialog(manage_ui)
        self.no_realms_defined_dialog = ManageDialog(manage_ui, "text_no_realm")
        self.alert_box_handler = self.manage.alert_box_handler

    @staticmethod
    def get_resolver_for_type(resolver_type):
        "Return the derived class for a given resolver type"
        if resolver_type == "ldapresolver":
            return LdapUserIdResolver
        elif resolver_type == "sqlresolver":
            return SqlUserIdResolver
        elif resolver_type == "passwdresolver":
            return PasswdUserIdResolver
        else:
            raise Exception("Unknown UserIdResolver type:%s" % (resolver_type))

    @staticmethod
    def parse_resolver_element(line):
        # Given an element, parse out resolver info

        class ResolverElement:
            def __init__(self, name, resolverType, element=None):
                self.name = name
                self.resolverType = resolverType
                self.element = element
                self.name_in_dialog = "%s [%s]" % (name, resolverType)

        res_name = line.find_element(By.CSS_SELECTOR, ".name").text
        res_type = line.find_element(By.CSS_SELECTOR, ".type").text

        assert "ui-selectee" in line.get_attribute("class").split(" "), (
            "Resolver dialog line not selectable"
        )

        return ResolverElement(res_name, res_type, line)

    def parse_contents(self):
        """
        Parse the resolver dialog list and build a list of resolvers
        """
        # Ensure server communication is finished
        self.wait_for_waiting_finished()

        # Ensure resolvers list element is visible
        resolvers_list = self.find_by_id("dialog_resolvers")

        self.resolvers = []

        # The dialog could be empty, so disable implicit wait for the list
        with self.implicit_wait_disabled():
            lines = resolvers_list.find_elements(
                By.CSS_SELECTOR, "#resolvers_list > ol > li"
            )

            for line in lines:
                self.resolvers.append(self.parse_resolver_element(line))

    def _get_resolver_by_name(self, name: str) -> Dict:
        """Get resolver given the name.

        Return tuple:
         resolver name
         type
         name in dialog
        """
        r = [r for r in self.resolvers if r.name == name]
        assert len(r) == 1, "Resolver name %r not found in current resolver list" % name
        resolver = r[0]
        return resolver

    def get_defined_resolvers(self) -> List[str]:
        """Return a list of currently defined resolver names."""
        self.raise_if_closed()
        return [r.name for r in self.resolvers]

    def create_resolver(self, data):
        resolver_type = data["type"]

        self.open()
        oldlist = self.get_defined_resolvers()

        assert data["name"] not in oldlist, (
            "Trying to define a resolver which already exists"
        )

        oldcount = len(oldlist)
        self.find_by_id(self.new_button_id).click()
        self.new_resolvers_dialog.check_text(
            "Which type of resolver do you want to create?"
        )

        resolverClass = self.get_resolver_for_type(resolver_type)
        resolver = resolverClass(self)

        assert resolver.newbutton_id, "Resolver new button id is not defined"
        self.new_resolvers_dialog.click_button(resolver.newbutton_id)
        self.manage.wait_for_waiting_finished()

        formdata = dict(data)

        try:
            del formdata["certificate"]
        except KeyError:
            pass

        # Fill in new resolver form
        resolver.fill_form(formdata)

        self.find_by_id(resolver.savebutton_id).click()
        self.manage.wait_for_waiting_finished()

        # We should be back to the resolver list
        self.raise_if_closed()
        self.reparse()

        newlist = self.get_defined_resolvers()
        newcount = len(newlist)
        if newcount != oldcount + 1:
            logging.error("Could not create resolver! %s", data)
            assert newcount == oldcount + 1

        return data["name"]

    def create_resolver_via_api(self, data: Dict) -> Dict:
        """Create resolver using API call.

        :param data: dictionary of parameters as used in create_resolver
        """

        # Default settings which the UI normally provides
        if data["type"] == "ldapresolver":
            params = {
                "EnforceTLS": "False",
                "only_trusted_certs": "False",
                "TIMEOUT": "5",
                "SIZELIMIT": "500",
                "NOREFERRALS": "True",
            }
            if "preset_ldap" in data:
                # Preset LDAP
                params.update(
                    {
                        "LOGINNAMEATTRIBUTE": "uid",
                        "LDAPSEARCHFILTER": "(uid=*)(objectClass=inetOrgPerson)",
                        "LDAPFILTER": "(&(uid=%s)(objectClass=inetOrgPerson))",
                        "USERINFO": '{ "username": "uid", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }',
                        "UIDTYPE": "entryUUID",
                    }
                )
            elif "preset_ad" in data:
                # Preset Active Directory
                params.update(
                    {
                        "LOGINNAMEATTRIBUTE": "sAMAccountName",
                        "LDAPSEARCHFILTER": "(sAMAccountName=*)(objectClass=user)",
                        "LDAPFILTER": "(&(sAMAccountName=%s)(objectClass=user))",
                        "USERINFO": '{ "username": "sAMAccountName", "phone" : "telephoneNumber", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }',
                        "UIDTYPE": "objectGUID",
                    }
                )
        else:
            params = {}

        params.update(data)

        # Mapping for renaming items which have a different name in the API compared to the
        # manage interface
        name_map = {
            "password": "BINDPW",
            "binddn": "BINDDN",
            "userfilter": "LDAPFILTER",
            "basedn": "LDAPBASE",
            "uri": "LDAPURI",
            "searchfilter": "LDAPSEARCHFILTER",
            "mapping": "USERINFO",
            "loginattr": "LOGINNAMEATTRIBUTE",
            "timeout": "TIMEOUT",
            "sizelimit": "SIZELIMIT",
            "filename": "fileName",
            "expected_users": None,  # Delete
            "preset_ldap": None,
        }

        params = {
            name_map.get(k, k): v
            for k, v in params.items()
            if name_map.get(k, k) is not None
        }

        self.manage.admin_api_call("system/setResolver", params)

    def get_resolver_params_via_api(self, resolver_name: str) -> dict:
        """Request resolver configuration via API.

        Checks that the status was ok and returns the resulting data
        """
        return self.manage.admin_api_call(
            "system/getResolver", {"resolver": resolver_name}
        )

    def close(self):
        super(UserIdResolverManager, self).close()
        if self.no_realms_defined_dialog.is_open():
            self._handle_first_resolver_dialogs()

    def _handle_first_resolver_dialogs(self):
        self.no_realms_defined_dialog.raise_if_closed()
        self.no_realms_defined_dialog.close()

        # The realms dialog now opens - close it
        realms = self.manage.realm_manager
        realms.raise_if_closed()
        realms.close()

    def reload(self):
        # Close and reopen
        self.close_if_open()
        self.open()

    def select_resolver(self, name):
        resolver = self._get_resolver_by_name(name)
        resolver.element.click()
        return resolver

    def edit_resolver(self, name: str):
        """return resolver, given open dialog."""

        self.raise_if_closed()
        resolver = self.select_resolver(name)
        self.find_by_id("button_resolver_edit").click()
        self.wait_for_waiting_finished()
        return resolver

    def delete_resolver(self, name: str):
        """Click on resolver in list and delete it."""
        driver = self.driver

        resolver_count = len(self.resolvers)

        self.select_resolver(name)
        self.find_by_id("button_resolver_delete").click()

        # we wait now that the delete confirmation dialog will appear
        #  remarks: find_by_id() is a utility which verifies that a web
        #           object is displayed and visible

        assert self.find_by_id("dialog_resolver_ask_delete")

        t = find_by_css(driver, "#dialog_resolver_ask_delete > p").text
        assert t == "Do you want to delete the resolver?"

        self.find_by_id("button_resolver_ask_delete_delete").click()

        # We should be back to the resolver list
        self.raise_if_closed()
        self.manage.wait_for_waiting_finished()

        # Resolver name would be e. g. : 'test_realm5 [SE_musicians ]'
        # Capture only resolver name.
        resolver = re.search(r"([^\[(]+)", name).group(1).strip(" ")
        delete_ok = self.alert_box_handler.check_last_message(
            "Resolver deleted successfully: " + resolver
        )
        assert delete_ok, "Error during resolver deletion!"

        # Reload resolvers
        self.parse_contents()

        assert len(self.resolvers) == resolver_count - 1, (
            "The number of resolvers shown should decrease after deletion. Before: %s, after:%s"
            % (resolver_count, len(self.resolvers))
        )

    def delete_resolver_via_api(self, resolver_name: str):
        """Delete resolver by resolver name via api call."""

        resolvers = self.manage.admin_api_call("system/getResolvers")

        if resolver_name not in resolvers:
            raise UserIdResolverException("resolver %r does not found!" % resolver_name)

        self.manage.admin_api_call("system/delResolver", {"resolver": resolver_name})

    def clear_resolvers_via_api(self):
        """Get all resolvers via API call and delete all by resolver name."""
        admin_resolver = get_default_app_setting("ADMIN_RESOLVER_NAME")
        # Get the resolvers in json format
        resolvers = self.manage.admin_api_call("system/getResolvers")
        if resolvers:
            for curr_resolver in resolvers:
                if curr_resolver == admin_resolver:
                    continue
                self.manage.admin_api_call(
                    "system/delResolver",
                    {"resolver": resolvers[curr_resolver]["resolvername"]},
                )

    def clear_resolvers(self):
        """Clear all existing resolvers.

        The clean up will be done via
        the following steps.
        1. Clear all alert boxes in the /manage UI
        2. Open the resolver dialog and get all
           resolvers.
        3. Delete resolver x and check alert box.
        4. Repeat 3. #resolvers times
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

        # The open method 'reparses' the dialog.
        # This reparse sets an internal list
        # with current realms.
        self.open()

        while True:
            # self.resolvers only returns the
            # reparsed list of resolvers - set by self.open.
            # Does not 'parse' the list in the GUI again.
            resolvers = self.resolvers
            if not resolvers:
                break
            self.delete_resolver(resolvers[0].name)

        self.close()

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
            num_found = -1
        else:
            self.find_by_id(testbutton_id).click()

            # Wait for alert box to be shown and then get contents
            alert_box = self.manage.alert_dialog
            alert_box.wait_for_dialog(timeout=20)
            alert_box_text = alert_box.get_text()

            m = re.search(r"Number of users found: (?P<nusers>\d+)", alert_box_text)
            if m is None:
                raise Exception(
                    "test_connection for %s failed: %s" % (name, alert_box_text)
                )
            num_found = int(m.group("nusers"))

            if expected_users:
                assert num_found == expected_users, (
                    "Expected number of users:%s, found:%s"
                    % (
                        expected_users,
                        num_found,
                    )
                )

            # Close the popup
            alert_box.close()

        # Close the resolver edit box
        self.find_by_id(cancelbutton_id).click()

        return num_found


class UserIdResolver:
    """Base-Class for creation of UserIdResolvers."""

    # Ids of various buttons in the UI - will be set during object init
    # The button to click to select the correct resolver type
    newbutton_id = None
    savebutton_id = None  # Save button on creation form
    testbutton_id = None  # Test button on edit form, if available
    editcancel_button_id = None  # Cancel button on edit form

    def __init__(self, manage_ui):
        self.manage_ui = manage_ui


class LdapUserIdResolver(UserIdResolver):
    """Creates a LDAP User-Id-Resolver in the LinOTP WebUI."""

    resolvertype = "ldap"
    newbutton_id = "button_new_resolver_type_ldap"
    savebutton_id = "button_ldap_resolver_save"
    testbutton_id = "button_test_ldap"
    editcancel_button_id = "button_ldap_resolver_cancel"

    def fill_form(self, data):
        driver = self.manage_ui.driver
        preset_ldap = data.get("preset_ldap")

        if preset_ldap:
            find_by_id(driver, "button_preset_ldap").click()
        else:
            find_by_id(driver, "button_preset_ad").click()

        fill_element_from_dict(driver, "ldap_resolvername", "name", data)
        fill_element_from_dict(driver, "ldap_uri", "uri", data)

        enforce_tls = data.get("enforce_tls")

        if enforce_tls is not None:
            assert data["uri"].startswith("ldap:")
            checkbox = find_by_id(driver, "ldap_enforce_tls")
            selected = checkbox.is_selected()
            if (not selected and enforce_tls) or (selected and not enforce_tls):
                checkbox.click()
                assert selected is not checkbox.is_selected()

        only_trusted_certs = data.get("only_trusted_certs")

        if only_trusted_certs:
            assert data["uri"].startswith("ldaps:") or enforce_tls is True
            checkbox = find_by_id(driver, "ldap_only_trusted_certs")
            selected = checkbox.is_selected()
            if (not selected and only_trusted_certs) or (
                selected and not only_trusted_certs
            ):
                checkbox.click()
                assert selected is not checkbox.is_selected()

        fill_element_from_dict(driver, "ldap_basedn", "basedn", data)
        fill_element_from_dict(driver, "ldap_binddn", "binddn", data)
        fill_element_from_dict(driver, "ldap_password", "password", data)

        # Check that some fields have been filled in correctly
        for field in ("uri", "basedn", "binddn", "password"):
            e = driver.find_element(By.ID, "ldap_" + field)
            assert e.get_attribute("value") == data[field]


class SqlUserIdResolver(UserIdResolver):
    """Creates a Sql User-Id-Resolver in the LinOTP WebUI."""

    resolvertype = "sql"
    newbutton_id = "button_new_resolver_type_sql"
    savebutton_id = "button_resolver_sql_save"
    testbutton_id = "button_test_sql"
    editcancel_button_id = "button_resolver_sql_cancel"

    def __init__(self, manage_ui):
        UserIdResolver.__init__(self, manage_ui)
        self.savebutton_id = "button_resolver_sql_save"
        self.editcancel_button_id = "button_resolver_sql_cancel"

    def fill_form(self, data):
        driver = self.manage_ui.driver

        fill_element_from_dict(driver, "sql_resolvername", "name", data)

        if "driver" in data:
            fill_element_from_dict(driver, "sql_driver", "driver", data)

        for field in (
            "server",
            "database",
            "user",
            "password",
            "table",
            "limit",
            "encoding",
        ):
            fill_element_from_dict(driver, "sql_" + field, field, data)


class PasswdUserIdResolver(UserIdResolver):
    """Creates a file(Passwd) User-Id-Resolver in the LinOTP WebUI."""

    resolvertype = "passwd"
    newbutton_id = "button_new_resolver_type_file"
    savebutton_id = "button_resolver_file_save"
    editcancel_button_id = "button_resolver_file_cancel"
    testbutton_id = None

    def __init__(self, manage_ui):
        UserIdResolver.__init__(self, manage_ui)
        self.savebutton_id = "button_resolver_file_save"
        self.resolver_type_button_id = "button_new_resolver_type_file"
        self.testbutton_id = None  # There is no test button for file resolver

    def fill_form(self, data):
        driver = self.manage_ui.driver

        fill_element_from_dict(driver, "file_resolvername", "name", data)
        fill_element_from_dict(driver, "file_filename", "filename", data)

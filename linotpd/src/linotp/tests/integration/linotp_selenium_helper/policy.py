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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""Contains Policy class"""

import time

from manage_elements import ManageTab
from helper import select, fill_form_element


class PolicyManager(ManageTab):
    policy_entries_css_selector = "table#policy_table > tbody > tr"
    policy_delete_button_id = "button_policy_delete"

    TAB_INDEX = 3

    def clear_policies_via_api(self):
        """
        Get all policies via API call
        and delete all by policy name.
        """

        # Get the policies in json format
        json_response = self.manage.admin_api_call("system/getPolicy")

        policies = json_response["result"]["value"]
        if(policies):
            for curr_policy in policies:
                self.manage.admin_api_call("system/delPolicy",
                                           {'name': policies[curr_policy]['name']})

    def clear_policies(self):
        self.open_tab()

        while True:
            policies = self.driver.find_elements_by_css_selector(
                self.policy_entries_css_selector)
            if not policies:
                break
            self.delete_policy(policies[0])
            time.sleep(1)

    def delete_policy(self, p):
        p.click()
        self.find_by_id(self.policy_delete_button_id).click()
        self.wait_for_grid_loading()

    def set_new_policy(self, policy):
        """
        Create a policy using the UI elements
        """
        self.open_tab()
        driver = self.driver

        policy_active_cb = self.find_by_id("policy_active")
        if not policy_active_cb.is_selected():
            policy_active_cb.click()

        fill_form_element(driver, "policy_name", policy.name)

        scope_select = self.find_by_id('policy_scope_combo')
        select(driver, scope_select, policy.scope)

        fill_form_element(driver, "policy_action", policy.action)
        fill_form_element(driver, "policy_realm", policy.realm)
        fill_form_element(driver, "policy_name", policy.name)
        fill_form_element(driver, "policy_user", policy.user)
        self.find_by_id("button_policy_add").click()
        self.wait_for_waiting_finished()


class Policy(object):
    """Creates a LinOTP Policy"""

    def __init__(self, manage_ui, name, scope, action, realm, user="*"):
        """Opens the LinOTP manage interface and creates a Policy"""
        self.name = name
        self.scope = scope
        self.action = action
        self.realm = realm
        self.user = user

        manage_ui.policy_view.set_new_policy(self)

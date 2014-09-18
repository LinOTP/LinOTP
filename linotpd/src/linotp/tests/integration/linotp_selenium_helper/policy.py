# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
"""Contains Policy class"""

from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys
from helper import select

class Policy:
    """Creates a LinOTP Policy"""

    def __init__(self, driver, base_url, name, scope, action, realm):
        """Opens the LinOTP manage interface and creates a Policy"""
        self.name = name
        self.scope = scope
        self.action = action
        self.realm = realm

        driver.get(base_url + "/manage/")
        driver.find_element_by_xpath("//div[@id='tabs']/ul/li[3]/a").click()
        policy_active_cb = driver.find_element_by_id("policy_active")
        if not policy_active_cb.is_selected():
            policy_active_cb.click()
        driver.find_element_by_id("policy_name").clear()
        driver.find_element_by_id("policy_name").send_keys(self.name)
        scope_select = driver.find_element_by_id('policy_scope_combo')
        select(driver, scope_select, self.scope)
        driver.find_element_by_id("policy_action").clear()
        driver.find_element_by_id("policy_action").send_keys(self.action)
        driver.find_element_by_id("policy_realm").clear()
        driver.find_element_by_id("policy_realm").send_keys(self.realm)
        driver.find_element_by_id("button_policy_add").click()


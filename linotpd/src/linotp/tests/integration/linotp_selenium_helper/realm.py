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
"""Contains Realm class"""

from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys
from helper import hover

class Realm:
    """Creates a LinOTP Realm"""

    def __init__(self, name, resolvers):
        """"""
        self.name = name
        self.resolvers = resolvers

    def create(self, driver, base_url):
        """Opens the LinOTP manage interface and the UserIdResolver menu"""
        driver.get(base_url + "/manage/")
        hover(driver, driver.find_element_by_css_selector('#menu > li'))
        driver.find_element_by_id("menu_edit_realms").click()
        driver.find_element_by_id("button_realms_new").click()
        driver.find_element_by_id("realm_name").clear()
        driver.find_element_by_id("realm_name").send_keys(self.name)
        elements = driver.find_elements_by_css_selector(
            "#resolvers_in_realms_select > li"
        )
        resolver_names = [resolver.name_for_list for resolver in self.resolvers]
        ActionChains(driver).key_down(Keys.CONTROL).perform()
        for element in elements:
            if element.text in resolver_names:
                element.click()
        ActionChains(driver).key_up(Keys.CONTROL).perform()
        driver.find_element_by_id("button_editrealms_save").click()
        driver.find_element_by_id("button_realms_close").click()

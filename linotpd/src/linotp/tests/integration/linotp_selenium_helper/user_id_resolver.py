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
import time

from linotp_selenium_helper.helper import (
    find_by_css,
    find_by_id,
    hover,
    )

class UserIdResolver:
    """Base-Class for UserIdResolvers.
    """

    def __init__(self, name, driver, base_url):
        """Initialize values and open the menu in the UI"""
        self.name = name
        self.driver = driver
        self.base_url = base_url
        self.name_for_list = ""
        self.testbutton_id = ""

        #Open the LinOTP manage interface and the UserIdResolver menu
        driver.get(self.base_url + "/manage")
        hover(self.driver, find_by_css(driver, "#menu > li"))
        find_by_id(driver, "menu_edit_resolvers").click()
        find_by_id(driver, "button_resolver_new").click()

    def test_connection(self):
        """Test the connection with the corresponding button in the UI.
        Return the number of found users.
        """
        driver = self.driver
        self.driver.get(self.base_url + "/manage")
        hover(self.driver, find_by_css(self.driver, "#menu > li"))
        find_by_id(driver, "menu_edit_resolvers").click()

        resolvers = self.driver.find_elements_by_css_selector("#resolvers_list > ol > li")

        for resolver in resolvers:
            if resolver.text == self.name_for_list:
                resolver.click()

        self.driver.find_element_by_id("button_resolver_edit").click()
        find_by_id(driver, self.testbutton_id).click()

        time.sleep(2)
        alert_box = find_by_id(driver, "alert_box_text")
        alert_box_text = alert_box.text
        self.driver.find_element_by_xpath("//button[@type='button' and ancestor::div[@aria-describedby='alert_box']]").click()

        m = re.search("Number of users found: (?P<nusers>\d+)", alert_box_text)
        if m is None:
            raise Exception("text_connection for " + self.name + " failed: " + alert_box_text)
        return int(m.group('nusers'))

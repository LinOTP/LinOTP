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
"""Contains LdapUserIdResolver class"""

import time
import re

from user_id_resolver import UserIdResolver
from helper import hover

class LdapUserIdResolver(UserIdResolver):
    """Creates a LDAP User-Id-Resolver in the LinOTP WebUI"""

    def __init__(self, name, driver, base_url,
                 uri="", certificate="", basedn="", binddn="", password="", preset_ldap=True):
        """"""
        UserIdResolver.__init__(self, name, driver, base_url)
        self.uri = uri.lower()
        self.certificate = certificate
        self.basedn = basedn
        self.binddn = binddn
        self.password = password
        self.preset_ldap = preset_ldap
        self.name_for_list = self.name + " [ldapresolver]"
        self.testbutton_id = "button_test_ldap"

        driver.find_element_by_id("button_new_resolver_type_ldap").click()
        if self.preset_ldap:
            driver.find_element_by_id("button_preset_ldap").click()
        else:
            driver.find_element_by_id("button_preset_ad").click()
        driver.find_element_by_id("ldap_resolvername").clear()
        driver.find_element_by_id("ldap_resolvername").send_keys(self.name)
        driver.find_element_by_id("ldap_uri").clear()
        driver.find_element_by_id("ldap_uri").send_keys(self.uri)
        if self.uri.startswith("ldaps"):
            driver.find_element_by_id("ldap_certificate").clear()
            driver.find_element_by_id("ldap_certificate").send_keys(self.certificate)
        driver.find_element_by_id("ldap_basedn").clear()
        driver.find_element_by_id("ldap_basedn").send_keys(self.basedn)
        ldap_binddn = driver.find_element_by_id("ldap_binddn")
        ldap_binddn.clear()
        ldap_binddn.send_keys(self.binddn)
        driver.find_element_by_id("ldap_password").clear()
        driver.find_element_by_id("ldap_password").send_keys(self.password)
        driver.find_element_by_id("button_ldap_resolver_save").click()
        time.sleep(1)
        driver.find_element_by_id("button_resolver_close").click()

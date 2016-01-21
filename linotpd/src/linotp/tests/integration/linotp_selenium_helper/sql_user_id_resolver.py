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
"""Contains SqlIdResolver class"""

import time
import re

from user_id_resolver import UserIdResolver
from helper import hover

class SqlUserIdResolver(UserIdResolver):
    """Creates a Sql User-Id-Resolver in the LinOTP WebUI"""

    def __init__(self, name, driver, base_url,
                 server="", database="", user="", password="", table="", limit="", encoding=""):
        """"""
        UserIdResolver.__init__(self, name, driver, base_url)
        self.server = server
        self.database = database
        self.user = user
        self.password = password
        self.table = table
        self.limit = limit
        self.encoding = encoding
        self.name_for_list = self.name + " [sqlresolver]"
        self.testbutton_id = "button_test_sql"

        driver.find_element_by_id("button_new_resolver_type_sql").click()
        driver.find_element_by_id("sql_resolvername").clear()
        driver.find_element_by_id("sql_resolvername").send_keys(self.name)
        driver.find_element_by_id("sql_server").clear()
        driver.find_element_by_id("sql_server").send_keys(self.server)
        driver.find_element_by_id("sql_database").clear()
        driver.find_element_by_id("sql_database").send_keys(self.database)
        driver.find_element_by_id("sql_user").clear()
        driver.find_element_by_id("sql_user").send_keys(self.user)
        driver.find_element_by_id("sql_password").clear()
        driver.find_element_by_id("sql_password").send_keys(self.password)
        driver.find_element_by_id("sql_table").clear()
        driver.find_element_by_id("sql_table").send_keys(self.table)
        driver.find_element_by_id("sql_limit").clear()
        driver.find_element_by_id("sql_limit").send_keys(self.limit)
        driver.find_element_by_id("sql_encoding").send_keys(self.encoding)
        driver.find_element_by_id("button_resolver_sql_save").click()
        time.sleep(1)
        driver.find_element_by_id("button_resolver_close").click()

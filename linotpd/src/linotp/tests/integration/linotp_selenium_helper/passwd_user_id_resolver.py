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
"""Contains PasswdIdResolver class"""

import time

from user_id_resolver import UserIdResolver

class PasswdUserIdResolver(UserIdResolver):
    """Creates a Passwd User-Id-Resolver in the LinOTP WebUI"""

    def __init__(self, name, driver, base_url, filename="/etc/passwd"):
        """"""
        UserIdResolver.__init__(self, name, driver, base_url)
        self.filename = filename
        self.name_for_list = self.name + " [passwdresolver]"

        driver.find_element_by_id("button_new_resolver_type_file").click()
        driver.find_element_by_id("file_resolvername").clear()
        driver.find_element_by_id("file_resolvername").send_keys(self.name)
        driver.find_element_by_id("file_filename").clear()
        driver.find_element_by_id("file_filename").send_keys(self.filename)
        driver.find_element_by_id("button_resolver_file_save").click()
        time.sleep(1)
        driver.find_element_by_id("button_resolver_close").click()

    def test_connection(self):
        """This overrided UserIdResolver.test_connection() because there is
           currently no way to test the connection for a Passwd Resolver
        """
        raise Exception("PasswdUserIdResolver does not allow testing the connection")

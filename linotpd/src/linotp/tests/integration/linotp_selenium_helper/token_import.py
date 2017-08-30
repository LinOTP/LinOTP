# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""Contains TokenImport class"""

import time

from helper import hover

import tempfile

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC


class TokenImport:
    """TokenImport imports files as Tokens in the LinOTP WebUI"""

    def __init__(self, driver, base_url, file_type, file_content, file_path):
        """Imports the file. Currently the only file_type supported is 'safenet'.
           Either file_content (string) or file_path (string) has to be present.
           If file_content is not None and there is no path then file_content
           is written to a temporary file that is used for the import.
        """
        self.driver = driver
        self.base_url = base_url
        self.file_type = file_type
        self.file_content = file_content
        self.file_path = file_path

        if file_content is not None and file_content != "":
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
            tf.write(file_content)
            tf.close()
            self.file_path = tf.name

        self.driver.get(self.base_url + "/manage")
        import_button = self.driver.find_element_by_xpath(u"//ul[@id='menu']//"
                                                          "li[a[text()='Import Token File']]")
        time.sleep(1)
        hover(self.driver, import_button)
        time.sleep(3)
        if self.file_type == "safenet":
            WebDriverWait(self.driver, 4).until(
                EC.element_to_be_clickable(
                    (By.ID, "menu_load_aladdin_xml_tokenfile"))
            )
            self.driver.find_element_by_id(
                "menu_load_aladdin_xml_tokenfile").click()
        else:
            exit(1)
        self.driver.find_element_by_xpath(
            '//*[@id="load_tokenfile_form_aladdin"]/p[2]/input').send_keys(self.file_path)

        self.driver.find_element_by_id("button_aladdin_load").click()
        self.driver.find_element_by_id("logo").click()

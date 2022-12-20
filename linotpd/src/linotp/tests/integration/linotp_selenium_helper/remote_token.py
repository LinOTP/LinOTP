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
"""Contains RemoteToken class"""

import time
import re

from token import Token
from helper import hover, select

class RemoteToken(Token):
    """Creates a Remote Token in the LinOTP WebUI"""

    def __init__(self, driver, base_url, url, remote_serial, pin, remote_otp_length=6):
        """Currently only supports enrolling remote tokens using the remote
           serial. PIN is always checked locally.
        """
        Token.__init__(self, driver=driver, base_url=base_url)
        select_tag = driver.find_element_by_id("tokentype")
        select(driver, select_element=select_tag, option_text="Remote token")
        driver.find_element_by_id("remote_server").clear()
        driver.find_element_by_id("remote_server").send_keys(url)
        driver.find_element_by_id("remote_otplen").clear()
        driver.find_element_by_id("remote_otplen").send_keys(remote_otp_length)
        driver.find_element_by_id("remote_serial").clear()
        driver.find_element_by_id("remote_serial").send_keys(remote_serial)
        driver.find_element_by_id("remote_pin1").clear()
        driver.find_element_by_id("remote_pin1").send_keys(pin)
        driver.find_element_by_id("remote_pin2").clear()
        driver.find_element_by_id("remote_pin2").send_keys(pin)
        driver.find_element_by_id("button_enroll_enroll").click()
        time.sleep(1)
        info_boxes = driver.find_elements_by_css_selector("#info_box > .info_box > span")
        for box in info_boxes:
            if box.text.startswith("created token with serial"):
                self.serial = box.find_element_by_tag_name("span").text
        if not self.serial or not self.serial.startswith("LSRE"):
            raise Exception("Remote token was not enrolled correctly.")


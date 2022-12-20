# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
"""Contains HotpToken (event-based HMAC token) class"""

from token import Token
from helper import select

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC

class HotpToken(Token):
    """Creates a Hotp Token in the LinOTP WebUI"""

    def __init__(self,
                 driver,
                 base_url,
                 pin="",
                 hmac_key="",
                 generate_key=False,
                 otp_length=6,
                 hash_algorithm="sha1",
                 description="Selenium enrolled"):
        """
        """
        assert bool(hmac_key) ^ bool(generate_key) # xor
        Token.__init__(self, driver=driver, base_url=base_url)
        select_tag = driver.find_element_by_id("tokentype")
        select(driver, select_element=select_tag, option_text="HMAC eventbased")
        wel_hmac_key_rb_gen = driver.find_element_by_id("hmac_key_rb_gen")
        wel_hmac_key_rb_no = driver.find_element_by_id("hmac_key_rb_no")
        wel_hmac_key = driver.find_element_by_id("hmac_key")
        wel_hmac_otplen = driver.find_element_by_id("hmac_otplen")
        wel_hmac_algorithm = driver.find_element_by_id("hmac_algorithm")
        wel_enroll_hmac_desc = driver.find_element_by_id("enroll_hmac_desc")

        if hmac_key:
            wel_hmac_key_rb_no.click()  # select: seed input - no random see
            wel_hmac_key.clear()
            wel_hmac_key.send_keys(hmac_key)
        elif generate_key:
            wel_hmac_key_rb_gen.click()  # select: random seed

        select(driver, select_element=wel_hmac_otplen, option_text=str(otp_length))
        select(driver, select_element=wel_hmac_algorithm, option_text=hash_algorithm)
        driver.find_element_by_id("hmac_pin1").clear()
        driver.find_element_by_id("hmac_pin1").send_keys(pin)
        driver.find_element_by_id("hmac_pin2").clear()
        driver.find_element_by_id("hmac_pin2").send_keys(pin)
        wel_enroll_hmac_desc.send_keys(description)
        driver.find_element_by_id("button_enroll_enroll").click()

        # Wait for API call to complete
        WebDriverWait(self.driver, 10).until_not(
                EC.visibility_of_element_located((By.ID, "do_waiting")))

        info_boxes = driver.find_elements_by_css_selector("#info_box > .info_box > span")
        for box in info_boxes:
            if box.text.startswith("created token with serial"):
                self.serial = box.find_element_by_tag_name("span").text
        if not self.serial or not self.serial.startswith("OATH"):
            raise Exception("HMAC/HOTP token was not enrolled correctly.")


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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""Contains Token class"""

from selenium.webdriver.common.by import By

from .helper import fill_form_element, select
from .manage_elements import ManageDialog


class EnrollTokenDialog(ManageDialog):
    """Testing of functionality to create new tokens via the manage UI"""

    body_id = "dialog_token_enroll"

    def __init__(self, manage_ui):
        """Initialize values and open the menu in the UI"""
        super().__init__(manage_ui)

    def open(self):
        """
        Open the dialog. There is no menu item, so the method is
        overriden with a click on the enroll button
        """
        if not self.is_open():
            self.driver.find_element(By.ID, "button_enroll").click()

        self.wait_for_dialog()

    def select_token_type(self, token_type_text: str):
        self.open()
        select_tag = self.driver.find_element(By.ID, "tokentype")

        select(
            self.driver, select_element=select_tag, option_text=token_type_text
        )

    def complete_enrollment(self, token_prefix: str) -> str:
        """Complete the enrollment process and return token serial number

        Here we click on the enroll button and check that we
        see a notification in the alert info area
        """
        self.click_button("button_enroll_enroll")

        self.manage.wait_for_waiting_finished()

        # We should be back to the main view
        assert not self.is_open()

        # Check the last alert line
        info = self.manage.alert_box_handler.last_line
        if info.type != "info" or not info.text.startswith(
            "created token with serial"
        ):
            raise RuntimeError(
                "Password not correctly created. Message:{}".format(info)
            )

        # Find the token serial number
        token_serial = info.element.find_element(
            By.CSS_SELECTOR, ".text_param1"
        ).text

        if not token_serial or not token_serial.startswith(token_prefix):
            raise Exception("Token was not enrolled correctly.")

        return token_serial

    def create_static_password_token(
        self, password, pin="", description="Selenium enrolled"
    ):
        self.select_token_type("Static Password Token")

        fill_form_element(self.driver, "pw_key", password)
        fill_form_element(self.driver, "enroll_pw_desc", description)
        fill_form_element(self.driver, "pw_pin1", pin)
        fill_form_element(self.driver, "pw_pin2", pin)

        return self.complete_enrollment("KIPW")

    def create_sms_token(
        self, pin="", phone="", description="Selenium enrolled"
    ):
        self.select_token_type("SMS OTP")

        fill_form_element(self.driver, "sms_phone", phone)
        fill_form_element(self.driver, "enroll_sms_desc", description)
        fill_form_element(self.driver, "sms_pin1", pin)
        fill_form_element(self.driver, "sms_pin2", pin)

        return self.complete_enrollment("LSSM")

    def create_hotp_token(
        self,
        pin="",
        hmac_key="",
        generate_key=False,
        otp_length=6,
        hash_algorithm="sha1",
        description="Selenium enrolled",
    ) -> str:
        assert bool(hmac_key) ^ bool(generate_key)  # xor

        self.select_token_type("HMAC eventbased")

        wel_hmac_otplen = self.driver.find_element(By.ID, "hmac_otplen")
        wel_hmac_algorithm = self.driver.find_element(By.ID, "hmac_algorithm")
        wel_enroll_hmac_desc = self.driver.find_element(
            By.ID, "enroll_hmac_desc"
        )

        if hmac_key:
            # select: seed input - no random seed
            self.driver.find_element(By.ID, "hmac_key_rb_no").click()
            fill_form_element(self.driver, "hmac_key", hmac_key)
        elif generate_key:
            # select: random seed
            self.driver.find_element(By.ID, "hmac_key_rb_gen").click()

        select(
            self.driver,
            select_element=wel_hmac_otplen,
            option_text=str(otp_length),
        )
        select(
            self.driver,
            select_element=wel_hmac_algorithm,
            option_text=hash_algorithm,
        )

        fill_form_element(self.driver, "enroll_hmac_desc", description)
        fill_form_element(self.driver, "hmac_pin1", pin)
        fill_form_element(self.driver, "hmac_pin2", pin)

        return self.complete_enrollment("OATH")

    def create_remote_token(
        self, url, remote_serial, pin="", remote_otp_length=6
    ) -> str:
        """Currently only supports enrolling remote tokens using the remote
        serial. PIN is always checked locally.
        """
        self.select_token_type("Remote token")

        fill_form_element(self.driver, "remote_server", url)
        fill_form_element(self.driver, "remote_otplen", remote_otp_length)
        fill_form_element(self.driver, "remote_serial", remote_serial)
        fill_form_element(self.driver, "remote_pin1", pin)
        fill_form_element(self.driver, "remote_pin2", pin)

        return self.complete_enrollment("LSRE")

    def create_email_token(self, email_address, pin="", description="") -> str:
        self.select_token_type("E-mail token")

        fill_form_element(self.driver, "enroll_email_desc", description)
        fill_form_element(self.driver, "email_pin1", pin)
        fill_form_element(self.driver, "email_pin2", pin)
        fill_form_element(self.driver, "email_address", email_address)

        return self.complete_enrollment("LSEM")

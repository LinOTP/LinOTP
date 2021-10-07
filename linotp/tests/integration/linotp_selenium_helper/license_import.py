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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""Contains LicenseImport class"""

from selenium.webdriver.remote.file_detector import LocalFileDetector

from .manage_ui import ManageDialog, ManageUi


class FileUploadException(Exception):
    pass


from contextlib import contextmanager
from tempfile import NamedTemporaryFile


@contextmanager
def LicenseTempFile(content, suffix=".pem"):

    with NamedTemporaryFile(mode="w", suffix=suffix) as temp_file:
        temp_file.write(content)
        temp_file.flush()
        yield temp_file


class LicenseImport(ManageDialog):
    """
    LicenseImport imports files as Tokens in the LinOTP WebUI
    """

    menu_item_id = "menu_help"
    menu_dialogs = ["menu_view_support", "button_support_setup"]

    file_submit = "button_support_set"
    file_input = "license_file"

    def __init__(self, manage_ui: ManageUi):
        """Constructor: create a new LicenseImport class

        remarks:
            using LocalFileDetector: we need to make the file available in
            the selenium docker container. Therefore we require to use the
            LocalFileDetector

        :param manage_ui: The base manage class for the ui elements
        """

        # ----------------------------------------------------------------- --

        # init the parent class

        ManageDialog.__init__(self, manage_ui)

        self.manage_ui = manage_ui

        # ----------------------------------------------------------------- --

        # to support selenium remote we need to setup the LocalFileDetector

        self.driver.file_detector = LocalFileDetector()

        # ----------------------------------------------------------------- --

        # open the manage interface - do the cleanup if something was left open

        self.manage.open_manage()

        self.manage_ui.close_all_dialogs()
        self.manage_ui.close_all_menus()

        # ----------------------------------------------------------------- --

        # navigate from the help menu to the upload dialog

        self.manage.find_by_css(self.manage.MENU_LINOTP_HELP_CSS).click()

        self.driver.find_element_by_id(self.menu_item_id)

        for butten_id in self.menu_dialogs:
            self.driver.find_element_by_id(butten_id).click()

    def import_file(self, file_name: str):
        """imports the a license file

        :remarks:
            On firefox the file input entry is not cleared after a dialog
            re-open. So we have to do this explicitly. Otherwiser the UI ends
            up in an undefined state.

        :param file_name: the file path of provided xml token file
        :raises: FileUploadException if the import failed
        """

        self.manage.alert_box_handler.clear_messages()
        # ----------------------------------------------------------------- --

        # get the file upload input and fill in the upload file name and
        # submit the data

        file_name_lineedit = self.driver.find_element_by_id(self.file_input)
        file_name_lineedit.clear()
        file_name_lineedit.send_keys(file_name)

        self.driver.find_element_by_id(self.file_submit).click()

        # ----------------------------------------------------------------- --

        # submit the upload request and wait till its finished, incl the
        # appearance of the message bar

        self.manage.wait_for_waiting_finished()
        self.manage_ui.close_all_dialogs()
        self.manage.alert_box_handler.wait_until_alert_box_visible()

        # ----------------------------------------------------------------- --

        # lookup if we have success in the message bar
        # - on error raise exception

        assert (
            self.manage.alert_box_handler.amount_of_lines == 1
        ), "Expect exactly one message to be shown"

        last_line = self.manage.alert_box_handler.last_line

        if last_line and last_line.type == "error":
            raise FileUploadException("Import failure: %r" % last_line.text)

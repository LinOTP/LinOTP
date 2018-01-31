# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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

from manage_ui import ManageDialog
from linotp_selenium_helper.manage_ui import MsgType

import tempfile
import os
import subprocess


class TokenImport(ManageDialog):
    """
    TokenImport imports files as Tokens in the LinOTP WebUI
    """

    def __init__(self, manage_ui):
        """
        Base class for all token imports. Derive from this class
        and implement its special behavior. You have to overwrite
        at least the following attributes in your derived class.
            menu_item_id
            body_id
            load_button_id
            file_name_lineedit
        :param manage_ui: The base manage class for the ui elements
        """
        ManageDialog.__init__(self, manage_ui)
        self.menu_css = manage_ui.MENU_LINOTP_IMPORT_TOKEN_CSS

        # Open the appropriate Token import dialog.
        # TopMenu->Import Token File-><safenet/aladdin,oath,yubikey,...>
        self.manage.activate_menu_item(self.menu_css,
                                       self.menu_item_id)

    def do_import(self, file_content=None, file_path=None):
        """
        Imports the file. Currently the only type supported is 'safenet'.
        Either xml_content (string) or file_path (string) has to be present.
        If file_content is not None and there is no path then file_content
        is written to a temporary file that is used for the import.

        :param file_content: xml string with Token import details
        :param file_path: the file path of provided xml token file
        """
        if(not file_content and not file_path):
            raise Exception("""Wrong test implementation. TokenImport.do_import
                            needs file_content or file_path!
                            """)

        if file_content:
            # Create the temp xml file with the given file_content.
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
            tf.write(file_content)
            tf.close()
            self.file_path = tf.name

            # We need to make the created file available in the selenium
            # docker container (Where the browser interaction is done).
            # For this reason we move the temp file in the shared
            # volume (integration tests dir), which is mounted inside
            # the selenium docker container (see docker-compose.yml).
            cwd = os.getcwd()
            subprocess.call(["mv",self.file_path,cwd])

            filename = os.path.basename(self.file_path)
            self.file_path = cwd + "/" + filename
            # Maybe created by root in the docker container.
            subprocess.call(["chmod","a+rw",self.file_path])

        else:
            # Use the provided xml token file.
            self.file_path = file_path

        # On firefox the lineedit is not cleared after dialog re-open
        # So we have to do this explicitly
        # Otherwise the token file to load will be added and
        # LinOTP ends up in an undefined state.
        self.driver.find_element_by_xpath(
            self.file_name_lineedit).clear()

        # Send the filename to the token file lineedit in the dialog.
        self.driver.find_element_by_xpath(
            self.file_name_lineedit).send_keys(self.file_path)

        self.driver.find_element_by_id(self.load_button_id).click()
        self.driver.find_element_by_id("logo").click()

        # delete the temp file if necessary
        if(not file_path):
            # In this case, we did not receive a pre-created file
            # So: delete the temp file.
            try:
                os.unlink(self.file_path)
            except:
                pass

        # Check the alert boxes on the top of the LinOTP UI
        return self.manage.alert_box_handler.check_message(
            'Failed to import token', MsgType.Error)


class TokenImportAladdin(TokenImport):
    """
    Import an Aladdin Token file (xml).
    Create an instance and invoke the 'do_import' method.
    """
    menu_item_id = 'menu_load_aladdin_xml_tokenfile'
    body_id = 'dialog_import_safenet'
    load_button_id = 'button_aladdin_load'
    file_name_lineedit = '//*[@id="load_tokenfile_form_aladdin"]/p[2]/input'

    def __init__(self, manage_ui):
        TokenImport.__init__(self, manage_ui)

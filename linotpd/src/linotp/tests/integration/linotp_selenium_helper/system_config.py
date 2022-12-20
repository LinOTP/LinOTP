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
"""
Contains System Settings Dialog class
"""

import logging

from manage_elements import ManageDialog

LOGGER = logging.getLogger(__name__)


class SystemConfig(ManageDialog):
    """
    Derived from ManageDialog
    """
    menu_item_id = 'menu_system_config'
    body_id = 'dialog_system_settings'
    save_button_id = 'button_system_save'

    """
    Tab 'Settings' UI elements
    """
    tab_settings_split_at = 'sys_splitAtSign'

    def __init__(self, manage_ui):
        """
        @param manage_ui Pass the manage_ui instance
        """

        # Call the default constructor
        ManageDialog.__init__(self,
                              manage_ui,
                              self.body_id)

    def setSplitAt(self, enable):
        """
        Within the 'Settings' Tab, 'Split at @ sign'
        """

        split_at_checkbox = self.find_by_id(self.tab_settings_split_at)

        # Checkbox is not selected/checked but you want to - so check it
        if(not split_at_checkbox.is_selected() and enable):
            split_at_checkbox.click()

        # Checkbox is selected/checked but you want to uncheck - so uncheck it
        if(split_at_checkbox.is_selected() and not enable):
            split_at_checkbox.click()

    def getSplitAt(self):
        """
        Return checkbox value True/False for the 'Settings' Tab,
        'Split at @ sign
        '"""

        split_at_checkbox = self.find_by_id(self.tab_settings_split_at)
        return split_at_checkbox.is_selected()

    def save(self):
        """
        Save the system configuration changes
        """

        self.find_by_id(self.save_button_id).click()

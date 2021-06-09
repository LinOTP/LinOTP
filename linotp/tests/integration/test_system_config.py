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
"""Selenium Test for changing the system configuration """

import pytest

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.manage_ui import MsgType


class TestSystemConfig(TestCase):

    system_config = None
    alert_box_handler = None

    @pytest.fixture(autouse=True)
    def setUp(self):
        self.system_config = self.manage_ui.system_config
        self.alert_box_handler = self.manage_ui.alert_box_handler

    def test_split_at(self):

        self.system_config.open()

        # Set the opposite value of current 'split at' - force change
        split_at_pre_state = self.system_config.getSplitAt()
        if split_at_pre_state:
            self.system_config.setSplitAt(False)
        else:
            self.system_config.setSplitAt(True)

        self.system_config.save()

        error_raised = self.alert_box_handler.check_message(
            "Error saving system configuration", MsgType.Error
        )
        # There shouldnt raise an error
        assert (
            not error_raised
        ), "Error during system configuration save procedure!"

        self.alert_box_handler.clear_messages()
        self.system_config.open()
        # After the re-open and the previous save, the checkbox should be
        # True/False (opposite of split_at_pre_state)
        split_at_state = self.system_config.getSplitAt()
        if split_at_pre_state:
            assert (
                not split_at_state
            ), "'False' for 'SplitAt@' checkbox not saved!"
        else:
            assert split_at_state, "'True' for 'SplitAt@' checkbox not saved!"

        # Test the other way around (set state for checkbox, set at test start)
        self.system_config.setSplitAt(split_at_pre_state)
        self.system_config.save()

        # There shouldnt raise an error
        error_raised = self.alert_box_handler.check_message(
            "Error saving system configuration", MsgType.Error
        )
        assert (
            not error_raised
        ), "Error during system configuration save procedure!"

        # Check whether the checkbox is enabled after saving and re-open
        self.system_config.open()
        split_at_state = self.system_config.getSplitAt()
        if split_at_pre_state is True:
            assert split_at_state, "'True' for 'SplitAt@' checkbox not saved!"
        else:
            assert (
                not split_at_state
            ), "'False' for 'SplitAt@' checkbox not saved!"

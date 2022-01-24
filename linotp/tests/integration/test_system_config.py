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

import time
from datetime import datetime, timedelta

import pytest

from linotp.lib.type_utils import DEFAULT_TIMEFORMAT
from linotp_selenium_helper import TestCase, helper
from linotp_selenium_helper.manage_ui import MsgType
from linotp_selenium_helper.validate import Validate


class TestSystemConfig(TestCase):

    system_config = None
    alert_box_handler = None

    @pytest.fixture(autouse=True)
    def setUp(self):
        self.system_config = self.manage_ui.system_config
        self.alert_box_handler = self.manage_ui.alert_box_handler

    def test_split_at(self):
        """
        Test that split_at option is saved and retrieved correctly
        """
        with self.system_config:
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
        with self.system_config:
            # After the re-open and the previous save, the checkbox should be
            # True/False (opposite of split_at_pre_state)
            split_at_state = self.system_config.getSplitAt()
            if split_at_pre_state:
                assert (
                    not split_at_state
                ), "'False' for 'SplitAt@' checkbox not saved!"
            else:
                assert (
                    split_at_state
                ), "'True' for 'SplitAt@' checkbox not saved!"

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
        with self.system_config:
            split_at_state = self.system_config.getSplitAt()
            if split_at_pre_state is True:
                assert (
                    split_at_state
                ), "'True' for 'SplitAt@' checkbox not saved!"
            else:
                assert (
                    not split_at_state
                ), "'False' for 'SplitAt@' checkbox not saved!"

    def test_usage_timestamp(self):
        """Test the option for storing the last Authentication info of Tokens"""

        # note: how should we add the initial users before this test?
        # open config box and set the option
        pasw = "12345"
        otp = "1234"

        with self.system_config:
            self.system_config.set_last_access_option(True)
            self.system_config.save()

        self.manage_ui.token_view.clear_tokens_via_api()
        tokenserial = self.manage_ui.token_enroll.create_static_password_token(
            pasw
        )
        # assign token
        username = "susi"
        self.manage_ui.user_view.select_user(username)
        self.manage_ui.token_view.assign_token(tokenserial, otp)

        validate = Validate(
            self.http_protocol,
            self.http_host,
            self.http_port,
            self.http_username,
            self.http_password,
        )

        # 1-successful authentication
        tvar = timedelta(seconds=2)
        validation_result = validate.validate(username, otp + pasw)
        assert (
            validation_result[0] == True
        ), "unexpected behavior: validation of user with password failed"
        validationtime = datetime.now()
        tokeninfo = self.manage_ui.token_view.get_token_info(tokenserial)
        last_authentication = datetime.strptime(
            tokeninfo["LinOtp.LastAuthSuccess"], DEFAULT_TIMEFORMAT
        )
        last_authentication_try = datetime.strptime(
            tokeninfo["LinOtp.LastAuthMatch"], DEFAULT_TIMEFORMAT
        )
        assert last_authentication <= validationtime + tvar
        assert last_authentication_try <= validationtime + tvar

        # 2-failing authentication
        time.sleep(tvar.seconds)
        validation_result = validate.validate(username, "wrong pass")

        assert (
            validation_result[0] == False
        ), "unexpected behavior: critical! validation of user should have failed here"

        validationtime = datetime.now()
        tokeninfo = self.manage_ui.token_view.get_token_info(tokenserial)
        last_authentication = datetime.strptime(
            tokeninfo["LinOtp.LastAuthSuccess"], DEFAULT_TIMEFORMAT
        )
        last_authentication_try = datetime.strptime(
            tokeninfo["LinOtp.LastAuthMatch"], DEFAULT_TIMEFORMAT
        )

        assert last_authentication < validationtime
        assert last_authentication_try <= validationtime + tvar

# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
"""LinOTP Selenium Test for token view automation"""

import pytest


class TestTokenView:
    @pytest.fixture(autouse=True)
    def setUp(self, testcase):
        self.testcase = testcase

        self.manage_ui = self.testcase.manage_ui
        self.token_view = self.testcase.manage_ui.token_view
        self.token_enroll = self.testcase.manage_ui.token_enroll

    def test_01_open_view(self):
        self.token_view.open()

    def test_02_clear_tokens(self):
        self.token_view.delete_all_tokens()

    def test_03_create_static_password_token(self):
        self.token_enroll.create_static_password_token("testPassword")

    def test_04_create_and_clear_tokens(self):
        v = self.token_view
        v.delete_all_tokens()
        # Create 10 tokens so UI delays are introduced while fetching tokens
        for _ in range(0, 10):
            self.token_enroll.create_static_password_token("testPassword")
        v.delete_all_tokens()


class TestTokenViewOperations:
    @pytest.fixture(autouse=True)
    def setUp(self, testcase):
        self.testcase = testcase

        self.testcase.manage_ui.token_view.delete_all_tokens()
        self.token_serial = (
            self.testcase.manage_ui.token_enroll.create_static_password_token(
                "testPassword"
            )
        )

    def test_01_select(self):
        self.testcase.manage_ui.token_view.select_token(self.token_serial)

    def test_02_delete(self):
        self.testcase.manage_ui.token_view.delete_token(self.token_serial)

    def test_03_info(self):
        info = self.testcase.manage_ui.token_view.get_token_info(self.token_serial)
        assert info["LinOtp.TokenSerialnumber"] == self.token_serial, (
            "Displayed token serial should be same as created serial number"
        )

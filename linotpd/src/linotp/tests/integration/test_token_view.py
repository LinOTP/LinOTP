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
"""LinOTP Selenium Test for token view automation """

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.token_view import TokenView
from linotp_selenium_helper.spass_token import SpassToken


def _create_test_token(driver, base_url):
    s = SpassToken(driver, base_url, pin="1234")
    return s


class TestTokenView(TestCase):

    def setUp(self):
        super(TestTokenView, self).setUp()
        self.token_view = self.manage_ui.token_view

    def test_01_open_view(self):
        self.token_view.open()

    def test_02_clear_tokens(self):
        self.token_view.delete_all_tokens()

    def test_03_create_token(self):
        v = self.token_view
        v.open()
        _create_test_token(self.driver, self.base_url)

    def test_04_create_and_clear_tokens(self):
        v = self.token_view
        v.delete_all_tokens()
        # Create 10 tokens so UI delays are introduced while fetching tokens
        for _ in xrange(0, 10):
            _create_test_token(self.driver, self.base_url)
        v.delete_all_tokens()


class TestTokenViewOperations(TestCase):

    def setUp(self):
        super(TestTokenViewOperations, self).setUp()
        self.token_view = self.manage_ui.token_view
        self.token_view.delete_all_tokens()
        self.token_serial = _create_test_token(
            self.driver, self.base_url).serial

    def test_01_select(self):
        self.token_view.select_token(self.token_serial)

    def test_02_delete(self):
        self.token_view.delete_token(self.token_serial)

    def test_03_info(self):
        info = self.token_view.get_token_info(self.token_serial)
        self.assertEqual(info['LinOtp.TokenSerialnumber'], self.token_serial,
                         "Displayed token serial should be same as created serial number")

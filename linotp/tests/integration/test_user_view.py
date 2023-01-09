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


import integration_data as data
import pytest

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.manage_ui import ManageUi
from linotp_selenium_helper.user_view import UserView


class TestAuth:
    """
    TestCase class that tests the auth/index forms
    """

    @pytest.fixture(autouse=True)
    def setUp(self, testcase):
        self.testcase = testcase
        self.realm_name = "se_test_auth"
        self.testcase.reset_resolvers_and_realms(
            data.sepasswd_resolver, self.realm_name
        )

    def test_user_filter(self):

        m = self.testcase.manage_ui
        m.open_manage()
        user_view = UserView(m, self.realm_name)
        username = "susi"
        user_view.select_user(username)

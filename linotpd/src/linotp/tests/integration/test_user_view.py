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


import time

from linotp_selenium_helper import TestCase
from linotp_selenium_helper.hotp_token import HotpToken
from linotp_selenium_helper.manage_ui import ManageUi
from linotp_selenium_helper.user_view import UserView

import integration_data as data

class TestAuth(TestCase):
    """
    TestCase class that tests the auth/index forms
    """

    def setUp(self):
        TestCase.setUp(self)
        self.realm_name = "se_test_auth"
        self.reset_resolvers_and_realms(data.sepasswd_resolver, self.realm_name)

    def test_user_filter(self):
        m = ManageUi(self)
        m.open_manage()
        user_view = UserView(m, self.realm_name)
        username = "susi"
        user_view.select_user(username)

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


import unittest

from linotp.lib.user import User


class TestUserClass(unittest.TestCase):

    def test_simple_user_class_comparisson(self):
        """ test that no sensitive data got logged """

        u1 = User()
        u2 = User()
        assert u1 == u2

        u3 = User (login='heinz')
        assert u1 != u3

    def test_realm_user_class_comparisson(self):
        """ test that no sensitive data got logged """

        u1 = User(login='emil', realm='heydo')
        u2 = User(login='emil', realm='heydo')
        assert u1 == u2

        u3 = User (login='emil')
        assert u1 != u3

    def test_user_nonzero(self):
        """ test that no sensitive data got logged """

        # check that u1 is zero: either None or empty

        u1 = User()
        if u1:
            assert True == False

        # check that u2 is zero: checks if the user has a login

        u2 = User(realm='heydo')
        if u2:
            assert True == False

        # check that u3 is not zero: neither None nor empty

        u3 = User(login='heinz')
        if not u3:
            assert True == False


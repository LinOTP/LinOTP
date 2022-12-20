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

import unittest

from linotp.lib.crypto import libcrypt_password
from linotp.lib.tools.set_password import SetPasswordHandler
from linotp.lib.tools.set_password import DataBaseContext


class TestSetPasswordTool(unittest.TestCase):

    def setUp(self):

        unittest.TestCase.setUp(self)

        self.db_context = DataBaseContext('sqlite:///:memory:')

    def check_for_exeption(self, pw_handler,
                           username, old_password, new_password,
                           exception, message):
        """
        check that an exception with the message will be raised
        """
        with self.assertRaises(exception) as exx:
            pw_handler.set_password(username,
                                    old_password,
                                    new_password)

        self.assertTrue(message in exx.exception.message)

    def test_set_password(self):

        # first create the user table
        SetPasswordHandler.create_table(self.db_context)

        admin_user = 'admin'
        admin_pw = libcrypt_password('admin_password')

        # setup the inital user and it's password

        SetPasswordHandler.create_admin_user(self.db_context,
                                             username=admin_user,
                                             crypted_password=admin_pw)

        # run a valid change of the admin password

        pw_handler = SetPasswordHandler(self.db_context)
        pw_handler.set_password(admin_user,
                                'admin_password',
                                'new_password')

        # test for non existing user

        msg = "no user 'username' found!"
        self.check_for_exeption(pw_handler,
                                'username', 'old_password', 'new_password',
                                Exception, message=msg)

        # test for old password mismatch

        msg = "old password missmatch!"
        self.check_for_exeption(pw_handler,
                                'admin', 'old_password', 'new_password',
                                Exception, message=msg)

        # test for invalid new password using different data types
        msg = "must be string, not None"
        self.check_for_exeption(pw_handler,
                                'admin', 'new_password', None,
                                Exception, message=msg)

        msg = "must be string, not int"
        self.check_for_exeption(pw_handler,
                                'admin', 'new_password', 123456,
                                Exception, message=msg)

        msg = "must be string, not float"
        self.check_for_exeption(pw_handler,
                                'admin', 'new_password', 1234.56,
                                Exception, message=msg)

        msg = "must be string, not DataBaseContext"
        self.check_for_exeption(pw_handler,
                                'admin', 'new_password', self.db_context,
                                Exception, message=msg)

        # make sure that the password did not change in between and the
        # password could be set correctly

        pw_handler.set_password(admin_user,
                                'new_password',
                                'admin_password')

        return

    def test_set_password_with_no_table(self):
        """
            try to set password though no table exists
        """

        pw_handler = SetPasswordHandler(self.db_context)

        msg = "no such table: admin_users"
        self.check_for_exeption(pw_handler,
                                'admin', 'admin_password', 'new_password',
                                Exception, message=msg)

        return

    def test_set_inital_admin_twice(self):

        # first create the user table
        SetPasswordHandler.create_table(self.db_context)

        admin_user = 'admin'
        admin_pw = libcrypt_password('admin_password')

        # setup the inital user and it's password

        SetPasswordHandler.create_admin_user(self.db_context,
                                             username=admin_user,
                                             crypted_password=admin_pw)

        admin_user = 'admin'
        admin_pw = libcrypt_password('password_of_admin')

        # setup the inital user and try to set it's password a second time
        # - this will fail as the user could only be set once

        SetPasswordHandler.create_admin_user(self.db_context,
                                             username=admin_user,
                                             crypted_password=admin_pw)

        pw_handler = SetPasswordHandler(self.db_context)

        msg = "old password missmatch!"
        self.check_for_exeption(pw_handler,
                                'admin', 'password_of_admin', 'new_password',
                                Exception, message=msg)

        pw_handler.set_password('admin', 'admin_password', 'new_password')

        return

# eof #

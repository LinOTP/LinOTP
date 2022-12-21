#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
#
#    This file is part of LinOTP userid resolvers.
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

from unittest import TestCase

from linotp.useridresolver.UserIdResolver import ResolverLoadConfigError
from linotp.useridresolver.PasswdIdResolver import IdResolver as PasswdResolver


class TestPasswdResolver(TestCase):

    y = None

    def setUp(self):
        '''
        initalize the config into a shared memory file
        '''

        pw_file = "/dev/shm/test_users.txt"
        content = '''user1:0DM4AJtW/rTYY:10:10:User Eins:Irgendwas:Nochmal
user2:.4UO1mxvTmdM6:11:11:User Zwei:Irgendwas:Nochmal
'''
        f = open(pw_file, 'w')
        f.write(content)
        f.close()

        pw_config = {'linotp.passwdresolver.fileName.my': pw_file}
        self.y = PasswdResolver()
        self.y.loadConfig(pw_config, 'my')

    def test_resolver_fail(self):
        '''
        Test to use a file, that does not exist
        '''
        pw_config = {'linotp.passwdresolver.fileName.my':
                     '/dev/shm/this_file_does_not_exist'}

        msg = ("File '/dev/shm/this_file_does_not_exist' does not "
               "exist or is not accesible")

        with self.assertRaisesRegexp(ResolverLoadConfigError, msg):

            self.y = PasswdResolver()
            self.y.loadConfig(pw_config, "my")

    def test_getUserId(self):
        '''test the existance of the user1 and user2'''
        res = self.y.getUserId("user1")
        self.assertTrue(res == "10")

        self.assertTrue(self.y.getUserInfo(res).get("surname") == "Eins")

        res = self.y.getUserId("user2")
        self.assertTrue(res == "11")

        self.assertTrue(self.y.getUserInfo(res).get("surname") == "Zwei")

    def test_checkpass(self):
        '''
        Check the password of user1 and user 2
        '''
        self.assertTrue(self.y.checkPass(self.y.getUserId("user1"), "pwU1"))
        self.assertTrue(self.y.checkPass(self.y.getUserId("user2"), "pwU2"))

    def test_getUserList(self):
        '''
        testing the userlist
        '''
        # all users are two users
        user_list = self.y.getUserList({})
        self.assertTrue(len(user_list) == 2)

        # there is only one user that ends with '1'
        user_list = self.y.getUserList({"username": "*1"})
        self.assertTrue(len(user_list) == 1)

    def test_getUsername(self):
        '''
        testing getting the username
        '''
        self.assertTrue(self.y.getUsername("10"))
        self.assertTrue(self.y.getUsername("11"))
        self.assertFalse(self.y.getUsername("9"))

# eof #

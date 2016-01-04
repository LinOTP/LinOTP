#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

import unittest
from unittest import TestCase

import useridresolver
from useridresolver import UserIdResolver


class TestResolve(TestCase):

    y = None

    def setUp(self):
        '''
        you can add testusers like this
            python tools/create-pwidresolver-user.py -u user1 -i 10  -p pwU1
        '''
        file = "/dev/shm/test_users.txt"
        content = '''user1:0DM4AJtW/rTYY:10:10:User Eins:Irgendwas:Nochmal
user2:.4UO1mxvTmdM6:11:11:User Zwei:Irgendwas:Nochmal
'''
        f = open(file, 'w')
        f.write(content)
        f.close()

        self.y = UserIdResolver.getResolverClass("PasswdIdResolver", "IdResolver")()
        self.y.loadConfig({ 'linotp.passwdresolver.fileName' : file }, "")

    def test_resolver_fail(self):
        '''
        Test to use a file, that does not exist
        '''
        with self.assertRaisesRegexp(IOError, "No such file or directory: '/dev/shm/this_file_does_not_exist'"):
            self.y = UserIdResolver.getResolverClass("PasswdIdResolver", "IdResolver")()
            self.y.loadConfig({ 'linotp.passwdresolver.fileName' : '/dev/shm/this_file_does_not_exist' }, "")


    def test_getUserId(self):
        '''test the existance of the user1 and user2'''
        res = self.y.getUserId("user1")
        print "uid (user1): ", res
        assert res == "10"

        assert self.y.getUserInfo(res).get("surname") == "Eins"

        res = self.y.getUserId("user2")
        print "uid (user2): ", res
        assert res == "11"

        assert self.y.getUserInfo(res).get("surname") == "Zwei"

    def test_checkpass(self):
        '''
        Check the password of user1 and user 2
        '''
        assert self.y.checkPass(self.y.getUserId("user1"), "pwU1")
        assert self.y.checkPass(self.y.getUserId("user2"), "pwU2")

    def test_getUserList(self):
        '''
        testing the userlist
        '''
        # all users are two users
        list = self.y.getUserList({})
        print list
        assert len(list) == 2

        # there is only one user that ends with '1'
        list = self.y.getUserList({"username" : "*1"})
        print list
        assert len(list) == 1

    def test_getUsername(self):
        '''
        testing getting the username
        '''
        assert self.y.getUsername("10")
        assert self.y.getUsername("11")
        assert not self.y.getUsername("9")




def main():
    unittest.main()

if __name__ == '__main__':
    main()

# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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


"""
"""


import os
import logging

from useridresolver.UserIdResolver import getResolverClass

from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestPasswdController(TestController):
    '''
    '''
    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()
        self.serials = []

    def tearDown(self):
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def test_resolver(self):
        '''
        Testing PasswdIdResolver
        '''
        y = getResolverClass("PasswdIdResolver", "IdResolver")()
        y.loadConfig({'fileName':
                      os.path.join(self.fixture_path, 'my-passwd')}, "")

        userlist = y.getUserList({'username': '*',
                                  "userid": "= 1000"})

        self.assertTrue(userlist[0].get('username') == "heinz", userlist)

        loginId = y.getUserId("heinz")
        self.assertTrue(loginId == '1000', loginId)

        ret = y.getUserInfo(loginId)
        self.assertTrue(ret.get('username') == "heinz", ret)

        username_exists = y.getUsername('1000')
        msg = "Username exists: %r" % username_exists
        self.assertTrue(username_exists, msg)

    def test_no_file(self):
        '''
        Testing PasswdIdResolver without file
        '''
        y = getResolverClass("PasswdIdResolver", "IdResolver")()
        y.loadFile()

        userlist = y.getUserList({'username': '*',
                                  "userid": "= 0"})
        self.assertTrue(userlist[0].get('username') == "root", userlist)

        loginId = y.getUserId("root")
        self.assertTrue(loginId == '0', loginId)

        ret = y.getUserInfo(loginId)
        self.assertTrue(ret.get('username') == "root", ret)

    def test_checkpass_shadow(self):
        '''
        Testing checkpass with PasswdIdResolver with a shadow passwd file
        '''
        y = getResolverClass("PasswdIdResolver", "IdResolver")()
        y.loadConfig({'fileName':
                      os.path.join(self.fixture_path, 'my-passwd')}, "")

        success = False
        try:
            y.checkPass('1000', "geheim")
        except NotImplementedError:
            success = True

        self.assertTrue(success)

    def test_checkpass(self):
        '''
        Testing checkpass
        '''
        y = getResolverClass("PasswdIdResolver", "IdResolver")()
        y.loadConfig({'fileName':
                      os.path.join(self.fixture_path, 'my-pass2')}, "")

        res = y.checkPass('2001', "geheim")
        msg = "result %r" % res
        self.assertTrue(res, msg)

        res = y.checkPass('2001', "wrongPW")
        msg = "result %r" % res
        self.assertTrue(res is False, msg)

    def test_searchfields(self):
        '''
        Testing getSearchfields
        '''
        y = getResolverClass("PasswdIdResolver", "IdResolver")()
        y.loadConfig({'fileName':
                      os.path.join(self.fixture_path, 'my-pass2')}, "")

        s = y.getSearchFields()
        self.assertTrue(s, s)

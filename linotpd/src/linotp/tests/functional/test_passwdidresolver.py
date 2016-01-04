# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#


"""
"""



from useridresolver.UserIdResolver import getResolverClass

from linotp.tests import TestController


import os
import logging
log = logging.getLogger(__name__)


class TestPasswdController(TestController):
    '''
    '''
    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()
        self.serials = []
        self.fixture_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'fixtures',
            )

    def tearDown(self):
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def test_resolver(self):
        '''
        Testing PasswdIdResolver
        '''
        y = getResolverClass("PasswdIdResolver", "IdResolver")()
        y.loadConfig({ 'linotp.passwdresolver.fileName' : os.path.join(self.fixture_path, 'my-passwd') }, "")

        userlist = y.getUserList({'username':'*', "userid":"= 1000"})
        print userlist
        assert userlist[0].get('username') == "heinz"


        loginId = y.getUserId("heinz")
        print loginId
        assert loginId == '1000'

        ret = y.getUserInfo(loginId)
        print ret
        assert ret.get('username') == "heinz"

        username_exists = y.getUsername('1000')
        print "Username exists: %r" % username_exists
        assert username_exists

    def test_no_file(self):
        '''
        Testing PasswdIdResolver without file
        '''
        y = getResolverClass("PasswdIdResolver", "IdResolver")()
        y.loadFile()

        userlist = y.getUserList({'username':'*', "userid":"= 0"})
        print userlist
        assert userlist[0].get('username') == "root"


        loginId = y.getUserId("root")
        print loginId
        assert loginId == '0'

        ret = y.getUserInfo(loginId)
        print ret
        assert ret.get('username') == "root"

    def test_checkpass_shadow(self):
        '''
        Testing checkpass with PasswdIdResolver with a shadow passwd file
        '''
        y = getResolverClass("PasswdIdResolver", "IdResolver")()
        y.loadConfig({ 'linotp.passwdresolver.fileName' : os.path.join(self.fixture_path, 'my-passwd') }, "")

        success = False
        try:
            y.checkPass('1000', "geheim")
        except NotImplementedError:
            success = True

        assert success

    def test_checkpass(self):
        '''
        Testing checkpass
        '''
        y = getResolverClass("PasswdIdResolver", "IdResolver")()
        y.loadConfig({ 'linotp.passwdresolver.fileName' : os.path.join(self.fixture_path, 'my-pass2') }, "")

        res = y.checkPass('2001', "geheim")
        print "result %r" % res
        assert res

        res = y.checkPass('2001', "wrongPW")
        print "result %r" % res
        assert res == False

    def test_searchfields(self):
        '''
        Testing getSearchfields
        '''
        y = getResolverClass("PasswdIdResolver", "IdResolver")()
        y.loadConfig({ 'linotp.passwdresolver.fileName' : os.path.join(self.fixture_path, 'my-pass2') }, "")

        s = y.getSearchFields()
        print s
        assert s


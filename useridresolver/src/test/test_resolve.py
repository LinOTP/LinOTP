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

import sys
import os

import json
import unittest
from unittest import TestCase
import subprocess

from os import getcwd
from useridresolver.UserIdResolver import UserIdResolver
from useridresolver.UserIdResolver import getResolverClass



class TestResolve(TestCase):

    y = None
    z = None
    proc = None
    ldap_y = None

    def setUp(self):
        '''
        This is run before each test. Read configuration from the given JSON file.
        '''
        with open(sys.argv[1], 'r') as f:
            cfgdata = json.load(f)

        config = cfgdata['config']
        config2 = config.copy()
        # A config with a differing Map (mapping string user IDs, not numerical user IDs)
        config2['linotp.sqlresolver.Map'] = cfgdata['config2_map']
        # Another config with a where clause (otherwise equals `config`)
        config3 = config.copy()
        config3['linotp.sqlresolver.Where'] = cfgdata['config3_where']

        self.y = getResolverClass("useridresolver.SQLIdResolver", "IdResolver")()
        self.y.loadConfig(config, "")
        self.z = getResolverClass("useridresolver.SQLIdResolver", "IdResolver")()
        self.z.loadConfig(config2, "")
        self.w = getResolverClass("useridresolver.SQLIdResolver", "IdResolver")()
        self.w.loadConfig(config3, "")

        self.ldap_y = getResolverClass("useridresolver.LDAPIdResolver", "IdResolver")()

        self.ldap_y.loadConfig({ 'linotp.ldapresolver.LDAPFILTER' : '(&(cn=%s))',
                                  'linotp.ldapresolver.LDAPSEARCHFILTER' : '(cn=*)',
                                  'linotp.ldapresolver.LOGINNAMEATTRIBUTE' : 'cn',
                                  'linotp.ldapresolver.USERINFO' : '{"username":"cn", "description":"", \
                                                "phone" : "telephoneNumber",\
                                                "groups" : "o",\
                                                "mobile" : "mobile", \
                                                "email" : "email",\
                                                "surname" : "sn",\
                                                "givenname" : "givenName",\
                                                "gender" : "" } ',
                                    'linotp.ldapresolver.LDAPURI' : 'ldap://localhost:1389',
                                    'linotp.ldapresolver.LDAPBASE'    : 'o=linotp,c=org',
                                    'linotp.ldapresolver.BINDDN'  : '',
                                    'linotp.ldapresolver.BINDPW'  : '',
                                    'linotp.ldapresolver.TIMEOUT' : '5',
                                    'linotp.ldapresolver.SIZELIMIT' : '10',
                                    })

    def getUserList(self, obj, arg):
        '''
            call obj.getUserList(), but check that we have no errors before returning.
        '''
        res = obj.getUserList(arg)
        for item in res:
            for key, val in item.iteritems():
                self.assertNotIn('-ERR', str(val))
        return res

    def tearDown(self):
        '''
        this is run after each test
        '''
        if self.proc is not None:
            self._stop_ldap()

    def _start_ldap(self):
        '''
        start the ldap server
        '''
        self.proc = subprocess.Popen(["tcpserver", "-RHl", "localhost", "0", "1389", "./tinyldap-64bit"]  ,
                             cwd="%s/test/data" % getcwd())
        assert self.proc != None


    def _stop_ldap(self):
        '''
        Stop the ldap server
        '''
        self.proc.terminate()


    def test_sql_getUserId(self):
        '''
        SQL: test the existance of the user1 and user2
        '''
        res = self.y.getUserId("user1")
        print "uid (user1): ", res
        assert res == 1

        assert self.y.getUserInfo(res).get("surname") == "Eins"

        res = self.y.getUserId("user2")
        print "uid (user2): ", res
        assert res == 2

        assert self.y.getUserInfo(res).get("surname") == "Zwo"

        res = self.z.getUserId("user2")
        print "uid (user2): ", res
        assert res == "user2"


    def test_sql_checkpass(self):
        '''
        SQL: Check the password of user1 and user 2
        '''
        assert self.y.checkPass(self.y.getUserId("user1"), "password")
        assert self.y.checkPass(self.y.getUserId("user2"), "password")

    def test_sql_checkpass_wo_salt(self):
        '''
        SQL: Check the password of user1 and user 2 without column SALT
        '''
        assert self.z.checkPass(self.z.getUserId("user1"), "password")
        assert self.z.checkPass(self.z.getUserId("user2"), "password")

    def test_get_search_fields(self):
        '''
        SQL: Check the search field detection.
        '''
        search_fields = self.y.getSearchFields()
        self.assertEqual(set(search_fields.keys()),
                         set(['username', 'userid', 'password', 'salt', 'givenname',
                              'surname', 'email']))
        self.assertEqual(set(search_fields.values()), set(['numeric', 'text']))

    def test_sql_search_escapes(self):
        '''
        SQL: Check that the SQL wildcards are correctly escaped.
        '''
        res1 = self.getUserList(self.y, {'givenname': 'Pro%ent'})
        self.assertEqual(len(res1), 1)
        self.assertEqual(res1[0]['username'], 'user_3')

        res2 = self.getUserList(self.y, {'username': 'user_3'})
        self.assertEqual(len(res2), 1)
        self.assertEqual(res2[0]['username'], 'user_3')

        res3 = self.getUserList(self.y, {'username': 'user.3'})
        self.assertEqual(len(res3), 2)
        self.assertEqual(set(s['username'] for s in res3), set([u'user_3', u'userx3']))

        res4 = self.getUserList(self.y, {'username': 'user*'})
        self.assertEqual(len(res4), 4)

        res5 = self.getUserList(self.y, {'surname': '....'})
        self.assertEqual(set(s['userid'] for s in res5), set([1, 3]))

    def test_sql_complex_search(self):
        '''
        SQL: test more complex search queries
        '''
        res1 = self.getUserList(self.y, {'userid': '> 2'})
        self.assertEqual(len(res1), 2)
        self.assertEqual(set(s['userid'] for s in res1), set((3, 4)))

        res2 = self.getUserList(self.y, {'userid': '  <=   3  '})
        self.assertEqual(len(res2), 3)

        res3 = self.getUserList(self.y, {'userid': '>77'})
        self.assertEqual(res3, [])

    def test_sql_where(self):
        '''
        SQL: test with a where clause. The where clause in `self.w` only gives us
        users with IDs > 2.
        '''
        res1 = self.getUserList(self.w, {})
        self.assertEqual(set(s['username'] for s in res1), set(('user_3', 'userx3')))
        self.assertEqual(self.w.getUsername(1), "")
        self.assertEqual(self.w.getUsername(2), "")
        self.assertEqual(self.w.getUsername(3), "user_3")
        self.assertEqual(self.w.getUsername(4), "userx3")
        self.assertEqual(self.w.getUsername(5), "")

        self.assertTrue(self.w.checkPass(self.w.getUserId('user_3'), 'test'))
        self.assertFalse(self.w.checkPass(self.w.getUserId('user_3'), 'falsch'))

    def test_sql_getUserList(self):
        '''
        SQL: testing the userlist
        '''
        # all users are two users
        list = self.getUserList(self.y, {})
        assert len(list) == 4

        # there is only one user that ends with '1'
        list = self.getUserList(self.y, {"username" : "*1"})
        print list
        assert len(list) == 1

    def test_sql_getUsername(self):
        '''
        SQL: testing getting the username
        '''
        assert self.y.getUsername(1) == "user1"
        assert self.y.getUsername(2) == "user2"
        assert self.y.getUsername(5) == ""
        # also test in the resolver with id as strings
        assert self.z.getUsername("user1") == "user1"
        assert self.z.getUsername("user2") == "user2"
        assert self.z.getUsername("user5") == ""


    def test_ldap_getUserId(self):
        '''
        LDAP: test the existance of the user1 and user2
        '''
        self._start_ldap()
        res1 = self.ldap_y.getUserId("user1")
        print "uid (user1): ", res1
        res2 = self.ldap_y.getUserId("user2")
        print "uid (user2): ", res2

        assert res1 == u"cn=user1,o=linotp,c=org"
        assert res2 == u"cn=user2,o=linotp,c=org"

    def test_ldap_checkpass(self):
        '''
        LDAP: Check the password of user1 and user 2
        '''
        self._start_ldap()
        r1 = self.ldap_y.checkPass(self.ldap_y.getUserId("user1"), "geheim")
        r2 = self.ldap_y.checkPass(self.ldap_y.getUserId("user2"), "geheim")
        assert r1
        assert r2

    def test_ldap_getUserId_unicode(self):
        '''
        LDAP: test the existance of user with german umlaut
        '''
        self._start_ldap()
        res3 = self.ldap_y.getUserId("kölbel")
        print "uid (kölbel): ", res3
        #res4 = self.ldap_y.getUserId("weiß")
        #print "uid (weiß): ", res4

        assert res3 == u"cn=kölbel,o=linotp,c=org"

    def test_ldap_getUserList(self):
        '''
        LDAP: testing the userlist
        '''
        # all users are two users
        self._start_ldap()
        list = self.ldap_y.getUserList({})
        print list
        assert len(list) == 4


    def test_ldap_getUsername(self):
        '''
        LDAP: testing getting the username
        '''
        self._start_ldap()
        r1 = self.ldap_y.getUsername(u"cn=user1,o=linotp,c=org")
        r2 = self.ldap_y.getUsername(u"cn=kölbel,o=linotp,c=org")
        r3 = self.ldap_y.getUsername(u"cn=niemand,o=linotp,c=org")
        print "r1: " , r1
        print "r2: " , r2
        print "r3: " , r3
        assert r1 == u"user1"
        assert r2 == u"kölbel"
        assert r3 == ""


def main():
    if len(sys.argv) < 2:
        print 'Usage: `python test_resolve.py JSON-CONFIG-FILE`'
        sys.exit(1)
    elif not os.path.isfile(sys.argv[1]):
        print '%r is not a file.' % sys.argv[1]
        sys.exit(1)
    unittest.main(argv=[sys.argv[0]])

if __name__ == '__main__':
    main()

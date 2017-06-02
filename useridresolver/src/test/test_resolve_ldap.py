#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

import mock
import unittest
import subprocess
import ldap

from os import getcwd
from copy import deepcopy
from useridresolver.UserIdResolver import getResolverClass
from useridresolver import LDAPIdResolver


class LDAPResolverTest(unittest.TestCase):

    def setUp(self):

        self.ldap_y = getResolverClass("useridresolver.LDAPIdResolver", "IdResolver")()

        self.ldap_test_param = {'linotp.ldapresolver.LDAPFILTER': '(&(cn=%s))',
                                'linotp.ldapresolver.LDAPSEARCHFILTER': '(cn=*)',
                                'linotp.ldapresolver.LOGINNAMEATTRIBUTE': 'cn',
                                'linotp.ldapresolver.USERINFO': '{"username":"cn", "description":"", \
                                                "phone" : "telephoneNumber",\
                                                "groups" : "o",\
                                                "mobile" : "mobile", \
                                                "email" : "email",\
                                                "surname" : "sn",\
                                                "givenname" : "givenName",\
                                                "gender" : "" } ',
                                'linotp.ldapresolver.LDAPURI': 'ldap://localhost:1389',
                                'linotp.ldapresolver.LDAPBASE': 'o=linotp,c=org',
                                'linotp.ldapresolver.BINDDN': '',
                                'linotp.ldapresolver.BINDPW': '',
                                'linotp.ldapresolver.TIMEOUT': '5',
                                'linotp.ldapresolver.SIZELIMIT': '10',
                                'linotp.certificates.use_system_certificates': False,
                                }
        self.ldap_y.loadConfig(self.ldap_test_param)

    def getUserList(self, obj, arg):
        '''
            call obj.getUserList(), but check that we have no errors before returning.
        '''
        res = obj.getUserList(arg)
        for item in res:
            for key, val in item.iteritems():
                self.assertNotIn('-ERR', str(val))
        return res

    @mock.patch.object(LDAPIdResolver.IdResolver, 'bind', autospec=True)
    def mocked_ldap_getuserid(self, user, retvalue, mock_bind):
        '''
        Request search for a user, and return the result.
        Use mock to avoid external LDAP call
        '''

        mock_bind.return_value.search_ext.return_value = 1
        mock_bind.return_value.result.return_value = [ldap.RES_SEARCH_ENTRY,
                                                      retvalue]

        res = self.ldap_y.getUserId(user)

        return res

class LDAPConnectTests(LDAPResolverTest):
    def test_ldap_testconnection_invalid_parameter(self):
        self.ldap_test_param['linotp.ldapresolver.TIMEOUT'] = 'qwerty'
        (status, desc) = LDAPIdResolver.IdResolver.testconnection(self.ldap_test_param)
        self.assertEqual(status, "error")

class LDAPInProcessTests(LDAPResolverTest):
    def test_ldap_getuserid_ad(self):
        '''
        LDAP: test handling of no user found
        from an AD server
        '''
        adret = [('CN=Clark Maxwell,OU=corp,DC=hotad,DC=example,DC=net',
             {'objectGUID': ['\x9a\x13Y\xb6uF\xd4N\xba\x0f \xc9\xfd\xd9{\x00']}),
            (None, ['ldap://ForestDnsZones.hotad.example.net/DC=ForestDnsZones,DC=hotad,DC=example,DC=net']),
            (None, ['ldap://DomainDnsZones.hotad.example.net/DC=DomainDnsZones,DC=hotad,DC=example,DC=net']),
            (None, ['ldap://hotad.example.net/CN=Configuration,DC=hotad,DC=example,DC=net'])]

        # Check with result
        res = self.mocked_ldap_getuserid('maxwell', adret)
        self.assertNotEqual(res, "")

        # This time, only return federated values
        res = self.mocked_ldap_getuserid('nouser', adret[1:])
        self.assertEqual(res, "")

    def test_ldap_getuserid_ldap_notfound(self):
        '''
        LDAP: test handling of user with empty result
        '''
        res = self.mocked_ldap_getuserid('nouser', [])
        self.assertEqual(res, "")

    def test_ldap_getuserid_ldap_found(self):
        '''
        LDAP: test handling of user from LDAP directory
        '''
        ldapret = [('cn=Johann Sebastian Bach,ou=people,dc=blackdog,dc=corp,dc=lsexperts,dc=de',
                    {'entryUUID': ['ef50cce4-1df9-1033-90e7-713823084e1f']})]
        res = self.mocked_ldap_getuserid('bach', ldapret)
        self.assertEqual(res, ldapret[0][0])

    def test_start_tls_connect_exception(self):
        '''
        LDAP: Test handling of start_tls exceptions

        These exceptions should be silently caught and the connection retried without
        STARTTLS
        '''
        for effect in [ldap.CONNECT_ERROR, ldap.UNAVAILABLE]:
            with mock.patch('useridresolver.LDAPIdResolver.ldap.initialize', autospec=True) as mock_ldap_init:
                l_obj = mock_ldap_init.return_value
                mock_start_tls = l_obj.start_tls_s
                mock_start_tls.side_effect = effect("This exception should be caught")

                caller = deepcopy(self.ldap_y)
                caller.enforce_tls = False
                caller.use_sys_cert = False

                self.ldap_y.connect('ldap://localhost', caller)
                mock_start_tls.assert_called_once()
                self.assertEqual(mock_ldap_init.call_count, 2,
                                 "ldap.initialize should have been called twice (with starttls, without starttls).\nException:%s\nCalls:%s".format(
                                     effect,
                                     mock_ldap_init.call_args_list)
                                 )

class LDAPResolverExtTest(LDAPResolverTest):
    proc = None  # LDAP process

    def setUp(self):
        LDAPResolverTest.setUp(self)
        self._start_ldap()

    def tearDown(self):
        LDAPResolverTest.tearDown(self)

        if self.proc is not None:
            self._stop_ldap()

    def _start_ldap(self):
        '''
        start the ldap server
        '''
        self.proc = subprocess.Popen(["tcpserver", "-RHl", "localhost", "0", "1389", "./tinyldap-64bit"]  ,
                             cwd="%s/test/data" % getcwd())
        self.assertIsNotNone(self.proc)

    def _stop_ldap(self):
        '''
        Stop the ldap server
        '''
        self.proc.terminate()
        print self.proc.communicate()

    def test_ldap_getUserId(self):
        '''
        LDAP: test the existance of the user1 and user2
        '''
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
        r1 = self.ldap_y.checkPass(self.ldap_y.getUserId("user1"), "geheim")
        r2 = self.ldap_y.checkPass(self.ldap_y.getUserId("user2"), "geheim")
        assert r1
        assert r2

    def test_ldap_getUserId_unicode(self):
        '''
        LDAP: test the existance of user with german umlaut
        '''
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
        list = self.ldap_y.getUserList({})
        print list
        assert len(list) == 4


    def test_ldap_getUsername(self):
        '''
        LDAP: testing getting the username
        '''
        r1 = self.ldap_y.getUsername(u"cn=user1,o=linotp,c=org")
        r2 = self.ldap_y.getUsername(u"cn=kölbel,o=linotp,c=org")
        r3 = self.ldap_y.getUsername(u"cn=niemand,o=linotp,c=org")
        print "r1: " , r1
        print "r2: " , r2
        print "r3: " , r3
        assert r1 == u"user1"
        assert r2 == u"kölbel"
        assert r3 == ""

if __name__ == '__main__':
    unittest.main()

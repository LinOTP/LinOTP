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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

"""
sql resolver tests
"""

import logging
import json

from mock import patch

from linotp.useridresolver.UserIdResolver import ResolverNotAvailable
from linotp.useridresolver.LDAPIdResolver import IdResolver as ldap_resolver

from linotp.lib.user import lookup_user_in_resolver

from linotp.tests import TestController


log = logging.getLogger(__name__)

def mocked_getUserInfo(_mock_self, *args, **kwargs):
    return "hoi"

def mock_getUserId(self, *args, **argv):
    return "maxwell_id"

class LdapResolverTest(TestController):
    """

        verify that cache is working:
        1. use validate/check to fill the cache with user bach
        2. check that second call does not call getUserId / getUserInfo
           as it could be satisfied from the cache

        verfiy that cache is not filled when exception is raised
        1. use /validate/check with different user and raise the exception
           from the bind
        2. check that a second call to /validate/check will try to lookup
           the user again in the resolver


    """

    def setUp(self):
        res = TestController.setUp(self)

        params = {
            "user_lookup_cache.enabled": True,
            "resolver_lookup_cache.enabled": True,
            }

        response = self.make_system_request('setConfig', params)
        self.assertTrue('"status": true' in response.body, response)

        return res

    def tearDown(self):

        self.delete_all_realms()
        self.delete_all_resolvers()

        params = {
            "user_lookup_cache.enabled": False,
            "resolver_lookup_cache.enabled": False,
            }

        response = self.make_system_request('setConfig', params)
        self.assertTrue('"status": true' in response.body, response)

        return TestController.tearDown(self)

    def setup_ldap_resolver(self):

        params = {
            'BINDDN': ('cn="Wolfgang Amadeus Mozart,ou=people,'
                       'dc=blackdog,dc=example,dc=com'), 
            'LDAPFILTER': '(&(uid=%s)(objectClass=inetOrgPerson))', 
            'CACERTIFICATE': '', 
            'BINDPW': 'Test123!', 
            'TIMEOUT': '5', 
            'NOREFERRALS': 'True', 
            'LOGINNAMEATTRIBUTE': 'uid', 
            'EnforceTLS': 'False', 
            'LDAPBASE': 'ou=people,dc=blackdog,dc=example,dc=com', 

            'LDAPURI': 'ldap://blackdog.example.com', 
            'LDAPSEARCHFILTER': '(uid=*)(objectClass=inetOrgPerson)', 
            'UIDTYPE': 'entryUUID', 
            'USERINFO': json.dumps({
                "username": "uid",
                "phone" : "telephoneNumber",
                "mobile" : "mobile",
                "email" : "mail",
                "surname" :"sn",
                "givenname" : "givenName"}),
            'SIZELIMIT': '500', 
            'type': 'ldapresolver',
            'name': 'blackdog', 
        }

        response = self.make_system_request(action='setResolver',
                                        params=params)

        self.assertTrue('"value": true' in response, response)

        resolver = 'useridresolver.LDAPIdResolver.IdResolver.blackdog'
        parameters = {
            'resolvers': resolver,
            'realm': 'black'
            }

        response = self.make_system_request('setRealm', params=parameters)
        self.assertTrue('"value": true' in response, response)


    def test_cache_without_exception(self):
        """
        verify that the entry is stored in cache if no exception is raised

        """

        self.setup_ldap_resolver()

        with patch.object(ldap_resolver, 'getUserInfo', autospec=True) as mocked_getUserInfo:
            with patch.object(ldap_resolver, 'getUserId', autospec=True) as mocked_getUserId:

                mocked_getUserId.return_value = "bache_id"
                mocked_getUserInfo.return_value = {
                    'name': 'bach',
                    'login': 'bach',
                    'id': 'bach_id'
                }

                params={
                    'user': 'bach@black',
                    'pass': '1234'
                }

                self.make_validate_request('check', params=params)

                assert mocked_getUserInfo.call_count == 2

                self.make_validate_request('check', params=params)

                assert mocked_getUserInfo.call_count == 2

        return

    def test_cache_with_exception(self):
        """
        verify that the user is not stored in user cache if exception is raised

        the getUserInfo is part of the cache feeder function
        so, when its called there has been no cache entry before - so a second
        call should not increment the getUserInfo

        """

        self.setup_ldap_resolver()

        with patch.object(ldap_resolver, 'getUserInfo', autospec=True) as mocked_getUserInfo:
            with patch.object(ldap_resolver, 'bind', autospec=True) as mocked_bind:

                mocked_bind.side_effect = ResolverNotAvailable("unable to bind")

                params={
                    'user': 'maxwell@black',
                    'pass': '1234'
                }

                self.make_validate_request('check', params=params)

                # a raise of the exception will interupt the cache feeder thus
                # not calling the getUserInfo

                assert mocked_getUserInfo.call_count == 0

                # TODO: we can verify that in the audit log, there is the
                # exception ResolverNotAvailable

            with patch.object(ldap_resolver, 'getUserId', autospec=True) as mocked_getUserId:

                mocked_getUserId.return_value = "maxwell_id"
                mocked_getUserInfo.return_value = {
                    'name': 'maxwell',
                    'login': 'maxwell@black',
                    'id': 'maxwell_id'
                }

                params={
                    'user': 'maxwell@black',
                    'pass': '1234'
                }

                self.make_validate_request('check', params=params)

                # the cache feeder was called => user info added to cache :)

                assert mocked_getUserInfo.call_count == 1

                self.make_validate_request('check', params=params)

                # no more additional call => user info taken from cache :)

                assert mocked_getUserInfo.call_count == 1

        return



# eof

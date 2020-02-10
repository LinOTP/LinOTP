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

getUserId_call_count = 0
raise_exception = False

log = logging.getLogger(__name__)

User_Info = {
    'bach_id': {
        'fusername': 'Johann Sebastian Bach',
        'username': 'bach',
        'userid': 'bach_id'
        },
    'marvell_id': {
        'fusername': 'Capitain Marvell',
        'username': 'marvell',
        'userid': 'marvell_id'
        },

    'maxwell_id': {
        'fusername': 'Maxwell Silver',
        'username': 'maxwell',
        'userid': 'maxwell_id'
        }
    }


def mock_getUserInfo_func(*args, **_kwargs):
    login = args[-1]
    return User_Info.get(login, {})


def mock_getUserId_func(*args, **_kwargs):

    global getUserId_call_count
    getUserId_call_count += 1

    login = args[-1]

    if getUserId_call_count % 2 == 0:
        return login + "_id"

    if raise_exception:
        raise ResolverNotAvailable('unable to bind')

    return None


def mock_getUserId_exc_func(*args, **_kwargs):
    raise ResolverNotAvailable('unable to bind')

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
        assert '"status": true' in response.body, response

        return res

    def tearDown(self):

        self.delete_all_realms()
        self.delete_all_resolvers()

        params = {
            "user_lookup_cache.enabled": False,
            "resolver_lookup_cache.enabled": False,
            }

        response = self.make_system_request('setConfig', params)
        assert '"status": true' in response.body, response

        return TestController.tearDown(self)

    def setup_ldap_resolver(self):

        params = [{
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
        },
            {
            'BINDDN': ('cn="Wolfgang Amadeus Mozart,ou=people,'
                       'dc=blackdark,dc=example,dc=com'),
            'LDAPFILTER': '(&(uid=%s)(objectClass=inetOrgPerson))',
            'CACERTIFICATE': '',
            'BINDPW': 'Test123!',
            'TIMEOUT': '5',
            'NOREFERRALS': 'True',
            'LOGINNAMEATTRIBUTE': 'uid',
            'EnforceTLS': 'False',
            'LDAPBASE': 'ou=people,dc=blackdark,dc=example,dc=com',

            'LDAPURI': 'ldap://blackdark.example.com',
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
            'name': 'blackdark',
        }]

        for param in params:

            response = self.make_system_request(
                                    action='setResolver', params=param)

            assert '"value": true' in response, response

        resolver = ('useridresolver.LDAPIdResolver.IdResolver.blackdog,'
                    'useridresolver.LDAPIdResolver.IdResolver.blackdark')
        parameters = {
            'resolvers': resolver,
            'realm': 'black'
            }

        response = self.make_system_request('setRealm', params=parameters)
        assert '"value": true' in response, response


    def test_cache_without_exception(self):
        """
        verify that the entry is stored in cache if no exception is raised

        """

        global getUserId_call_count

        self.setup_ldap_resolver()

        with patch.object(ldap_resolver, 'getUserInfo', autospec=True) as mocked_getUserInfo:
            with patch.object(ldap_resolver, 'getUserId', autospec=True) as mocked_getUserId:

                mocked_getUserId.side_effect = mock_getUserId_func
                mocked_getUserInfo.side_effect = mock_getUserInfo_func

                params={
                    'user': 'bach@black',
                    'pass': '1234'
                }

                getUserId_call_count = 0

                self.make_validate_request('check', params=params)

                # one for the lookup, one for the existance check
                assert mocked_getUserInfo.call_count == 2

                # for each resolver once
                assert mocked_getUserId.call_count == 2

                getUserId_call_count = 0

                self.make_validate_request('check', params=params)

                # one more for the existance check
                assert mocked_getUserInfo.call_count == 3

                assert mocked_getUserId.call_count == 2

        return


    def test_cache_with_exception(self):
        """
        verify that the user is not stored in user cache if exception is raised

        the getUserInfo is part of the cache feeder function
        so, when its called there has been no cache entry before - so a second
        call should not increment the getUserInfo

        """

        global getUserId_call_count

        self.setup_ldap_resolver()

        with patch.object(ldap_resolver, 'getUserId', autospec=True) as mocked_getUserId:

            mocked_getUserId.side_effect = mock_getUserId_exc_func

            getUserId_call_count = 0

            params={
                'user': 'maxwell',
                'pass': '1234'
            }

            self.make_validate_request('check', params=params)

            # at least for each resolver getUserId is called once
            assert mocked_getUserId.call_count > 2

            old_count = mocked_getUserId.call_count

            self.make_validate_request('check', params=params)

            # as nothing is cached the new counter is at least twice of size

            assert mocked_getUserId.call_count >= 2 * old_count

        return

    def test_multiple_resolvers(self):
        """
        verify that all resolvers are queried and the user is stored
        in user cache but only calls the resolver for one time

        """
        global getUserId_call_count

        global raise_exception
        raise_exception = False

        self.setup_ldap_resolver()

        with patch.object(ldap_resolver, 'getUserId') as mocked_getUserId:
            with patch.object(ldap_resolver, 'getUserInfo') as mocked_getUserInfo:

                mocked_getUserInfo.side_effect = mock_getUserInfo_func
                mocked_getUserId.side_effect = mock_getUserId_func

                getUserId_call_count = 0

                params={
                    'user': 'marvell',
                    'pass': '1234'
                }

                self.make_validate_request('check', params=params)

                # getUserId is called for each resolver
                assert mocked_getUserId.call_count == 2

                # the one which verifies the existance
                assert mocked_getUserInfo.call_count == 2

                # second call

                getUserId_call_count = 0

                self.make_validate_request('check', params=params)

                # the resolvers ar not called anymore as the info is in the
                # cache |(user, realm) -> resolver|
                # only the existance check is done which does one more call

                assert mocked_getUserId.call_count == 2

                # and the getUserInfo is fully in the cache
                assert mocked_getUserInfo.call_count == 3

        return


    def test_multiple_resolvers_with_not_avaialable(self):
        """
        verify that all resolvers are queried and the user is stored
        in user cache but only calls the resolver for one time

        """
        global getUserId_call_count

        global raise_exception
        raise_exception = True

        self.setup_ldap_resolver()

        with patch.object(ldap_resolver, 'getUserId') as mocked_getUserId:
            with patch.object(ldap_resolver, 'getUserInfo') as mocked_getUserInfo:

                mocked_getUserInfo.side_effect = mock_getUserInfo_func
                mocked_getUserId.side_effect = mock_getUserId_func

                getUserId_call_count = 0

                params={
                    'user': 'marvell',
                    'pass': '1234'
                }

                self.make_validate_request('check', params=params)

                # getUserId is called for each resolver
                assert mocked_getUserId.call_count == 2

                # + the one which verifies the existance
                assert mocked_getUserInfo.call_count == 2

                # second call

                getUserId_call_count = 0

                self.make_validate_request('check', params=params)

                # the resolvers ar not called anymore as the info is in the
                # cache |(user, realm) -> resolver|
                assert mocked_getUserId.call_count == 2

                # only the existance check is done which does one more call
                assert mocked_getUserInfo.call_count == 3

        raise_exception = False

        return
# eof

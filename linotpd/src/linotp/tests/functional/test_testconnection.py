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
test the admin/testresolver api

the admin/testresolver api could be used wo password, if the resolver
is already known in LinOTP
"""
import json
from mock import patch
import useridresolver.LDAPIdResolver
import logging

from linotp.tests.functional.test_orphaned import OrphandTestHelpers
from linotp.tests import TestController

log = logging.getLogger(__name__)

PASSWORD = ''


class MockedResolver():

    @classmethod
    def testconnection(*argparams, **kwparams):
        """
        stub to check if password is integrated in the parameters or not

        :return: just always return an connection error, which is ignored
        """
        global PASSWORD

        param = argparams[1]
        PASSWORD = param.get('BINDPW')

        desc = {'desc': "Can't contact LDAP server"}
        status = 'error'
        return (status, desc)


class TestTestresolverAPI(TestController, OrphandTestHelpers):
    """
    test class for the admin/testresolver api
    """

    def setUp(self):
        TestController.setUp(self)

    def define_ldap_resolver(self, name):
        """
        """
        u_map = {"username": "sAMAccountName",
                 "phone": "telephoneNumber",
                 "mobile": "mobile",
                 "email": "mail",
                 "surname": "sn",
                 "givenname": "givenName"}

        params = {
            'BINDDN': 'cn=administrator,dc=yourdomain,dc=tld',
            'LDAPFILTER': '(&(sAMAccountName=%s)(objectClass=user))',
            'LDAPBASE': 'dc=yourdomain,dc=tld',
            'name': name,
            'CACERTIFICATE': '',
            'LOGINNAMEATTRIBUTE': 'sAMAccountName',
            'LDAPURI': 'ldap://linotpserver1, ldap://linotpserver2',
            'LDAPSEARCHFILTER': '(sAMAccountName=*)(objectClass=user)',
            'UIDTYPE': 'objectGUID',
            'BINDPW': 'Test123!',
            'USERINFO': json.dumps(u_map),
            'TIMEOUT': u'5',
            'SIZELIMIT': u'500',
            'NOREFERRALS': u'True',
            'type': u'ldapresolver',
            'EnforceTLS': u'True'}

        response = self.make_system_request('setResolver', params=params)

        return response, params

    def _transform_(self, defintion):
        mapping = {
           'USERINFO': 'ldap_mapping',
           'LDAPFILTER': 'ldap_userfilter',
           'LDAPBASE': 'ldap_basedn',
           'BINDPW': 'ldap_password',
           'BINDDN': 'ldap_binddn',
           'SIZELIMIT': 'ldap_sizelimit',
           'LDAPSEARCHFILTER': 'ldap_searchfilter',
           'LOGINNAMEATTRIBUTE': 'ldap_loginattr',
           'EnforceTLS': 'enforcetls',
           'LDAPURI': 'ldap_uri',
           'UIDTYPE': 'ldap_uidtype',
           'NOREFERRALS': 'noreferrals',
           'TIMEOUT': 'ldap_timeout',
           'CACERTIFICATE': 'ldap_certificate'}

        transform = {}
        for key, value in defintion.items():
            if key in mapping:
                transform[mapping[key]] = value

        return transform

    @patch('useridresolver.LDAPIdResolver.IdResolver.testconnection',
           MockedResolver.testconnection)
    def test_testresolver_for_ldap(self):
        '''
        run the admin testresolver api for the ldap resolver definition

        the response for testconnection  is ignored as it is our mocking result
        we are only interested, which PASSWORD is provided to the
        testconnection which in case of a resolver with different
        name or uri must be empty

        '''
        global PASSWORD

        resolver_name = 'MyLDAP'

        # before running the mocked test request, we have to register
        # the ldap resolver

        response, defintion = self.define_ldap_resolver(resolver_name)
        self.assertTrue('"value": true' in response)

        params = {}
        params.update(self._transform_(defintion))
        params['type'] = 'ldapresolver'
        params['name'] = resolver_name
        params['previous_name'] = resolver_name

        #
        # don't provide a password with the request - the password is taken
        # from the stored resolver of same name

        pw = params['ldap_password']
        del params['ldap_password']

        response = self.make_admin_request('testresolver', params=params)
        self.assertTrue(PASSWORD == 'Test123!', PASSWORD)

        # rename
        # use different name - so that no password will be added

        params['name'] = resolver_name + "_dummy"
        params['previous_name'] = resolver_name
        response = self.make_admin_request('testresolver', params=params)
        self.assertTrue(PASSWORD == 'Test123!', PASSWORD)

        #
        # use same resolver name but the URI is different => no password

        params['name'] = resolver_name
        params['previous_name'] = resolver_name
        ldap_uri = params['ldap_uri']
        params['ldap_uri'] = 'ttt' + ldap_uri

        response = self.make_admin_request('testresolver', params=params)

        self.assertTrue("Missing parameter: ['BINDPW']" in response,
                        response)

        #
        # use same resolver name but different URI and password => password

        params['name'] = resolver_name
        params['previous_name'] = resolver_name
        params['ldap_password'] = pw
        params['ldap_uri'] = 'ttt' + ldap_uri

        response = self.make_admin_request('testresolver', params=params)
        self.assertTrue(PASSWORD == 'Test123!', PASSWORD)

        return

    def test_testresolver_for_sql(self):
        '''
        run the admin testresolver api for the sql resolver definition
        '''

        self.setUpSQL()

        self.delete_all_realms()
        self.delete_all_resolvers()

        resolverName = 'MySQLResolver'
        realmName = 'sqlrealm'.lower()

        self.addUsers()
        self.addSqlResolver(resolverName)
        self.addSqlRealm(realmName, resolverName, defaultRealm=True)

        params = {}
        params.update(self.sqlResolverDef)

        params['type'] = 'sqlresolver'
        params['name'] = resolverName
        params['url'] = self.sqlconnect

        response = self.make_admin_request('testresolver', params=params)
        self.assertTrue('"rows": 12' in response)

        #
        # the connection test even works, if the password is missing
        # as the resolver name is already stored and the password could
        # retrieved from the stored configuration
        #

        del params['Password']
        params['previous_name'] = resolverName
        response = self.make_admin_request('testresolver', params=params)
        self.assertTrue('"rows": 12' in response)

        #
        # in case of an undefined resolver no password could be retrieved and
        # the connection will fail
        #

        params['name'] = 'undefined'
        del params['previous_name']
        response = self.make_admin_request('testresolver', params=params)
        self.assertTrue("Missing parameter: ['Password']" in response)

        self.delSqlRealm(realmName)
        self.delSqlResolver(resolverName)

        return

# eof

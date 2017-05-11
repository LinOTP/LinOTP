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


""" """

import logging
from pylons import config

import json
import os

from sqlalchemy.engine import create_engine
from sqlalchemy import engine_from_config
import sqlalchemy

from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestResolver(TestController):

    def setUp(self):
        TestController.setUp(self)
        self.create_common_resolvers()
        return

    def tearDown(self):
        TestController.tearDown(self)
        self.delete_all_realms()
        self.delete_all_resolvers()
        return

    def define_ldap_resolver(self, name, params=None):
        """
        """
        u_map = {"username": "sAMAccountName",
                 "phone": "telephoneNumber",
                 "mobile": "mobile",
                 "email": "mail",
                 "surname": "sn",
                 "givenname": "givenName"}

        iparams = {
            'name': name,
            'BINDDN': 'cn=administrator,dc=yourdomain,dc=tld',
            'LDAPBASE': 'dc=yourdomain,dc=tld',
            'LDAPURI': 'ldap://linotpserver1, ldap://linotpserver2',

            'CACERTIFICATE': '',

            'LOGINNAMEATTRIBUTE': 'sAMAccountName',
            'LDAPSEARCHFILTER': '(sAMAccountName=*)(objectClass=user)',
            'LDAPFILTER': '(&(sAMAccountName=%s)(objectClass=user))',
            'UIDTYPE': 'objectGUID',
            'USERINFO': json.dumps(u_map),

            'TIMEOUT': '5',
            'SIZELIMIT': '500',
            'NOREFERRALS': 'True',
            'type': 'ldapresolver',
            'EnforceTLS': 'True'}

        if params:
            iparams.update(params)

        response = self.make_system_request('setResolver', params=iparams)

        return response, iparams

    def define_sql_resolver(self, name, params=None, user_mapping=None):
        """
        create sql useridresolver
        """

        engine = engine_from_config(config, 'sqlalchemy.')
        db_url = engine.url

        server = db_url.host
        if db_url.port:
            server = "%s:%s" % (db_url.host, db_url.port)

        if not user_mapping:
            user_mapping = {}
        usermap = {
                "userid": "id",
                "username": "user",
                "phone": "telephoneNumber",
                "mobile": "mobile",
                "email": "mail",
                "surname": "sn",
                "givenname": "givenName",
                "password": "password",
                "salt": "salt"
                }
        user_mapping.update(usermap)

        if not params:
            params = {}

        resolver_def = {
                'name': name,

                'Server': server,
                'Database': db_url.database,
                'Driver': db_url.drivername,
                'User': db_url.username,
                # 'Password': db_url.password,

                'Map': json.dumps(usermap),
                'Where': u'',
                'Encoding': u'',
                'Limit': u'40',
                'Table': u'usertable',
                'type': u'sqlresolver',
                'Port': u'3306',
                'conParams': u''}

        resolver_def.update(params)
        resolver_def['name'] = name

        response = self.make_system_request('setResolver',
                                            params=resolver_def)

        return response, resolver_def

    def test_try_to_create_faulty_resolver(self):
        """
        test: it's not possible to define a resolver w.o. required parameters
        """

        #
        # define resolver LDA1 w. the required BINDPW

        params = {'BINDPW': 'Test123!'}
        response, params = self.define_ldap_resolver('LDA1', params=params)
        self.assertTrue('"status": true,' in response, response)

        #
        # and check if its available

        response = self.make_system_request('getResolvers', params=params)
        self.assertTrue("LDA1" in response, response)

        #
        # now try to define resolver LDA2 w.o. the required BINDPW

        response, params = self.define_ldap_resolver('LDA2')
        msg = "Missing parameter: ['BINDPW']"
        self.assertIn(msg, response, response)

        #
        # and check that it is not available

        response = self.make_system_request('getResolvers', params={})
        self.assertFalse("LDA2" in response, response)

        return

    def test_resolver_duplicate(self):
        """
        test: it is not possible to have multiple resolvers with same name
        """

        params = {'resolver': 'myDefRes'}
        response = self.make_system_request('getResolver', params=params)
        jresp = json.loads(response.body)
        data = jresp.get('result', {}).get('value', {}).get('data', {})
        self.assertIn('fileName', data, response)

        response = self.make_system_request('getConfig')
        jresp = json.loads(response.body)
        value = jresp.get('result', {}).get('value', {})
        self.assertIn('passwdresolver.fileName.myDefRes', value, response)

        response, _defi = self.define_sql_resolver(name='myDefRes')
        msg = "Cound not create resolver, resolver u'myDefRes' already exists!"
        self.assertTrue(msg in response, response)

        response = self.make_system_request('getConfig')
        jresp = json.loads(response.body)
        value = jresp.get('result', {}).get('value', {})
        self.assertIn('passwdresolver.fileName.myDefRes', value, response)
        self.assertNotIn('sqlresolver.Limit.myDefRes', value, response)

        params = {'resolver': 'myDefRes'}
        response = self.make_system_request('getResolver', params=params)
        jresp = json.loads(response.body)
        data = jresp.get('result', {}).get('value', {}).get('data', {})
        self.assertIn('fileName', data, response)
        self.assertNotIn('Server', data, response)

        return

    def test_rename_resolver(self):
        """
        test: it's possible to rename a resolver w.o. required parameters
        """

        #
        # define resolver LDA1 w. the required BINDPW

        params = {'BINDPW': 'Test123!'}
        response, params = self.define_ldap_resolver('LdapX', params=params)
        self.assertTrue('"status": true,' in response, response)

        #
        # rename resolver LdapX to LdapZ w.o. password
        # as no critical changes are made

        params = {'previous_name': 'LdapX'}
        response, params = self.define_ldap_resolver('LdapZ', params=params)
        self.assertTrue('"status": true,' in response, response)

        response = self.make_system_request('getResolvers')
        self.assertNotIn('LdapX', response, response)
        self.assertIn('LdapZ', response, response)

    def test_update_critical_data_ldap(self):
        """
        test: it's not possible to define a resolver w. critical changes
        """

        #
        # define resolver LDA1 w. the required BINDPW

        params = {'BINDPW': 'Test123!'}
        response, params = self.define_ldap_resolver('LdapX', params=params)
        self.assertTrue('"status": true,' in response, response)

        #
        # rename resolver LDA1 to LDB with critical changes
        # w.o. password will fail

        params = {'previous_name': 'LdapX',
                  'BINDDN': 'ou=roundabout, '
                            'cn=administrator,dc=yourdomain,dc=tld', }
        response, params = self.define_ldap_resolver('LdapZ', params=params)
        self.assertTrue('"status": false,' in response, response)

        response = self.make_system_request('getResolvers')
        self.assertNotIn('LdapZ', response, response)
        self.assertIn('LdapX', response, response)

        #
        # rename resolver LDA1 to LDB with critical changes
        # w. password will have success

        params = {'previous_name': 'LdapX',
                  'BINDPW': 'Test123!',
                  'BINDDN': 'ou=roundabout, '
                            'cn=administrator,dc=yourdomain,dc=tld', }

        response, params = self.define_ldap_resolver('LdapZ', params=params)
        self.assertTrue('"status": true,' in response, response)

        response = self.make_system_request('getResolvers')
        self.assertNotIn('LdapX', response, response)
        self.assertIn('LdapZ', response, response)

    def test_update_critical_data_sql(self):
        """
        test: it's not possible to define a resolver w. critical changes
        """

        #
        # define resolver SqlX w. the required Password

        params = {"Password": "Test123!", }
        response, params = self.define_sql_resolver('SqlX', params=params)
        self.assertTrue('"status": true,' in response, response)

        #
        # rename resolver SqlX to SqlZ with critical changes
        # w.o. password will fail

        params = {'previous_name': 'SqlX',
                  'User': 'dummy_user', }

        response, params = self.define_sql_resolver('SqlZ', params=params)
        self.assertTrue('"status": false,' in response, response)

        response = self.make_system_request('getResolvers')
        self.assertNotIn('SqlZ', response, response)
        self.assertIn('SqlX', response, response)

        #
        # rename resolver SqlX to SqlZ with critical changes
        # w. password will have success

        params = {'previous_name': 'SqlX',
                  'User': 'dummy_user',
                  'Password': 'Test123!'}

        response, params = self.define_sql_resolver('SqlZ', params=params)
        self.assertTrue('"status": true,' in response, response)

        response = self.make_system_request('getResolvers')
        self.assertNotIn('SqlX', response, response)
        self.assertIn('SqlZ', response, response)

    def test_rename_resolver_in_realms(self):

        resolver_param = {
                'fileName': (os.path.join(self.fixture_path, 'def-passwd')),
                'type': 'passwdresolver',
            }

        for name in ['AAAA', 'BBBB', 'CCCC', 'DDDD']:
            response = self.create_resolver(name, resolver_param)
            self.assertTrue('"value": true' in response.body)

        resolver_list = []
        resolver_base = 'useridresolver.PasswdIdResolver.IdResolver.'
        for name in ['AAAA', 'BBBB', 'CCCC', 'DDDD']:
            resolver_list.append(resolver_base + name)

        response = self.create_realm('eins', resolver_list)
        self.assertTrue('"value": true' in response.body)

        response = self.create_realm('zwei', resolver_list)
        self.assertTrue('"value": true' in response.body)

        # now we change the resolver name BBBB to ZZZZ

        zzzz_resolver_param = {}
        zzzz_resolver_param.update(resolver_param)
        zzzz_resolver_param['previous_name'] = 'BBBB'
        response = self.create_resolver('ZZZZ', zzzz_resolver_param)
        self.assertTrue('"value": true' in response.body)

        # finally we have to check the realm definition

        response = self.make_system_request('getRealms', {})
        jresp = json.loads(response.body)
        eins = jresp['result']['value']['eins']['useridresolver']
        zwei = jresp['result']['value']['zwei']['useridresolver']

        new_resolver_list = ['AAAA', 'CCCC', 'DDDD', 'ZZZZ']
        expected_resolvers = [resolver_base +
                              name for name in new_resolver_list]
        self.assertItemsEqual(eins, expected_resolvers)
        self.assertItemsEqual(zwei, expected_resolvers)

        return

# eof #########################################################################

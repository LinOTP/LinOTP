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


""" """

import json
import logging
import os

import pytest
import sqlalchemy
from mock import patch
from sqlalchemy import engine_from_config
from sqlalchemy.engine import create_engine

from linotp.flap import config
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

        engine = create_engine(config.get('DATABASE_URI'))
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
                'Where': '',
                'Encoding': '',
                'Limit': '40',
                'Table': 'usertable',
                'type': 'sqlresolver',
                'Port': '3306',
                'conParams': ''}

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
        assert '"status": true,' in response, response

        #
        # and check if its available

        response = self.make_system_request('getResolvers', params=params)
        assert "LDA1" in response, response

        #
        # now try to define resolver LDA2 w.o. the required BINDPW

        response, params = self.define_ldap_resolver('LDA2')
        msg = "Missing parameter: ['BINDPW']"
        assert msg in response, response

        #
        # and check that it is not available

        response = self.make_system_request('getResolvers', params={})
        assert not ("LDA2" in response), response

        return

    def test_resolver_duplicate(self):
        """
        test: it is not possible to have multiple resolvers with same name
        """

        params = {'resolver': 'myDefRes'}
        response = self.make_system_request('getResolver', params=params)
        jresp = json.loads(response.body)
        data = jresp.get('result', {}).get('value', {}).get('data', {})
        assert 'fileName' in data, response

        response = self.make_system_request('getConfig')
        jresp = json.loads(response.body)
        value = jresp.get('result', {}).get('value', {})
        assert 'passwdresolver.fileName.myDefRes' in value, response

        response, _defi = self.define_sql_resolver(name='myDefRes')
        msg = "Cound not create resolver, resolver 'myDefRes' already exists!"
        assert response.json['result']['error']['message'] == msg, response

        response = self.make_system_request('getConfig')
        jresp = json.loads(response.body)
        value = jresp.get('result', {}).get('value', {})
        assert 'passwdresolver.fileName.myDefRes' in value, response
        assert 'sqlresolver.Limit.myDefRes' not in value, response

        params = {'resolver': 'myDefRes'}
        response = self.make_system_request('getResolver', params=params)
        jresp = json.loads(response.body)
        data = jresp.get('result', {}).get('value', {}).get('data', {})
        assert 'fileName' in data, response
        assert 'Server' not in data, response

        return

    def test_rename_resolver(self):
        """
        test: it's possible to rename a resolver w.o. required parameters
        """

        #
        # define resolver LDA1 w. the required BINDPW

        params = {'BINDPW': 'Test123!'}
        response, params = self.define_ldap_resolver('LdapX', params=params)
        assert '"status": true,' in response, response

        #
        # rename resolver LdapX to LdapZ w.o. password
        # as no critical changes are made

        params = {'previous_name': 'LdapX'}
        response, params = self.define_ldap_resolver('LdapZ', params=params)
        assert '"status": true,' in response, response

        response = self.make_system_request('getResolvers')
        assert 'LdapX' not in response, response
        assert 'LdapZ' in response, response

    def test_update_critical_data_ldap(self):
        """
        test: it's not possible to define a resolver w. critical changes
        """

        #
        # define resolver LDA1 w. the required BINDPW

        params = {'BINDPW': 'Test123!'}
        response, params = self.define_ldap_resolver('LdapX', params=params)
        assert '"status": true,' in response, response

        #
        # rename resolver LDA1 to LDB with critical changes
        # w.o. password will fail

        params = {'previous_name': 'LdapX',
                  'BINDDN': 'ou=roundabout, '
                            'cn=administrator,dc=yourdomain,dc=tld', }
        response, params = self.define_ldap_resolver('LdapZ', params=params)
        assert '"status": false,' in response, response

        response = self.make_system_request('getResolvers')
        assert 'LdapZ' not in response, response
        assert 'LdapX' in response, response

        #
        # rename resolver LDA1 to LDB with critical changes
        # w. password will have success

        params = {'previous_name': 'LdapX',
                  'BINDPW': 'Test123!',
                  'BINDDN': 'ou=roundabout, '
                            'cn=administrator,dc=yourdomain,dc=tld', }

        response, params = self.define_ldap_resolver('LdapZ', params=params)
        assert '"status": true,' in response, response

        response = self.make_system_request('getResolvers')
        assert 'LdapX' not in response, response
        assert 'LdapZ' in response, response

    @pytest.mark.exclude_sqlite
    def test_update_critical_data_sql(self):
        """
        test: it's not possible to define a resolver w. critical changes
        """

        params = {"Password": "Test123!", }
        response, params = self.define_sql_resolver('SqlX', params=params)
        assert '"status": true,' in response, response

        #
        # rename resolver SqlX to SqlZ with critical changes
        # w.o. password will fail

        params = {'previous_name': 'SqlX',
                  'User': 'dummy_user', }

        response, params = self.define_sql_resolver('SqlZ', params=params)
        assert '"status": false,' in response, response

        response = self.make_system_request('getResolvers')
        assert 'SqlZ' not in response, response
        assert 'SqlX' in response, response

        #
        # rename resolver SqlX to SqlZ with critical changes
        # w. password will have success

        params = {'previous_name': 'SqlX',
                  'User': 'dummy_user',
                  'Password': 'Test123!'}

        response, params = self.define_sql_resolver('SqlZ', params=params)
        assert '"status": true,' in response, response

        response = self.make_system_request('getResolvers')
        assert 'SqlX' not in response, response
        assert 'SqlZ' in response, response

    def test_rename_resolver_in_realms(self):

        resolver_param = {
                'fileName': (os.path.join(self.fixture_path, 'def-passwd')),
                'type': 'passwdresolver',
            }

        for name in ['AAAA', 'BBBB', 'CCCC', 'DDDD']:
            response = self.create_resolver(name, resolver_param)
            assert '"value": true' in response.body

        resolver_list = []
        resolver_base = 'useridresolver.PasswdIdResolver.IdResolver.'
        for name in ['AAAA', 'BBBB', 'CCCC', 'DDDD']:
            resolver_list.append(resolver_base + name)

        response = self.create_realm('eins', resolver_list)
        assert '"value": true' in response.body

        response = self.create_realm('zwei', resolver_list)
        assert '"value": true' in response.body

        # now we change the resolver name BBBB to ZZZZ

        zzzz_resolver_param = {}
        zzzz_resolver_param.update(resolver_param)
        zzzz_resolver_param['previous_name'] = 'BBBB'
        response = self.create_resolver('ZZZZ', zzzz_resolver_param)
        assert '"value": true' in response.body

        # finally we have to check the realm definition

        response = self.make_system_request('getRealms', {})
        jresp = response.json['result']['value']
        eins = jresp['eins']['useridresolver']
        zwei = jresp['zwei']['useridresolver']

        new_resolver_list = ['AAAA', 'CCCC', 'DDDD', 'ZZZZ']
        expected_resolvers = [resolver_base +
                              name for name in new_resolver_list]
        assert eins.sort() == expected_resolvers.sort(), response.json
        assert zwei.sort() == expected_resolvers.sort(), response.json

    def test_userlist_with_ldap_resolver(self):
        """
        ldap resolver userlist decryptes the bindpw during response iteration
        """

        # define the mocked lobj is used during the userlist iteration

        class Mock_lObj():

            pw = None
            dn = None

            def simple_bind_s(self, dn_encode, pw_encode):
                self.pw = pw_encode
                self.dn = dn_encode

            def result3(self, *args, **kwargs):
                return

            def search_ext(self, *args, **kwargs):
                return 'sdsafsdf'

            def set_option(self, *args, **kwargs):
                pass

            def unbind_s(self, *args, **kwargs):
                pass

        # ------------------------------------------------------------------ --

        # define resolver fake_ldap with a bind password and add the resolver
        # to the realm 'lino'

        ldap_name = 'fake_ldap'
        bind_pw = 'Test123!'

        params = {'BINDPW': bind_pw}
        response, params = self.define_ldap_resolver(ldap_name, params=params)
        assert '"value": true' in response.body

        params = {
            'resolvers':
                'useridresolver.LDAPIdResolver.IdResolver.' + ldap_name,
            'realm': 'lino'}
        response = self.make_system_request('setRealm', params=params)
        assert '"value": true' in response.body

        # ------------------------------------------------------------------ --

        # run the 'userlist' request against the faked ldap resolver

        with patch('linotp.useridresolver.LDAPIdResolver.IdResolver') \
            as mock_resolver:

            mock_lobj = Mock_lObj()
            mock_resolver.connect.return_value = mock_lobj

            params = {'realm': 'lino'}
            response = self.make_admin_request('userlist', params=params)

            # finally the test that the decryption was sucessful

            assert mock_lobj.pw == bind_pw

        params = {'realm': 'lino'}
        response = self.make_system_request('delRealm', params)
        assert '"result": true' in response.body

        params = {'resolver': 'fake_ldap'}
        response = self.make_system_request('delResolver', params)
        assert '"value": true' in response.body

        return

# eof #

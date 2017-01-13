# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 KeyIdentity GmbH
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


""" """

import logging
import random
from datetime import datetime
from datetime import timedelta
from pylons import config

import json


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
            'BINDDN': 'cn=administrator,dc=yourdomain,dc=tld',
            'LDAPFILTER': '(&(sAMAccountName=%s)(objectClass=user))',
            'LDAPBASE': 'dc=yourdomain,dc=tld',
            'name': name,
            'CACERTIFICATE': '',
            'LOGINNAMEATTRIBUTE': 'sAMAccountName',
            'LDAPURI': 'ldap://linotpserver1, ldap://linotpserver2',
            'LDAPSEARCHFILTER': '(sAMAccountName=*)(objectClass=user)',
            'UIDTYPE': 'objectGUID',
            # 'BINDPW': 'Test123!',
            'USERINFO': json.dumps(u_map),
            'TIMEOUT': u'5',
            'SIZELIMIT': u'500',
            'NOREFERRALS': u'True',
            'type': u'ldapresolver',
            'EnforceTLS': u'True'}

        if params:
            iparams.update(params)

        response = self.make_system_request('setResolver', params=iparams)

        return response, iparams

    def createSQLResolver(self, name='name', resolver_spec=None,
                          user_mapping=None):
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

        if not resolver_spec:
            resolver_spec = {}

        resolver_def = {
                'Map': json.dumps(usermap),
                'name': name,

                'Server': server,
                'Database': db_url.database,
                'Driver': db_url.drivername,
                'User': db_url.username,
                'Password': db_url.password,

                'Where': u'',
                'Encoding': u'',
                'Limit': u'40',
                'Table': u'usertable',
                'type': u'sqlresolver',
                'Port': u'3306',
                'conParams': u''}

        resolver_spec.update(resolver_def)
        resolver_spec['name'] = name

        response = self.make_system_request('setResolver',
                                            params=resolver_spec)

        return response

    def test_try_to_create_faulty_resolver(self):
        """
        test: it's not possible to define a resolver w.o. required parameters
        """

        #
        # define resolver LDA w. the required BINDPW

        params = {'BINDPW': 'Test123!'}
        response, params = self.define_ldap_resolver('LDA', params=params)
        self.assertTrue('"status": true,' in response, response)

        #
        # and check if its available

        response = self.make_system_request('getResolvers', params=params)
        self.assertTrue("LDA" in response, response)

        #
        # now try to define resolver LDA2 w.o. the required BINDPW

        response, params = self.define_ldap_resolver('LDA2')
        msg1 = "Unable to instantiate the resolver u'LDA2'"
        msg2 = "Please verify configuration or connection!"
        self.assertIn(msg1, response, response)
        self.assertIn(msg2, response, response)

        #
        # and check that it is not available

        response = self.make_system_request('getResolvers', params={})
        self.assertFalse("LDA2" in response, response)

        return

    def test_resolver_duplicate(self):
        """
        verify that it is not possible to have multiple resolvers
        with same name and differnt type
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

        response = self.createSQLResolver(name='myDefRes')
        self.assertTrue('"value": true'in response, response)

        response = self.make_system_request('getConfig')
        jresp = json.loads(response.body)
        value = jresp.get('result', {}).get('value', {})
        self.assertNotIn('passwdresolver.fileName.myDefRes', value, response)
        self.assertIn('sqlresolver.Limit.myDefRes', value, response)

        params = {'resolver': 'myDefRes'}
        response = self.make_system_request('getResolver', params=params)
        jresp = json.loads(response.body)
        data = jresp.get('result', {}).get('value', {}).get('data', {})
        self.assertNotIn('fileName', data, response)
        self.assertIn('Server', data, response)

        return

# eof #########################################################################

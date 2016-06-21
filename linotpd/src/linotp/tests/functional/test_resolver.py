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

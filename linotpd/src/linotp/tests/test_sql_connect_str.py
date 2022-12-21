#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#


import unittest

from sqlalchemy.engine.url import make_url

from linotp.useridresolver.SQLIdResolver import build_simple_connect


class TestSqlConnectStr(unittest.TestCase):

    test_sets = [{

        'description': 'Test Set 1 - db2',
        'parameters': {'driver': 'db2+ibm_db',
                       'server': '',
                       'port': '',
                       'user': 'USER',
                       'pass_': 'PASS',
                       'db': 'DB_ALIAS',
                       'conParams': ''},
        'result': 'db2+ibm_db://USER:PASS@/DB_ALIAS'}, {

        'description': 'Test Set 2 - mysql',
        'parameters': {'driver': 'mysql',
                       'server': 'hostname',
                       'port': '',
                       'user': 'scott',
                       'pass_': 'tiger',
                       'db': 'dbname',
                       'conParams': ''},
        'result': 'mysql://scott:tiger@hostname/dbname'}, {

        'description': 'Test Set 3 - postgres 8.0',
        'parameters': {'driver': 'postgresql+pg8000',
                       'server': 'localhost',
                       'port': '5432',
                       'user': 'scott',
                       'pass_': 'tiger',
                       'db': 'mydatabase',
                       'conParams': ''},
        'result': 'postgresql+pg8000://scott:tiger@localhost:5432/mydatabase'},
                 {

        'description': 'Test Set 4 - oracle',
        'parameters': {'driver': 'oracle+cx_oracle',
                       'server': 'tnsname',
                       'port': '',
                       'user': 'scott',
                       'pass_': 'tiger',
                       'db': '',
                       'conParams': ''},
        'result': 'oracle+cx_oracle://scott:tiger@tnsname'}, {

        'description': 'Test Set 5 - sqlite - relative db',
        'parameters': {'driver': 'sqlite',
                       'server': '',
                       'port': '',
                       'user': '',
                       'pass_': '',
                       'db': 'foo.db',
                       'conParams': ''},
        'result': 'sqlite:///foo.db'}, {

        'description': 'Test Set 6 - sqlite - absolute db',
        'parameters': {'driver': 'sqlite',
                       'server': '',
                       'port': '',
                       'user': '',
                       'pass_': '',
                       'db': '/tmp/foo.db',
                       'conParams': ''},
        'result': 'sqlite:////tmp/foo.db'},


        ]

    def test_connect_str_from_parameter(self):
        """
        check all test vectors from single parameters to sqlurl

        sqlurls taken from:
            http://docs.sqlalchemy.org/en/latest/core/engines.html

        """

        for test_set in self.test_sets:

            params = test_set['parameters']
            result = test_set['result']
            description = test_set['description']

            sql_connect = build_simple_connect(**params)

            self.assertEqual(sql_connect, result,
                             "error in test set %s: %r:%r" %
                             (description, sql_connect, result))

            # finally we verify that sqlalchemy is able to interpret the url

            make_url(sql_connect)

# eof #

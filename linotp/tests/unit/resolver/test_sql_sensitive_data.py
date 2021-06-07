#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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

import os
import json
from unittest import TestCase
from mock import patch

from linotp.useridresolver.SQLIdResolver import IdResolver as SQLResolver

class TestSQLResolverSensitiveData(object):
    """Test class for SQL sensitive data"""

    resolver = None

    @patch('linotp.lib.crypto.encrypted_data.decryptPassword')
    @patch('linotp.lib.crypto.encrypted_data.encryptPassword')
    def load_resolver(self, mocked_encryptPassword, mocked_decryptPassword):
        """"Read sql resolver configuration from a given JSON file."""

        current_directory = os.path.dirname(os.path.abspath(__file__))

        sql_config = {
            "config": {
                "Driver": "sqlite",
                "Port": "",
                "Database": "%s/imported/data/linotp-users.sql" % current_directory,
                "Server": "",
                "User": "",
                "Password": "",
                "Table": "linotp_users",
                "Map":  json.dumps({
                        "username": "username",
                        "userid": "id",
                        "password": "password",
                        "givenname": "givenname",
                        "surname": "surname",
                        "email": "email"})
            },
            "config2_map": json.dumps({
                "username": "username",
                            "userid": "username",
                            "password": "password",
                            "givenname": "givenname",
                            "surname": "surname",
                            "email": "email"}),

            "config3_where": "(1 = 0 OR linotp_users.id > 2 ) AND 1 = 1"
        }

        mocked_encryptPassword.return_value = b''
        mocked_decryptPassword.return_value = b''

        config = sql_config['config']

        resolver = SQLResolver()
        resolver.loadConfig(config, "")

        return resolver

    def test_sql_getUserInfo(self, base_app):
        """SQL: test the userinfo does not return sensitive data."""

        with base_app.app_context():
            resolver = self.load_resolver()

            res = resolver.getUserId("user1")
            assert res == 1

            user_info = resolver.getUserInfo(res)
            assert 'password' not in user_info

        return

    def test_sql_getUserList(self,base_app):
        """SQL: test the userinfo does not return sensitive data."""

        with base_app.app_context():
            resolver = self.load_resolver()

            users = resolver.getUserList({'username': '*'})

            for user_info in users:
                assert 'password' not in user_info

        return

    def test_sql_checkpass(self, base_app):
        """SQL: Check the password of user1 and user 2 still works."""

        with base_app.app_context():
            resolver = self.load_resolver()

            assert resolver.checkPass(
                resolver.getUserId("user1"),
                "password")
            assert resolver.checkPass(
                resolver.getUserId("user2"),
                "password")

        return

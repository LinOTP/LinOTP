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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

"""
sql tests controller - for sql tests

- partially refactored from the test_orphaned.py

"""

import copy
import logging

from linotp.tests import TestController

from .sql_user import SqlUserDB

log = logging.getLogger(__name__)


class SQLTestController(TestController):
    """
    test controller to support sql resolver test
    """

    def setUpSQL(self, connect=None):
        """
        sql connection setup
        """
        self.sqlconnect = connect or self.app.config.get("DATABASE_URI")
        sqlUser = SqlUserDB(connect=self.sqlconnect)
        self.sqlResolverDef = sqlUser.getResolverDefinition()
        return

    def createUserTable(self, schema_additions=None):
        """
        create the user table for the userid resolver
        """

        userAdd = SqlUserDB(connect=self.sqlconnect)

        try:
            userAdd.createTable(params=schema_additions)
        except Exception as e:
            userAdd.dropTable()
            userAdd.createTable()
            log.error(" create user table error: %r ", e)
            userAdd.delUsers()

    def addUser(
        self,
        login,
        uid,
        password,
        givenname,
        surname,
        mobile,
        telephonenumber,
        mail,
    ):
        """
        add a user to the user db
        """

        userAdd = SqlUserDB(connect=self.sqlconnect)
        user = {
            "user": login,
            "uid": uid,
            "telephonenumber": telephonenumber or "",
            "mobile": mobile or "",
            "sn": surname or "",
            "givenname": givenname or "",
            "password": password or "",
            "mail": mail or "",
        }
        userAdd.addUser(**user)

        resolverDefinition = userAdd.getResolverDefinition()
        userAdd.close()

        return resolverDefinition

    def addUsers(self, usercount=10):
        """
        generator to create users in the user db
        """

        userAdd = SqlUserDB(connect=self.sqlconnect)

        for i in range(1, usercount + 1):
            user = {
                "user": "hey%d" % i,
                "telephonenumber": "012345-678-%d" % i,
                "mobile": "00123-456-%d" % i,
                "sn": "yak%d" % i,
                "givenname": "kayak%d" % i,
                "password": "JT7bTACk0ud6U",
                "uid": i,
            }
            user["mail"] = "%s.%s@example.com" % (
                user["sn"],
                user["givenname"],
            )
            userAdd.addUser(**user)

        resolverDefinition = userAdd.getResolverDefinition()
        userAdd.close()

        return resolverDefinition

    def delUsers(self, uid=None, username=None):
        """
        delete user from the database
        """
        userAdd = SqlUserDB(connect=self.sqlconnect)
        userAdd.delUsers(uid=uid, username=username)
        userAdd.close()

    def addSqlResolver(self, name):
        """
        create a resolver and add this to the linotp server
        """
        parameters = copy.deepcopy(self.sqlResolverDef)

        parameters["name"] = name
        parameters["type"] = "sqlresolver"
        parameters["Limit"] = "20"

        resp = self.make_system_request(
            action="setResolver", params=parameters
        )

        assert '"value": true' in resp, resp

        resp = self.make_system_request(action="getResolvers")
        assert '"resolvername": "%s"' % (name) in resp, resp

        param2 = {"resolver": name}
        resp = self.make_system_request(action="getResolver", params=param2)
        assert '"Table": "User2"' in resp, resp

        return

    def delSqlResolver(self, name):
        """delete the sql resolver"""
        parameters = {
            "resolver": name,
        }
        resp = self.make_system_request(
            action="delResolver", params=parameters
        )
        assert '"value": true' in resp, resp

        return resp

    def addSqlRealm(self, realmName, resolverName, defaultRealm=False):
        """
        add resolver to realm
        """
        resolver = "useridresolver.SQLIdResolver.IdResolver.%s" % resolverName
        parameters = {"resolvers": resolver, "realm": realmName}

        resp = self.make_system_request("setRealm", params=parameters)
        assert '"value": true' in resp, resp

        if defaultRealm:
            params = {"realm": realmName}
            resp = self.make_system_request("setDefaultRealm", params=params)
            assert '"value": true' in resp, resp
        return

    def delSqlRealm(self, realmName):
        """delete realm"""

        parameters = {
            "realm": realmName,
        }
        resp = self.make_system_request(action="delRealm", params=parameters)
        assert '"result": true' in resp, resp

        return resp

    def dropUsers(self):
        """shutdown the db"""

        userAdd = SqlUserDB(connect=self.sqlconnect)
        userAdd.dropTable()

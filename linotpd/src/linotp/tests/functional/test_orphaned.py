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


"""
"""

import logging
from linotp.tests import TestController, url
import copy

try:
    import json
except ImportError:
    import simplejson as json

log = logging.getLogger(__name__)

from sqlalchemy.engine import create_engine
import sqlalchemy
q = '"'


class SQLUser(object):

    def __init__(self, connect='sqlite:///:memory:'):
        self.tableName = 'User2'
        self.usercol = '"user"'
        self.userTable = '"%s"' % (self.tableName)

        self.connection = None
        try:
            self.engine = create_engine(connect)
            connection = self.engine.connect()
            self.sqlurl = self.engine.url
            if self.sqlurl.drivername == 'mysql':
                self.userTable = ("%s.%s"
                                  % (self.sqlurl.database, self.tableName))
                self.usercol = 'user'

        except Exception as e:
            print "%r" % e
        self.connection = connection

        umap = {"userid": "id",
                "username": "user",
                "phone": "telephonenumber",
                "mobile": "mobile",
                "email": "mail",
                "surname": "sn",
                "givenname": "givenname",
                "password": "password",
                "salt": "salt"}

        self.resolverDef = {
            'Table': self.tableName,
            'Map': json.dumps(umap),
         }

        # extend the dict with userid resolver attributes from the connect
        conn_dict = self._parse_connection(connect)
        self.resolverDef.update(conn_dict)

        return

    def _parse_connection(self, connect):
        """
        analyse the sql connection string and transform this to a dict
        that can be used as an input for an sqluserid resolver

         connect = postgres://otpd:linotp2d@localhost/otpdb

        """

        dbdrive_port, _sep, rest = connect.partition('//')
        dbdrive, _sep, port = dbdrive_port.partition(':')
        user_pass, _sep, host_db = rest.partition('@')
        user, _sep, passw = user_pass.partition(':')
        host, _sep, db = host_db.partition('/')

        conn = {
             'Database': db,
             'Driver': dbdrive,
             'Server': host,
             'User': user,
             'Password': passw,
             'type': 'sqlresolver',
            }
        if port:
            conn['Port'] = port
        return conn

    def getResolverDefinition(self):
        return self.resolverDef

    def creatTable(self):

        createStr = """
            CREATE TABLE %s
            (
              %s text,
              telephonenumber text,
              mobile text,
              sn text,
              givenname text,
              password text,
              salt text,
              id text,
              mail text
            )
            """ % (self.userTable, self.usercol)
        t = sqlalchemy.sql.expression.text(createStr)
        self.connection.execute(t)
        return

    def dropTable(self):
        dropStr = "DROP TABLE %s;" % (self.userTable)
        t = sqlalchemy.sql.expression.text(dropStr)
        self.connection.execute(t)

    def addUser(self, user, telephonenumber, mobile, sn, givenname,
                password, salt, uid, mail):
        intoStr = """
            INSERT INTO %s( %s, telephonenumber, mobile,
            sn, givenname, password, salt, id, mail)
            VALUES (:user, :telephonenumber, :mobile, :sn, :givenname,
                    :password, :salt, :id, :mail);
            """ % (self.userTable, self.usercol)
        t = sqlalchemy.sql.expression.text(intoStr)

        self.connection.execute(t, user=user, telephonenumber=telephonenumber,
                                mobile=mobile, sn=sn,
                                givenname=givenname, password=password,
                                salt=salt, id=uid, mail=mail)

        #execute(sqlalchemy.sql.expression.text("""SELECT COUNT(*)
        # FROM Config WHERE Config.Key = :key"""), key=REPLICATION_CONFIG_KEY)

    def query(self):
        selectStr = "select * from %s" % (self.userTable)
        result = self.connection.execute(selectStr)
        res = []
        for row in result:
            res.append(row)

        return res

    def delUsers(self, uid=None, username=None):

        if username is not None:
            delStr = 'DELETE FROM %s  WHERE user=:user;' % (self.userTable)
            t = sqlalchemy.sql.expression.text(delStr)
            self.connection.execute(t, user=username)

        elif type(uid) in (str, u''):
            delStr = 'DELETE FROM %s  WHERE id=:id;' % (self.userTable)
            t = sqlalchemy.sql.expression.text(delStr)
            self.connection.execute(t, id=uid)

        elif uid is None:
            delStr = 'DELETE FROM %s ;' % (self.userTable)
            t = sqlalchemy.sql.expression.text(delStr)
            self.connection.execute(t)

    def close(self):
        self.connection.close()

    def __del__(self):
        self.connection.close()


class TestOrphandTokens(TestController):

    def setUp(self):
        TestController.setUp(self)
        self.set_config_selftest()
        self.setUpSQL()

    def setUpSQL(self):

        self.sqlconnect = self.appconf.get('sqlalchemy.url')
        sqlUser = SQLUser(connect=self.sqlconnect)
        self.sqlResolverDef = sqlUser.getResolverDefinition()
        return

    def addUsers(self, usercount=10):

        userAdd = SQLUser(connect=self.sqlconnect)

        try:
            userAdd.creatTable()
        except Exception as e:
            userAdd.dropTable()
            userAdd.creatTable()
            log.error(" create user table error: %r " % e)
            userAdd.delUsers()

        for i in range(1, usercount):
            user = 'hey%d' % i
            telephonenumber = '012345-678-%d' % i
            mobile = '00123-456-%d' % i
            sn = 'yak%d' % i
            givenname = 'kayak%d' % i
            password = 'safr2r32'
            salt = 't123'
            uid = '__%d' % i
            mail = sn + '.' + givenname + "@example.com"

            userAdd.addUser(user, telephonenumber, mobile, sn, givenname,
                            password, salt, uid, mail)

        u_dict = [{
            'user': 'kn_t',
            'telephonenumber': '012345-678-99999',
            'mobile': '00123-456-99999',
            'sn': 'kn_t',
            'givenname': 'knöt',
            'password': 'safr2r32',
            'salt': 't123',
            'uid': '__9999',
            },
            {'user': 'knöt',
            'telephonenumber': '012345-678-99998',
            'mobile': '00123-456-99998',
            'sn': 'knöt',
            'givenname': 'knöt',
            'password': 'safr2r32',
            'salt': 't123',
            'uid': '__9998',
            },
            {'user': 'kn%t',
            'telephonenumber': '012345-678-99997',
            'mobile': '00123-456-99997',
            'sn': 'kn%t',
            'givenname': 'kn%t',
            'password': 'safr2r32',
            'salt': 't123',
            'uid': '__9997',
            },
            ]
        for user in u_dict:
            user['mail'] = ("%s.%s@example.com"
                            % (user['sn'], user['givenname']))
            userAdd.addUser(**user)

        resolverDefinition = userAdd.getResolverDefinition()
        userAdd.close()

        return resolverDefinition

    def delUsers(self, uid=None, username=None):

        userAdd = SQLUser(connect=self.sqlconnect)
        userAdd.delUsers(uid=uid, username=username)
        userAdd.close()

    def addSqlResolver(self, name):

        parameters = copy.deepcopy(self.sqlResolverDef)

        parameters['name'] = name
        parameters['type'] = 'sqlresolver'
        parameters['Limit'] = '20'

        resp = self.app.get(url(controller='system', action='setResolver'),
                            params=parameters)
        self.assertTrue('"value": true' in resp, resp)

        resp = self.app.get(url(controller='system', action='getResolvers'))
        self.assertTrue('"resolvername": "%s"' % (name) in resp, resp)

        param2 = {'resolver': name
                  }
        resp = self.app.get(url(controller='system', action='getResolver'),
                            params=param2)
        self.assertTrue('"Table": "User2"' in resp, resp)

        return

    def delSqlResolver(self, name):

        parameters = {
            'resolver': name,
        }
        resp = self.app.get(url(controller='system', action='delResolver'),
                            params=parameters)
        self.assertTrue('"value": true' in resp, resp)

        return resp

    def addSqlRealm(self, realmName, resolverName, defaultRealm=False):
        resolver = 'useridresolver.SQLIdResolver.IdResolver.%s' % resolverName
        parameters = {'resolvers': resolver,
             'realm': realmName}

        resp = self.make_system_request('setRealm', params=parameters)
        self.assertTrue('"value": true' in resp, resp)

        if defaultRealm:
            params = {'realm': realmName}
            resp = self.make_system_request('setDefaultRealm', params=params)
            self.assertTrue('"value": true' in resp, resp)
        return

    def delSqlRealm(self, realmName):
        parameters = {
            'realm': realmName,
        }
        resp = self.app.get(url(controller='system', action='delRealm'),
                            params=parameters)
        self.assertTrue('"result": true' in resp, resp)

        return resp

    def getUserList(self, resolver):

        param = {'username': '*', 'resConf': resolver}
        response = self.app.get(url(controller='admin', action='userlist'),
                                params=param)
        if ("error") in response:
            body = json.loads(response.body)
            result = body.get('result')
            error = result.get('error')
            raise Exception(error.get('message'))
        else:
            self.assertTrue('"status": true,' in response, response)

        body = json.loads(response.body)
        result = body.get('result')
        userList = result.get('value')

        return userList

    def addToken(self, user):

        param = {'user': user,
                 'pin': user,
                 'serial': 's' + user,
                 'type': 'spass'}

        response = self.app.get(url(controller='admin', action='init'),
                                params=param)
        self.assertTrue('"status": true,' in response, response)

        return

    def authToken(self, user):

        param = {'user': user, 'pass': user}
        response = self.app.get(url(controller='validate', action='check'),
                                params=param)
        return response

    def showTokens(self):

        param = None
        response = self.app.get(url(controller='admin', action='show'),
                                params=param)
        self.assertTrue('"status": true,' in response, response)
        return response

    def test_orphandTokens_byUser(self):
        '''
            test an orphand token - where the user is removed in the sql database

            Description:
            - create a SQL User Database with a certain number of users
            - create a SQLResolver, who refers to this user database
            - create a realm for this sql resolver
            - create a token for one of the SQL users
            - admin/show should show the token user
            - run authentication for this user
            - remove users from the SQL database
            - admin/show should show the /:no user info:/
            - authentication should fail

        '''
        self.setUpSQL()

        self.delete_all_realms()
        self.delete_all_resolvers()

        resolverName = 'MySQLResolver'
        realmName = 'sqlrealm'.lower()

        self.addUsers()
        self.addSqlResolver(resolverName)
        self.addSqlRealm(realmName, resolverName, defaultRealm=True)

        users = self.getUserList(resolverName)
        user = users[0].get('username')

        self.addToken(user)
        ret = self.authToken(user)
        self.assertTrue('"value": true' in ret, ret)

        self.delUsers()
        users = self.getUserList(resolverName)
        self.assertTrue(len(users) == 0, users)

        res = self.showTokens()
        self.assertTrue("/:no user info:/" in res, res)

        ret = self.authToken(user)
        self.assertTrue('"value": false' in ret, ret)

        self.delSqlRealm(realmName)
        self.delSqlResolver(resolverName)

        return

    def test_orphandTokens_byResolver(self):
        '''
            test an orphaned token by resolver - where the user is not retrievable by the resolver any more

            Description:
            - create a SQL User Database with a certain number of users
            - create a SQLResolver, who refers to this user database
            - create a realm for this sql resolver
            - create a token for one of the SQL users
            - admin/show should show the token user
            - run authentication for this user

            - remove the SQLResolver

            - admin/show should show the /:no user info:/
            - authentication should fail

        '''
        self.setUpSQL()

        self.delete_all_realms()
        self.delete_all_resolvers()

        resolverName = 'MySQLResolver'
        realmName = 'sqlrealm'.lower()

        self.addUsers()
        self.addSqlResolver(resolverName)
        self.addSqlRealm(realmName, resolverName, defaultRealm=True)

        users = self.getUserList(resolverName)
        self.assertTrue(len(users) > 0, users)

        user = users[0].get('username')

        self.addToken(user)
        ret = self.authToken(user)
        self.assertTrue('"value": true' in ret, ret)

        self.delSqlRealm(realmName)
        self.delSqlResolver(resolverName)

        message = ''
        try:
            empty_user_list = self.getUserList(resolverName)
        except Exception as e:
            message = "%r" % e
            log.error(message)
        self.assertTrue(len(empty_user_list) == 0, empty_user_list)
        #assert "invalid resolver class specification" in message

        ret = self.authToken(user)
        self.assertTrue('"value": false' in ret, ret)

        res = self.showTokens()
        self.assertTrue("/:no user info:/" in res, res)

        return

    def test_again(self):
        for _i in range(1, 3):
            self.test_orphandTokens_byResolver()
            self.test_orphandTokens_byUser()

        return

    def test_umlaut_search(self):
        """
        Escaping SQL Resolver: support for wildcards (s. #12135)
        """

        self.setUpSQL()

        self.delete_all_realms()
        self.delete_all_resolvers()

        resolverName = 'MySQLResolver'
        realmName = 'sqlrealm'.lower()

        self.addUsers()
        self.addSqlResolver(resolverName)
        self.addSqlRealm(realmName, resolverName, defaultRealm=True)

        parameters = {'username': 'knöt'}
        response = self.app.get(url(controller='admin', action='userlist'),
                                                            params=parameters)

        self.assertTrue('"userid": "__9998"' in response, response)
        self.assertTrue('"userid": "__9997"' not in response, response)
        self.assertTrue('"userid": "__9999"' not in response, response)

        ## ignore SQL wildcards
        parameters = {'username': 'kn%t'}
        response = self.app.get(url(controller='admin', action='userlist'),
                                                            params=parameters)

        self.assertTrue('"userid": "__9998"' not in response, response)
        self.assertTrue('"userid": "__9997"' in response, response)
        self.assertTrue('"userid": "__9999"' not in response, response)

        ## ignore SQL wildcards
        parameters = {'username': 'kn_t'}
        response = self.app.get(url(controller='admin', action='userlist'),
                                                            params=parameters)

        self.assertTrue('"userid": "__9998"' not in response, response)
        self.assertTrue('"userid": "__9997"' not in response, response)
        self.assertTrue('"userid": "__9999"' in response, response)

        ## support LinOTP wildcards
        parameters = {'username': 'kn*t'}
        response = self.app.get(url(controller='admin', action='userlist'),
                                                            params=parameters)

        self.assertTrue('"userid": "__9998"' in response, response)
        self.assertTrue('"userid": "__9997"' in response, response)
        self.assertTrue('"userid": "__9999"' in response, response)

        ## support LinOTP wildcards
        parameters = {'username': 'kn.t'}
        response = self.app.get(url(controller='admin', action='userlist'),
                                                            params=parameters)

        self.assertTrue('"userid": "__9998"' in response, response)
        self.assertTrue('"userid": "__9997"' in response, response)
        self.assertTrue('"userid": "__9999"' in response, response)

        ## support LinOTP wildcards for other fields
        parameters = {'userid': '*9*'}
        response = self.app.get(url(controller='admin', action='userlist'),
                                                            params=parameters)

        self.assertTrue('"userid": "__9"' in response, response)
        self.assertTrue('"userid": "__9998"' in response, response)
        self.assertTrue('"userid": "__9997"' in response, response)
        self.assertTrue('"userid": "__9999"' in response, response)

        return

###eof#########################################################################

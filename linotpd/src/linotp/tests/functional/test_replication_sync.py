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

try:
    import json
except ImportError:
    import simplejson as json


from sqlalchemy.engine import create_engine
import sqlalchemy

from linotp.tests import TestController, url

log = logging.getLogger(__name__)


class SQLData(object):

    def __init__(self, connect='sqlite:///:memory:'):
        self.userTable = 'Config'

        self.connection = None
        try:
            self.engine = create_engine(connect)
            connection = self.engine.connect()
        except Exception as e:
            print "%r" % e
        self.connection = connection
        return

    def addData(self, key, value, typ, description):
        iStr = """
            INSERT INTO "%s"( "Key", "Value", "Type", "Description")
            VALUES (:key, :value, :typ, :description);
            """ % (self.userTable)

        if "mysql" in self.engine.driver:
            iStr = """
            INSERT INTO %s (%s.Key, Value, Type, Description)
            VALUES (:key, :value, :typ, :description);
            """ % (self.userTable, self.userTable)


        intoStr = iStr

        t = sqlalchemy.sql.expression.text(intoStr)

        self.connection.execute(t, key=key, value=value, typ=typ, description=description)
        return

    def updateData(self, key, value):
        uStr = 'UPDATE "%s"  SET "Value"=:value WHERE "Key" = :key;'
        if "mysql" in self.engine.driver:
            uStr = 'UPDATE %s  SET Value=:value WHERE Config.Key = :key;'

        updateStr = uStr % (self.userTable)

        t = sqlalchemy.sql.expression.text(updateStr)
        self.connection.execute(t, key=key, value=value)
        return

    def query(self):
        selectStr = "select * from %s" % (self.userTable)
        result = self.connection.execute(selectStr)
        rows = []
        for row in result:
            rows.append(row)
            print unicode(row)
        return

    def delData(self, key):
        dStr = 'DELETE FROM "%s" WHERE "Key"=:key;' % (self.userTable)
        if "mysql" in self.engine.driver:
            dStr = ('DELETE FROM %s WHERE %s.Key=:key;' %
                    (self.userTable, self.userTable))

        delStr = dStr
        t = sqlalchemy.sql.expression.text(delStr)
        self.connection.execute(t, key=key)
        return


    def close(self):
        self.connection.close()


    def __del__(self):
        self.connection.close()






class TestReplication(TestController):

    def setUp(self):

        TestController.setUp(self)

        #self.appconf = self.app.app.app.apps[1].application.app.application.app.app.app.config
        self.sqlconnect = self.appconf.get('sqlalchemy.url')
        sqlData = SQLData(connect=self.sqlconnect)
        log.debug(sqlData)

        return

    def tearDown(self):
        ''' Overwrite parent tear down, which removes all realms '''
        return

    def addData(self, key, value, description):

        sqlData = SQLData(connect=self.sqlconnect)
        typ = type(value).__name__
        sqlData.addData(key, value, typ, description)
        sec = random.randrange(1, 9)
        sqlData.updateData("linotp.Config", str(datetime.now()
                                               + timedelta(milliseconds=sec)))
        sqlData.close()

        return


    def delData(self, key):

        sqlData = SQLData(connect=self.sqlconnect)
        sqlData.delData(key)

        sec = random.randrange(1, 9)
        sqlData.updateData("linotp.Config", str(datetime.now()
                                               + timedelta(milliseconds=sec)))
        sqlData.close()

        return

    def addToken(self, user):

        params = {
            'user': user,
            'pin':user,
            'serial': 's' + user,
            'type':'spass',
            }
        response = self.make_admin_request('init', params)
        assert '"status": true,' in response

        return

    def authToken(self, user):

        param = { 'user': user, 'pass':user}
        response = self.app.get(url(controller='validate', action='check'), params=param)
        return response

    def showTokens(self):

        response = self.make_admin_request('show', {})
        assert '"status": true,' in response
        return response


    def test_replication(self):
        '''
            test replication of an simple config entry

            Description:
            - put LinOtp in replication aware mode
            - add a new entry in the Config Data vi SQL + update the timestamp
            - query the Config (system/getConfig, which should show the entry

            - del a entry in the Config Data vi SQL + update the timestamp
            - query the Config (system/getConfig, which should show the entry no more

        '''
        ''' 0. '''
        params = {
            'enableReplication' : 'true',
            }
        resp = self.make_system_request('setConfig', params)
        assert('"setConfig enableReplication:true": true' in resp)

        ''' 1. '''
        self.addData('replication', 'test1', 'test data')

        ''' 2. '''
        resp = self.make_system_request('getConfig', {})
        assert('"replication": "test1"' in resp)


        ''' 3. '''
        self.delData('replication')

        ''' 4. '''
        resp = self.make_system_request('getConfig', {})
        res = ('"replication": "test1"' in resp)
        assert (res == False)

        ''' 5 - cleanup'''
        params = {
            'key':'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        assert('"delConfig enableReplication": true' in resp)

        return



    def test_replication_2(self):
        '''
            test 'no' replication, when 'enableReplication' entry is not set

            Description:
            - put LinOtp in replication aware mode
            - add a new entry in the Config Data vi SQL + update the timestamp
            - query the Config (system/getConfig, which should show the entry

            - del a entry in the Config Data vi SQL + update the timestamp
            - query the Config (system/getConfig, which should show the entry no more

        '''
        ''' 0. '''
        self.addData('replication', 'test1', 'test data')

        ''' 1. '''
        resp = self.make_system_request('getConfig', {})
        res = ('"replication": "test1"' in resp)
        assert (res == False)

        ''' 2. '''
        params = {
            'enableReplication' : 'true',
            }
        resp = self.make_system_request('setConfig', params)
        assert('"setConfig enableReplication:true": true' in resp)


        ''' 3. '''
        self.delData('replication')

        ''' 3. '''
        resp = self.make_system_request('getConfig', {})
        res = ('"replication": "test1"' in resp)
        assert (res == False)


        self.addData('replication', 'test1', 'test data')

        ''' 4. '''
        resp = self.make_system_request('getConfig', {})
        res = ('"replication": "test1"' in resp)
        assert (res == True)


        ''' 3. '''
        self.delData('replication')

        ''' 3. '''
        resp = self.make_system_request('getConfig', {})
        res = ('"replication": "test1"' in resp)
        assert (res == False)


        ''' 5 - cleanup'''
        params = {
            'key': 'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        assert('"delConfig enableReplication": true' in resp)

        return


    def test_updateResolver(self):
        '''
            test replication with resolver update

        '''
        umap = { "userid" : "id",
                "username": "user",
                "phone" : "telephoneNumber",
                "mobile" : "mobile",
                "email" : "mail",
                "surname" : "sn",
                "givenname" : "givenName",
                "password" : "password",
                "salt" : "salt" }

        sqlResolver = {
            "sqlresolver.conParams.mySQL": None,
            "sqlresolver.Where.mySQL": None,
            "sqlresolver.Limit.mySQL": "20",
            "sqlresolver.User.mySQL": "user",
            "sqlresolver.Database.mySQL": "yourUserDB",
            "sqlresolver.Password.mySQL": "157455c27f605ad309d6059e1d936a4" +
                                        "e:7a812ba9e613fb931386f5f4fb025890",
            "sqlresolver.Table.mySQL": "usertable",
            "sqlresolver.Server.mySQL": "127.0.0.1",
            "sqlresolver.Driver.mySQL": "mysql",
            "sqlresolver.Encoding.mySQL": None,
            "sqlresolver.Port.mySQL": "3306",
            "sqlresolver.Map.mySQL": json.dumps(umap)

            }
        for k in sqlResolver:
            self.delData(k)

        ''' 0. '''
        params = {
            'enableReplication': 'true',
            }
        resp = self.make_system_request('setConfig', params)
        assert('"setConfig enableReplication:true": true' in resp)

        for k in sqlResolver:
            self.addData(k, sqlResolver.get(k), '')

        params = {
            'resolver':'mySQL',
            }
        resp = self.make_system_request('getResolver', params)
        assert('"Database": "yourUserDB"' in resp)

        for k in sqlResolver:
            self.delData(k)

        params = {
            'resolver':'mySQL',
            }
        resp = self.make_system_request('getResolver', params)
        assert('"data": {}' in resp)


        ''' 5 - cleanup'''
        params = {
            'key':'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        assert('"delConfig enableReplication": true' in resp)



        return

    def test_updateRealm(self):
        '''
            test replication with realm and resolver update
        '''
        realmDef = {
            "useridresolver.group.realm":
                    "useridresolver.PasswdIdResolver.IdResolver.resolverTest",
            "passwdresolver.fileName.resolverTest": "/etc/passwd",
            "DefaultRealm": "realm",
            }

        for k in realmDef:
            self.delData(k)

        params = {
            'enableReplication' : 'true',
            }
        resp = self.make_system_request('setConfig', params)
        assert('"setConfig enableReplication:true": true' in resp)


        resp = self.make_system_request('getRealms', {})
        res = '"realmname": "realm"' in resp
        assert res == False


        for k in realmDef:
            self.addData(k, realmDef.get(k), '')

        resp = self.make_system_request('getRealms', {})
        res = '"realmname": "realm"' in resp
        assert res == True


        ''' 5 - cleanup'''
        for k in realmDef:
            self.delData(k)

        resp = self.make_system_request('getRealms', {})
        res = '"realmname": "realm"' in resp
        assert res == False


        params = {
            'key':'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        assert('"delConfig enableReplication": true' in resp)



        return

    def test_auth_updateRealm(self):
        '''
          test resolver and realm update with authentication

          0. delete all related data
          1. enable replication
          2. write sql data
          3. lookup for the realm definition
          4. enroll token and auth for user root
          5. cleanup: remove realm definition + replication flag

        '''
        realmDef = {
            "useridresolver.group.realm":
                    "useridresolver.PasswdIdResolver.IdResolver.resolverTest",
            "passwdresolver.fileName.resolverTest": "/etc/passwd",
            "DefaultRealm": "realm",
            }

        ''' 0. delete all related data'''
        for k in realmDef:
            self.delData(k)

        ''' 1. switch on replication '''
        params = {
            'enableReplication' : 'true',
            }
        resp = self.make_system_request('setConfig', params)
        assert('"setConfig enableReplication:true": true' in resp)


        ''' 1.b check that realm is not defined '''
        resp = self.make_system_request('getRealms', {})
        res = '"realmname": "realm"' in resp
        assert res == False


        ''' 2  write sql data '''
        for k in realmDef:
            self.addData(k, realmDef.get(k), '')

        ''' 3. lookup for the realm definition'''
        resp = self.make_system_request('getRealms', {})
        res = '"realmname": "realm"' in resp
        assert res == True

        ''' 4. enroll token and auth for user root '''
        self.addToken('root')
        res = self.authToken('root')
        assert ('"value": true' in res)


        ''' 5 - cleanup'''
        for k in realmDef:
            self.delData(k)

        ''' 5b. lookup for the realm definition'''
        resp = self.make_system_request('getRealms', {})
        res = '"realmname": "realm"' in resp
        assert res == False

        params = {
            'key':'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        assert('"delConfig enableReplication": true' in resp)


        return


    def test_0000_policy(self):
        '''
            test the replication of policies
        '''

        policyDef = {
            "Policy.enrollPolicy.action": "maxtoken=3,",
            "Policy.enrollPolicy.scope": "enrollment",
            "Policy.enrollPolicy.client": None,
            "Policy.enrollPolicy.time": None,
            "Policy.enrollPolicy.realm": "*",
            "Policy.enrollPolicy.user": "*",
            }

        ''' 0 - cleanup'''
        params = {
            'key':'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        assert('"delConfig enableReplication": true' in resp)

        for k in policyDef:
            self.delData(k)


        ''' 1. switch on replication '''
        params = {
            'enableReplication' : 'true',
            }
        resp = self.make_system_request('setConfig', params)
        assert('"setConfig enableReplication:true": true' in resp)

        ''' 2  write sql data '''
        for k in policyDef:
            self.addData(k, policyDef.get(k), '')

        ''' 3. getPolicy '''
        params = {
            'name': 'enrollPolicy',
            }
        resp = self.make_system_request('getPolicy', params)
        assert('"action": "maxtoken=3' in resp)

        ''' 5 - cleanup'''
        for k in policyDef:
            self.delData(k)

        ''' 5b. lookup for the policy definition'''
        params = {
            'name' : 'enrollPolicy',
            }
        resp = self.make_system_request('getPolicy', params)
        res = ('"action": "maxtoken=3' in resp)
        assert res == False

        ''' 5c. reset replication '''
        params = {
            'key': 'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        assert('"delConfig enableReplication": true' in resp)


        return

##eof##########################################################################


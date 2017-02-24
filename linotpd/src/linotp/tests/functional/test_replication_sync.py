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
import random
from datetime import datetime
from datetime import timedelta

try:
    import json
except ImportError:
    import simplejson as json


from sqlalchemy.engine import create_engine
import sqlalchemy

from linotp.tests import TestController

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

        self.connection.execute(t, key=key, value=value, typ=typ,
                                description=description)
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

        self.sqlconnect = self.appconf.get('sqlalchemy.url')
        sqlData = SQLData(connect=self.sqlconnect)
        log.debug(sqlData)
        params = {
            'key': 'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        self.assertTrue('"delConfig enableReplication": true' in resp)
        return

    def tearDown(self):
        ''' Overwrite parent tear down, which removes all realms '''
        return

    def addData(self, key, value, description):

        sqlData = SQLData(connect=self.sqlconnect)
        typ = type(value).__name__
        sqlData.addData(key, value, typ, description)
        sec = random.randrange(1, 9)
        sqlData.updateData("linotp.Config",
                           str(datetime.now() + timedelta(milliseconds=sec)))
        sqlData.close()

        return

    def delData(self, key):

        sqlData = SQLData(connect=self.sqlconnect)
        sqlData.delData(key)

        sec = random.randrange(1, 9)
        sqlData.updateData("linotp.Config",
                           str(datetime.now() + timedelta(milliseconds=sec)))
        sqlData.close()

        return

    def addToken(self, user):

        params = {
            'user': user,
            'pin': user,
            'serial': 's' + user,
            'type': 'spass',
            }
        response = self.make_admin_request('init', params)
        self.assertTrue('"status": true,' in response)

        return

    def authToken(self, user):

        param = {'user': user, 'pass': user}
        response = self.make_validate_request('check', params=param)
        return response

    def showTokens(self):

        response = self.make_admin_request('show', {})
        self.assertTrue('"status": true,' in response)
        return response

    def set_caching(self, enable=True):
        """

        """
        caches = ["user_lookup_cache.enabled",
                  "resolver_lookup_cache.enabled"]

        enable_str = "False"
        if enable:
            enable_str = "True"

        for cache in caches:

            params = {cache: enable_str}
            response = self.make_system_request('setConfig', params)
            msg = '"setConfig %s:%s": true' % (cache, enable_str)
            self.assertTrue(msg in response, response)

    def set_cache_expiry(self, expiration):

        caches = ["user_lookup_cache.expiration",
                  "resolver_lookup_cache.expiration"]

        for cache in caches:

            params = {cache: expiration}
            response = self.make_system_request('setConfig', params)
            msg = '"setConfig %s:%s": true' % (cache, expiration)
            self.assertTrue(msg in response, response)

        return

    def test_replication(self):
        '''
            test replication of an simple config entry

            Description:
            - put LinOtp in replication aware mode
            - add a new entry in the Config Data vi SQL + update the timestamp
            - query the Config (system/getConfig, which should show the entry

            - del a entry in the Config Data vi SQL + update the timestamp
            - query the Config (system/getConfig, which should show the
              entry no more

        '''
        # 0.
        params = {
            'enableReplication': 'true',
            }
        resp = self.make_system_request('setConfig', params)
        self.assertTrue('"setConfig enableReplication:true": true' in resp)

        # 1.
        self.addData('replication', 'test1', 'test data')

        # 2.
        resp = self.make_system_request('getConfig', {})
        self.assertTrue('"replication": "test1"' in resp)

        # 3.
        self.delData('replication')

        # 4.
        resp = self.make_system_request('getConfig', {})
        self.assertTrue('"replication": "test1"' not in resp)

        # 5 - cleanup
        params = {
            'key': 'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        self.assertTrue('"delConfig enableReplication": true' in resp)

        return

    def test_replication_2(self):
        '''
            test 'no' replication, when 'enableReplication' entry is not set

            Description:
            - put LinOtp in replication aware mode
            - add a new entry in the Config Data vi SQL + update the timestamp
            - query the Config (system/getConfig, which should show the entry

            - del a entry in the Config Data vi SQL + update the timestamp
            - query the Config (system/getConfig, which should show the
              entry no more

        '''
        # 0.
        self.addData('replication', 'test1', 'test data')

        # 1.
        resp = self.make_system_request('getConfig', {})
        self.assertTrue('"replication": "test1"' not in resp, resp)

        # 2.
        params = {'enableReplication': 'true'}
        resp = self.make_system_request('setConfig', params)
        self.assertTrue('"setConfig enableReplication:true": true' in resp)

        # 3.
        self.delData('replication')

        # 3.
        resp = self.make_system_request('getConfig', {})
        self.assertTrue('"replication": "test1"' not in resp, resp)

        self.addData('replication', 'test1', 'test data')

        # 4.
        resp = self.make_system_request('getConfig', {})
        self.assertTrue('"replication": "test1"' in resp, resp)

        # 4b
        self.delData('replication')

        resp = self.make_system_request('getConfig', {})
        self.assertTrue('"replication": "test1"' not in resp, resp)

        # 5 - cleanup
        params = {
            'key': 'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        self.assertTrue('"delConfig enableReplication": true' in resp)

        return

    def updateResolver_test(self):
        '''
            test replication with resolver update

        '''
        umap = {"userid": "id",
                "username": "user",
                "phone": "telephoneNumber",
                "mobile": "mobile",
                "email": "mail",
                "surname": "sn",
                "givenname": "givenName",
                "password": "password",
                "salt": "salt"}

        sqlResolver = {
            "sqlresolver.conParams.mySQL": None,
            "sqlresolver.Where.mySQL": None,
            "sqlresolver.Limit.mySQL": "20",
            "sqlresolver.User.mySQL": "user",
            "sqlresolver.Database.mySQL": "yourUserDB",
            "sqlresolver.Password.mySQL": ("157455c27f605ad309d6059e1d936a4"
                                           "e:7a812ba9e613fb931386f5f4"
                                           "fb025890"),
            "sqlresolver.Table.mySQL": "usertable",
            "sqlresolver.Server.mySQL": "127.0.0.1",
            "sqlresolver.Driver.mySQL": "mysql",
            "sqlresolver.Encoding.mySQL": None,
            "sqlresolver.Port.mySQL": "3306",
            "sqlresolver.Map.mySQL": json.dumps(umap)

            }
        for k in sqlResolver:
            self.delData(k)

        # 0.
        params = {
            'enableReplication': 'true',
            }
        resp = self.make_system_request('setConfig', params)
        self.assertTrue('"setConfig enableReplication:true": true' in resp)

        for k in sqlResolver:
            self.addData(k, sqlResolver.get(k), '')

        params = {
            'resolver': 'mySQL',
            }
        resp = self.make_system_request('getResolver', params)
        self.assertTrue('"Database": "yourUserDB"' in resp)

        for k in sqlResolver:
            self.delData(k)

        params = {
            'resolver': 'mySQL',
            }
        resp = self.make_system_request('getResolver', params)
        self.assertTrue('"data": {}' in resp)

        # 5 - cleanup
        params = {
            'key': 'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        self.assertTrue('"delConfig enableReplication": true' in resp)

        return

    def updateRealm_test(self):
        '''
            test replication with realm and resolver update
        '''
        realmDef = {
            "linotp.useridresolver.group.realm":
                "useridresolver.PasswdIdResolver.IdResolver.resolverTest",
            "linotp.passwdresolver.fileName.resolverTest": "/etc/passwd",
            "linotp.DefaultRealm": "realm",
            }

        for k in realmDef:
            self.delData(k)

        params = {
            'enableReplication': 'true',
            }
        resp = self.make_system_request('setConfig', params)
        self.assertTrue('"setConfig enableReplication:true": true' in resp)

        resp = self.make_system_request('getRealms', {})
        self.assertTrue('"realmname": "realm"' not in resp, resp)

        for k in realmDef:
            self.addData(k, realmDef.get(k), '')

        resp = self.make_system_request('getRealms', {})
        self.assertTrue('"realmname": "realm"' in resp, resp)

        # 5 - cleanup
        for k in realmDef:
            self.delData(k)

        resp = self.make_system_request('getRealms', {})
        self.assertTrue('"realmname": "realm"' not in resp, resp)

        params = {
            'key': 'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        self.assertTrue('"delConfig enableReplication": true' in resp)

        return

    def test_auth_updateRealm(self):
        '''
          test resolver and realm update with authentication

          0. delete all related data
          1. enable replication
          2. write sql data
          3. lookup for the realm definition
          4. enroll token and auth for user passthru_user1
          5. add new resolver definition
          6. check that user in the realm is not defined
          7. lookup for the realm definition
          8. add resolver definition again
          9. check that user is defined in realm again
          10. cleanup
          11. lookup if the realm definition is removed
          12. disable replication

        '''
        self.create_common_resolvers()
        self.create_common_realms()

        res_group = {
                "resolverTest":
                "useridresolver.PasswdIdResolver.IdResolver.resolverTest",
                "myDefRes":
                "useridresolver.PasswdIdResolver.IdResolver.myDefRes",
                }

        realmDef = {
            "linotp.passwdresolver.fileName.resolverTest": "/etc/passwd",
            "linotp.useridresolver.group.realm":
                "useridresolver.PasswdIdResolver.IdResolver.myDefRes",
            "linotp.DefaultRealm": "realm",
            }

        realmDef["linotp.useridresolver.group.realm"] = ','.join(res_group.values())

        # 0. delete all related data
        for k in realmDef:
            self.delData(k)

        # 1. switch on replication
        params = {
            'enableReplication': 'true',
            }
        resp = self.make_system_request('setConfig', params)
        self.assertTrue('"setConfig enableReplication:true": true' in resp)

        # 1.b check that realm is not defined
        resp = self.make_system_request('getRealms', {})
        self.assertTrue('"realmname": "realm"' not in resp, resp)

        # 2  write sql data
        for k in realmDef:
            self.addData(k, realmDef.get(k), '')

        # 3. lookup for the realm definition
        resp = self.make_system_request('getRealms', {})
        self.assertTrue('"realmname": "realm"' in resp, resp)

        # 4. enroll token and auth for user passthru_user1
        self.addToken('passthru_user1')
        res = self.authToken('passthru_user1')
        self.assertTrue('"value": true' in res)

        # 5. set new resolver definition
        realmDef["linotp.useridresolver.group.realm"] = res_group["resolverTest"]
        for key, value in realmDef.items():
            self.delData(key)
            self.addData(key, value, '')

        # 6. check that user in the realm is not defined
        res = self.authToken('passthru_user1')
        self.assertTrue('"value": false' in res)

        # 7. lookup for the realm definition
        resp = self.make_system_request('getRealms',)
        self.assertTrue('"realmname": "realm"' in resp, resp)
        self.assertTrue("resolverTest" in resp, resp)

        # 8. add new resolver definition again
        realmDef["linotp.useridresolver.group.realm"] = res_group["myDefRes"]
        for key, value in realmDef.items():
            self.delData(key)
            self.addData(key, value, '')

        # 9. check that user is defined in realm again
        res = self.authToken('passthru_user1')
        self.assertTrue('"value": true' in res)

        # 10. cleanup
        for k in realmDef:
            self.delData(k)

        # 11. lookup if the realm definition is removed
        resp = self.make_system_request('getRealms', {})
        self.assertTrue('"realmname": "realm"' not in resp, resp)

        # 12. disable replication
        params = {
            'key': 'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        self.assertTrue('"delConfig enableReplication": true' in resp)

        return

    def test_policy(self):
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

        # 0 - cleanup
        params = {
            'key': 'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        self.assertTrue('"delConfig enableReplication": true' in resp)

        for k in policyDef:
            self.delData(k)

        # 1. switch on replication
        params = {
            'enableReplication': 'true',
            }
        resp = self.make_system_request('setConfig', params)
        self.assertTrue('"setConfig enableReplication:true": true' in resp,
                        resp)

        # 2  write sql data
        for k in policyDef:
            self.addData(k, policyDef.get(k), '')

        # 3. getPolicy
        params = {
            'name': 'enrollPolicy',
            }
        resp = self.make_system_request('getPolicy', params)
        self.assertTrue('"action": "maxtoken=3' in resp)

        # 4. cleanup
        for k in policyDef:
            self.delData(k)

        # 4b. lookup for the policy definition
        params = {
            'name': 'enrollPolicy',
            }
        resp = self.make_system_request('getPolicy', params)
        res = ('"action": "maxtoken=3' in resp)
        self.assertTrue(res is False, resp)

        # 4c. reset replication
        params = {
            'key': 'enableReplication',
            }
        resp = self.make_system_request('delConfig', params)
        self.assertTrue('"delConfig enableReplication": true' in resp)

        return

    def test_updateRealm_with_caching(self):
        """
        test replication with realm and resolver update  with caching enabled
        """

        self.set_caching(enable=True)
        self.set_cache_expiry(expiration='3 hours')

        try:
            self.updateRealm_test()

        finally:
            self.set_caching(enable=False)

        return

    def test_updateRealm_wo_caching(self):
        """
        test replication with realm and resolver update  with caching disabled
        """
        self.set_caching(enable=False)
        self.updateRealm_test()

        return

    def test_caching_expiration_value(self):
        """
        test replication with resolver update with caching enabled
        """

        self.set_caching(enable=True)

        with self.assertRaises(AssertionError) as ass_err:
            self.set_cache_expiry(expiration='3600 xx')

        error_message = ass_err.exception.message
        self.assertTrue("must be of type 'duration'" in error_message)

        with self.assertRaises(AssertionError) as ass_err:
            self.set_cache_expiry(expiration='3w10')

        error_message = ass_err.exception.message
        self.assertTrue("must be of type 'duration'" in error_message)

        with self.assertRaises(AssertionError) as ass_err:
            self.set_cache_expiry(expiration='3600 years')

        error_message = ass_err.exception.message
        self.assertTrue("must be of type 'duration'" in error_message)

        self.set_cache_expiry(expiration='3600 seconds')
        self.set_cache_expiry(expiration=3600)
        self.set_cache_expiry(expiration='3600')
        self.set_cache_expiry(expiration='3600 s')
        self.set_cache_expiry(expiration='3 hours')

        self.set_cache_expiry(expiration='3 weeks 5 days')
        self.set_cache_expiry(expiration='180 minutes')

        self.set_cache_expiry(expiration='1h 20 minutes 90 s')
        return

    def test_updateResolver_with_caching(self):
        """
        test replication with resolver update with caching enabled
        """

        self.set_caching(enable=True)
        self.set_cache_expiry(expiration='3600 seconds')

        try:
            self.updateResolver_test()

        finally:
            self.set_caching(enable=False)

        return

    def test_updateResolver_wo_caching(self):
        """
        test replication with resolver update with caching disabled
        """
        self.set_caching(enable=False)
        self.updateResolver_test()

        return


# eof #########################################################################

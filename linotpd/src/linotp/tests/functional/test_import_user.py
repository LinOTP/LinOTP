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


"""
Testing the import of users, which should generate
- an sql table for the users
- an sql resolver (readonly)
- import the users

during the user import it is checked, if the
- user already exists or
- if it is updated or,
- in case of a former existing user, the user will be deleted

the check is made by a dryrun

- test simple csv import
- create realm, containing the resolver with
  - testconnection
  - userlist
  - update of the resolver parameters

- delete the resolver on test end

"""

import os
import json
import logging

# for drop Table we require some sql

from sqlalchemy.engine import create_engine
from sqlalchemy import sql
from sqlalchemy.exc import ProgrammingError

from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestImportUser(TestController):

    resolver_name = "myresolv"
    target_realm = "myrealm"
    resolver_spec = ('useridresolver.'
                     'SQLIdResolver.'
                     'IdResolver.' + resolver_name)

    def setUp(self):

        self.delete_all_realms()
        self.delete_all_policies()
        self.delete_all_resolvers()
        self.dropTable()

        TestController.setUp(self)

    def dropTable(self):
        """
        for the tests, we will drop the imported user table
        """

        sqlconnect = self.appconf.get('sqlalchemy.url')
        engine = create_engine(sqlconnect)
        connection = engine.connect()

        # we try to delete the table if it exists

        try:

            dropStr = "DROP TABLE imported_user;"
            t = sql.expression.text(dropStr)
            connection.execute(t)

        except ProgrammingError as exx:

            log.info("Drop Table failed %r", exx)

        except Exception as exx:

            log.info("Drop Table failed %r", exx)

    def test_import_user(self):
        """
        check that import users will create. update and delete users
        """

        content = ""
        upload_files = [("file", "user_list", content)]
        params = {'resolver': self.resolver_name,
                  'dryrun': False,
                  'format': 'password',
                  'delimiter': ',',
                  'quotechar': '"',
                  }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"updated": {}' in response, response)
        self.assertTrue('"created": {}' in response, response)

        def_passwd_file = os.path.join(self.fixture_path, 'def-passwd')

        with open(def_passwd_file, "r") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]
        params = {'resolver': self.resolver_name,
                  'dryrun': False,
                  'format': 'password',
                  'delimiter': ',',
                  'quotechar': '"',
                  }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"updated": {}' in response, response)
        jresp = json.loads(response.body)
        created = jresp.get('result', {}).get('value', {}).get('created', {})
        self.assertTrue(len(created) == 25, response)

        csv_data = content.split('\n')[4:]
        content = '\n'.join(csv_data)
        upload_files = [("file", "user_list", content)]

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        jresp = json.loads(response.body)
        deleted = jresp.get('result', {}).get('value', {}).get('deleted', {})
        self.assertTrue(len(deleted) == 4, response)

        updated = jresp.get('result', {}).get('value', {}).get('updated', {})
        self.assertTrue(len(updated) == 21, response)

        self.assertTrue('"created": {}' in response, response)

        return

    def test_import_user_dryrun(self):
        """
        check that the dryrun does not import a user
        """

        def_passwd_file = os.path.join(self.fixture_path, 'def-passwd')

        with open(def_passwd_file, "r") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]
        params = {'resolver': self.resolver_name,
                  'dryrun': True,
                  'format': 'password',
                  'delimiter': ',',
                  'quotechar': '"',
                  }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"updated": {}' in response, response)

        jresp = json.loads(response.body)
        created = jresp.get('result', {}).get('value', {}).get('created', {})
        self.assertTrue(len(created) == 25, response)

        upload_files = [("file", "user_list", content)]
        params = {'resolver': self.resolver_name,
                  'dryrun': True,
                  'format': 'password',
                  'delimiter': ',',
                  'quotechar': '"',
                  }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"updated": {}' in response, response)

        jresp = json.loads(response.body)
        created = jresp.get('result', {}).get('value', {}).get('created', {})
        self.assertTrue(len(created) == 25, response)

        # make sure that no resolver has been created on dryrun

        params = {'resolver': self.resolver_name}
        response = self.make_system_request('getResolver', params=params)
        self.assertTrue('"data": {}' in response, response)

        # make sure that no realm has been created on dryrun

        params = {}
        response = self.make_system_request('getRealms', params=params)
        self.assertTrue('"value": {}' in response, response)

    def test_list_imported_users(self):
        """
        list the csv imported users in testresolver and with admin userlist
        """

        # ------------------------------------------------------------------ --

        # open the csv data and import the users

        def_passwd_file = os.path.join(self.fixture_path, 'def-passwd.csv')

        with open(def_passwd_file, "r") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]

        column_mapping = {
                "username": 0,
                "userid": 1,
                "surname": 2,
                "givenname": 3,
                "email": 4,
                "phone": 5,
                "mobile": 6,
                "password": 7}

        params = {
                'resolver': self.resolver_name,
                'dryrun': False,
                'format': 'csv',
                'delimiter': ',',
                'quotechar': '"',
                'column_mapping': json.dumps(column_mapping), }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"updated": {}' in response, response)

        jresp = json.loads(response.body)
        created = jresp.get('result', {}).get('value', {}).get('created', {})
        self.assertTrue(len(created) == 24, response)

        # ------------------------------------------------------------------ --

        # run a testresolver, if the users are really there

        params = {'resolver': self.resolver_name}
        response = self.make_system_request('getResolver', params=params)
        jresp = json.loads(response.body)

        resolver_params = jresp.get(
                                'result', {}).get('value', {}).get('data', {})

        resolver_params['Password'] = ''
        resolver_params['type'] = 'sqlresolver'
        resolver_params['name'] = self.resolver_name
        resolver_params['previous_name'] = self.resolver_name
        response = self.make_admin_request('testresolver',
                                           params=resolver_params)

        jresp = json.loads(response.body)
        rows = jresp.get(
                    'result', {}).get(
                    'value', {}).get(
                    'desc', {}).get(
                    'rows', {})

        self.assertTrue(rows == 24)

        # ------------------------------------------------------------------ --

        # create a realm for this resolver and do a userlist

        params = {'realm': 'myrealm', 'resolvers': self.resolver_spec}
        response = self.make_system_request(action='setRealm',  params=params)

        resolver_id = self.resolver_spec.split('.')[-1]
        params = {'resConf': resolver_id, 'username': '*'}
        response = self.make_admin_request(action='userlist', params=params)

        jresp = json.loads(response.body)
        users = jresp.get('result', {}).get('value', [])
        self.assertTrue(len(users) == 24, users)

        # ------------------------------------------------------------------ --

        # login to the selfservice and enroll an HMAC token

        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': '*',
                  'realm': '*',
                  'scope': 'selfservice', }

        response = self.make_system_request('setPolicy', params=policy)

        # for passthru_user1 do check if policy is defined
        auth_user = ('passthru_user1@' + self.target_realm, 'geheim1')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        jresp = json.loads(response.body)
        img = jresp.get('detail', {}).get('googleurl', {}).get('img', '')

        self.assertTrue("data:image" in img, response)

        return

    def test_import_user_policy(self):
        """
        check that import users is policy protected
        """

        policy = {'name': 'user_import',
                  'action': 'import_users',
                  'user': 'hans',
                  'realm': '*',
                  'scope': 'tools', }

        response = self.make_system_request('setPolicy', params=policy)

        self.assertTrue('"status": true' in response)

        content = ""
        upload_files = [("file", "user_list", content)]
        params = {
                  'resolver': self.resolver_name,
                  'dryrun': False,
                  'format': 'password',
                  'delimiter': ',',
                  'quotechar': '"',
                  }

        msg = ("You do not have the administrative right to manage tools."
               " You are missing a policy scope=tools, action=import_users")

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files,)

        self.assertTrue(msg in response, response)

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files,
                                           auth_user='hans')

        self.assertFalse(msg in response, response)
        self.assertTrue('"updated": {}' in response, response)
        self.assertTrue('"created": {}' in response, response)

        return

    def test_imported_with_plain_passwords(self):
        """
        list the csv imported users with plain passwords
        """

        # ------------------------------------------------------------------ --

        # open the csv data and import the users

        def_passwd_file = os.path.join(self.fixture_path,
                                       'def-passwd-plain.csv')

        with open(def_passwd_file, "r") as f:
            content = f.read()

        upload_files = [("file", "user_list", content)]

        column_mapping = {
                "username": 0,
                "userid": 1,
                "surname": 2,
                "givenname": 3,
                "email": 4,
                "phone": 5,
                "mobile": 6,
                "password": 7}

        params = {
                'resolver': self.resolver_name,
                'passwords_in_plaintext': True,
                'dryrun': False,
                'format': 'csv',
                'delimiter': ',',
                'quotechar': '"',
                'column_mapping': json.dumps(column_mapping), }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"updated": {}' in response, response)

        jresp = json.loads(response.body)
        created = jresp.get('result', {}).get('value', {}).get('created', {})
        self.assertTrue(len(created) == 24, response)

        # upload one more times to check for update and not modified

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        self.assertTrue('"modified": {}' in response, response)

        jresp = json.loads(response.body)
        updated = jresp.get('result', {}).get('value', {}).get('updated', {})
        self.assertTrue(len(updated) == 24, response)

        # login to the selfservice to check the password
        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': '*',
                  'realm': '*',
                  'scope': 'selfservice', }

        response = self.make_system_request('setPolicy', params=policy)

        setRealmParams = {
            'realm': 'newrealm',
            'resolvers': self.resolver_spec
        }

        response = self.make_system_request(action='setRealm',
                                            params=setRealmParams
                                            )

        # for passthru_user1 do check if policy is defined
        auth_user = ('root', 'root')

        params = {'type': 'hmac', 'genkey': '1', 'serial': 'hmac123'}
        response = self.make_userservice_request('enroll',
                                                 params=params,
                                                 auth_user=auth_user)
        jresp = json.loads(response.body)
        img = jresp.get('detail', {}).get('googleurl', {}).get('img', '')

        self.assertTrue("data:image" in img, response)

        return

# eof ########################################################################

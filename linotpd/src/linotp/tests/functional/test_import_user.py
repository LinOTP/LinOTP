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

the check could be made by a dryrun

TODO:
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

    group_id = 'import_user'
    resolver_name = "user_import"

    def setUp(self):

        self.delete_all_policies()
        self.deleteResolver(self.resolver_name)
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

    def deleteResolver(self, resolver_name):

        params = {"resolver": resolver_name}
        resp = self.make_system_request('delResolver', params)
        self.assertTrue('"status": true' in resp)

    def delete_users(self, groupid):
        """
        delete of the users could only be done by an update of the user
        with an empty file
        """

        content = ""
        upload_files = [("file", "user_list", content)]
        params = {'groupid': groupid,
                  'resolver': 'user_import',
                  'dryrun': False,
                  'format': 'password',
                  'delimiter': ',',
                  'quotechar': '"',
                  }

        response = self.make_tools_request(action='import_users',
                                           params=params,
                                           upload_files=upload_files)

        return response

    def test_0000_import_user(self):
        """
        check that import users will create. update and delete users
        """

        content = ""
        upload_files = [("file", "user_list", content)]
        params = {'groupid': self.group_id,
                  'resolver': 'user_import',
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
        params = {'groupid': self.group_id,
                  'resolver': 'user_import',
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
        self.assertTrue(len(created) == 24, response)

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
        self.assertTrue(len(updated) == 20, response)

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
        params = {'groupid': self.group_id,
                  'resolver': 'user_import',
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
        self.assertTrue(len(created) == 24, response)

        upload_files = [("file", "user_list", content)]
        params = {'groupid': self.group_id,
                  'resolver': 'user_import',
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
        self.assertTrue(len(created) == 24, response)

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
                'groupid': self.group_id,
                'resolver': 'csv_user_import',
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

        params = {'resolver': 'csv_user_import'}
        response = self.make_system_request('getResolver', params=params)
        jresp = json.loads(response.body)

        resolver_params = jresp.get(
                            'result', {}).get(
                            'value', {}).get(
                            'data', {})

        resolver_params['Password'] = ''
        resolver_params['type'] = 'sqlresolver'
        resolver_params['name'] = 'csv_user_import'
        resolver_params['previous_name'] = 'csv_user_import'
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

        reasolver_spec = ('useridresolver.'
                          'SQLIdResolver.'
                          'IdResolver.' + 'csv_user_import')

        response = self.create_realm('IMPO', [reasolver_spec])
        self.assertTrue('"status": true' in response, response)

        params = {'realm': 'IMPO', 'username': '*'}
        response = self.make_admin_request(action='userlist', params=params)

        jresp = json.loads(response.body)
        users = jresp.get('result', {}).get('value', [])
        self.assertTrue(len(users) == 24, users)

        # ------------------------------------------------------------------ --

        # login to the selfservice and enroll an HMAC token

        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': '*',
                  'realm': 'IMPO',
                  'scope': 'selfservice', }

        response = self.make_system_request('setPolicy', params=policy)

        # for passthru_user1 do check if policy is defined
        auth_user = ('passthru_user1@IMPO', 'geheim1')

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
                  'realm': 'IMPO',
                  'scope': 'tools', }

        response = self.make_system_request('setPolicy', params=policy)

        self.assertTrue('"status": true' in response)

        content = ""
        upload_files = [("file", "user_list", content)]
        params = {'groupid': self.group_id,
                  'resolver': 'user_import',
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
                'resolver': self.group_id,
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

        # create a realm for this resolver and do a userlist

        reasolver_spec = ('useridresolver.'
                          'SQLIdResolver.'
                          'IdResolver.' + self.group_id)

        response = self.create_realm('IMPO', [reasolver_spec])
        self.assertTrue('"status": true' in response, response)

        # login to the selfservice to check the password

        policy = {'name': 'T1',
                  'action': 'enrollHMAC',
                  'user': '*',
                  'realm': 'IMPO',
                  'scope': 'selfservice', }

        response = self.make_system_request('setPolicy', params=policy)

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

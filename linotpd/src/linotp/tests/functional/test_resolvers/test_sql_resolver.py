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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

"""
sql resolver tests
"""

import logging
import json
import pytest

from .sql_test_controller import SQLTestController

log = logging.getLogger(__name__)


@pytest.mark.exclude_sqlite
class SQLResolverTest(SQLTestController):

    def setUp(self):
        """ create an sql user table some users and the sql resolver """

        self.delete_all_policies()
        SQLTestController.setUp(self)
        self.setUpSQL()

        return

    def tearDown(self):
        """ drop the users and the user table """

        self.dropUsers()
        self.delete_all_token()
        self.delete_all_policies()

        return SQLTestController.tearDown(self)

    def test_sqlresolver_with_uid_as_int(self):
        """
        test that we can use an sql resolver with the uid defined as int
        """

        user = 'hey1'
        serial = 'sql_hmac_test_token'
        realm = 'sqlRealm'

        # ------------------------------------------------------------------ --

        # create the User schema with id field as integer

        self.createUserTable(schema_additions={'id': 'integer'})

        # ------------------------------------------------------------------ --

        self.addUsers(usercount=2)

        # ------------------------------------------------------------------ --

        # define resolver and realm
        response = self.make_system_request('getRealms',params={})

        if realm.lower() not in response.json['result']['value']:
            self.addSqlResolver('my_sql_users')
            self.addSqlRealm(realm, 'my_sql_users', defaultRealm=True)

        # ------------------------------------------------------------------ --

        # create token for user 'hey1'

        params = {
            'type': 'hmac',
            'genkey': 1,
            'user': user,
            'realm': realm,
            'serial': serial,
            'pin': 'mypin'
        }
        response = self.make_admin_request('init', params=params)

        assert 'false' not in response.body, response

        # ------------------------------------------------------------------ --

        # create the required selfservice policy

        params = {
            'name': 'my_selfservice_pol',
            'action': 'reset',
            'scope': 'selfservice',
            'user': '*',
            'realm': '*',
            }

        response = self.make_system_request('setPolicy', params=params)
        assert 'false' not in response.body

        # ------------------------------------------------------------------ --

        # run a wrong login, so that the token failcount increments

        params = {
            'user': user,
            'pass': 'mypin123456'
            }

        response = self.make_validate_request('check', params=params)
        assert '"value": false' in response

        # ------------------------------------------------------------------ --

        # verify that the token count is incremented to 1

        params = {
            'serial': serial
            }

        response = self.make_admin_request('show', params=params)
        jresp = json.loads(response.body)
        token_info = jresp.get(
            'result', {}).get(
                'value', {}).get(
                    'data',[{}])[0]
        assert token_info.get( "LinOtp.FailCount", -1) == 1

        # ------------------------------------------------------------------ --

        # now login to the selfservice and run the token reset

        auth_user = {'login': user,
                     'realm': realm,
                     'password': 'geheim1'}

        params = {'serial': serial}

        response = self.make_userselfservice_request('reset',
                                                     params=params,
                                                     auth_user=auth_user,
                                                     new_auth_cookie=True)

        assert 'false' not in response, response

        # ------------------------------------------------------------------ --

        # verify that the token count is reset to 0

        params = {
            'serial': serial
            }

        response = self.make_admin_request('show', params=params)
        jresp = json.loads(response.body)
        token_info = jresp.get(
            'result', {}).get(
                'value', {}).get(
                    'data',[{}])[0]
        assert token_info.get( "LinOtp.FailCount", -1) == 0

        return

# eof

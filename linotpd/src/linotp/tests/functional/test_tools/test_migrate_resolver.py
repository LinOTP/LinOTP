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
Testing the migration of tokens from one resolver to a different one

- constrain is, that the user must exist in both resolvers with same uid

"""

import os
import json
import logging

from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestImportUser(TestController):

    resolver_name = "myresolv"
    target_realm = "myrealm"
    resolver_spec = ('useridresolver.'
                     'SQLIdResolver.'
                     'IdResolver.' + resolver_name)

    def setUp(self):

        self.create_common_resolvers()
        self.create_common_realms()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_token()

        TestController.setUp(self)

    def test_migrate_token(self):
        """
        test if tokens could be migrated from one resolver to a different one.

        remark:
        usecase for token migration is, that the user moved to a different
        resolver but the realm stays the same in the first place

        1. create two resolvers with identical users
        2. create realm for resolvers
        2. create tokens assigened to a user in the first realm
        3. migrate tokens
        4. check if token now belongs to user in the second resolver

        """

        resolver_param = {
            'name': 'black1',
            'fileName': (os.path.join(self.fixture_path, 'def-passwd')),
            'type': 'passwdresolver'}

        response = self.make_system_request('setResolver',
                                            params=resolver_param)

        content = json.loads(response.body)
        self.assertTrue(content['result']['status'])

        resolver_param = {
            'name': 'black2',
            'fileName': (os.path.join(self.fixture_path, 'def-passwd')),
            'type': 'passwdresolver'}

        response = self.make_system_request('setResolver',
                                            params=resolver_param)

        content = json.loads(response.body)
        self.assertTrue(content['result']['status'])

        response = self.create_realm('black', [
            'useridresolver.PasswdIdResolver.IdResolver.black1'])

        params = {'type': 'hmac',
                  'serial': 'migration_token',
                  'user': 'passthru_user1@black',
                  'genkey': '1'
                  }

        response = self.make_admin_request('init', params)

        response = self.create_realm('black', [
            'useridresolver.PasswdIdResolver.IdResolver.black1',
            'useridresolver.PasswdIdResolver.IdResolver.black2'])

        # run the migration

        params = {
            'from': 'black1',
            'to': 'black2'}

        response = self.make_tools_request(action='migrate_resolver',
                                           params=params)

        self.assertTrue('1 tokens of 1 migrated' in response, response)

        # verify the tokens in the token list
        params = {'resConf': 'black2'}
        response = self.make_admin_request('show', params)
        jresp = json.loads(response.body)

        token = jresp.get('result', {}).get('value', {}).get('data', [])[0]

        self.assertTrue('black2' in token.get('LinOtp.IdResClass'))
        self.assertTrue(token['LinOtp.TokenSerialnumber'] == 'migration_token')

        return

# eof ########################################################################

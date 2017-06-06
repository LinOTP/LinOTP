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
"""
import json
from linotp.tests import TestController


class TestTokensearch(TestController):
    '''
    test the search on a token list
    '''
    serials = []

    def setUp(self):
        ''' setup the Test Controller'''
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        ''' make the dishes'''
        self.remove_tokens()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)
        return

    def remove_tokens(self):
        '''
        remove all tokens, which are in the internal array of serial

        :return: - nothing -
        '''
        for serial in self.serials:
            param = {"serial": serial}
            response = self.make_admin_request('remove', params=param)
            self.assertTrue('value' in response)

        return

    def test_singel_character_wildcard_search(self):
        """ single char wildcard test for user lookup in token view"""

        # ------------------------------------------------------------------ --

        response = self.make_system_request(
                    'getConfig',
                    params={'key': 'splitAtSign'})

        jresp = json.loads(response.body)
        splitAtSig = jresp.get(
                        'result', {}).get(
                            'value', {}).get(
                                'getConfig splitAtSig')

        # ------------------------------------------------------------------ --

        response = self.make_system_request(
                    'setConfig',
                    params={'splitAtSign': 'false'})

        msg = '"setConfig splitAtSign:false": true'

        self.assertTrue(msg in response)

        # create token
        params = {'type': 'spass',
                  'user': 'pass.thru@example.com'}

        response = self.make_admin_request('init', params=params)
        self.assertTrue('serial' in response)

        jresp = json.loads(response.body)
        serial = jresp.get('detail', {}).get('serial', '')
        if serial:
            self.serials.append(serial)

        # search for token which belong to a certain user
        params = {'user': 'pass.thru@example.com'}
        response = self.make_admin_request('show', params=params)
        self.assertTrue(serial in response)

        # search with wildcard for token which belong to a certain user
        params = {'user': 'pass*thru@example.com'}
        response = self.make_admin_request('show', params=params)
        self.assertTrue(serial in response)

        # ----------------------------------------------------------------- --

        if splitAtSig is None:
            response = self.make_system_request(
                        'delConfig', params={'key': 'splitAtSign'})

        else:
            response = self.make_system_request(
                        'setConfig',
                        params={'splitAtSign': splitAtSig})

        # ----------------------------------------------------------------- --
        return

# eof #

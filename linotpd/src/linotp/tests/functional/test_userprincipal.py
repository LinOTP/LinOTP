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
Verify LinOTP for UserPrincipal (user@domain) authentication

the test will create a static-password token, and
will try to verify the user in different situations.
"""
import logging
import json

from linotp.tests import TestController

log = logging.getLogger(__name__)


class TestUserPrincipalController(TestController):

    def setUp(self):
        self.tokens = {}
        TestController.setUp(self)
        self.set_config_selftest()
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        return TestController.tearDown(self)

    def test_userprincipal(self):
        """
        Verify LinOTP for UserPrincipal (user@domain) authentication

        the test will create a static-password token, and
        will try to verify the user in different situations.

        """
        params = {
            "key": 'splitAtSign'
            }
        response = self.make_system_request('getConfig', params=params)
        jresp = json.loads(response.body)
        splitAtSign = jresp.get('result', {}).get(
                                'value').get(
                                'getConfig splitAtSign', '')
        try:

            params = {
                'splitAtSign': False
                }
            response = self.make_system_request('setConfig', params=params)

            user = "pass@user"
            pin = "1234"
            realm = 'myDefRealm'
            serial = "F722362"
            # Initialize authorization (we need authorization in
            # token creation/deletion)...

            params = {
                   "realm": realm,
                   "serial": serial,
                   'pin': pin,
                   "otpkey": "AD8EABE235FC57C815B26CEF37090755",
                   "type": 'spass'
                    }

            # Create test token...
            response = self.make_admin_request('init', params=params)
            self.assertTrue(serial in response, response)

            # although not needed, we assign token...
            params = {
                'serial': serial,
                'user': user,
                'realm': realm
                }
            response = self.make_admin_request('assign', params=params)
            self.assertTrue('"status": true' in response, response)

            params = {
                'serial': serial,
                }

            response = self.make_admin_request('enable', params=params)
            self.assertTrue('"status": true' in response, response)

            # test user-principal authentication
            params = {
                'user': user,
                'pass': pin,
                'realm': realm
                }

            response = self.make_validate_request('check', params=params)

            params = {
                'serial': serial,
                }

            response = self.make_admin_request('remove', params=params)

        finally:

            # restore original state

            params = {
                'splitAtSign': splitAtSign
                }
            response = self.make_system_request('setConfig', params=params)

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
#

"""
test the helpdesk enrollment api
- list users
- enroll token
- list tokens of user
- user might be in one or more realms
"""

import json
from linotp.tests import TestController

class TestHelpdeskEnrollment(TestController):

    def setUp(self):
        """ setup for std resolver / realms"""

        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        """ clean up for all token and resolver / realms """

        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_token()
        self.delete_all_policies()

        TestController.tearDown(self)

    def test_list_users(self):
        """ test that 'api/helpdesk/users' endpoint honores admin policies """

        # define admin policy for helpdesk user 'helpdesk'

        policy = {
            'name': 'admin',
            'action': '*',
            'scope': 'admin',
            'active': True,
            'realm': '*',
            'user': 'superadmin, admin',
            'client': '*',
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not  in response

        policy = {
            'name': 'helpdesk',
            'action': 'show, userlist',
            'scope': 'admin',
            'active': True,
            'realm': 'mydefrealm',
            'user': 'helpdesk,',
            'client': '*',
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not  in response

        # ------------------------------------------------------------------ --

        # verify that the helpdesk user can see only users for the
        # specified realm

        params = {}

        response = self.make_helpdesk_request(
            'users', params=params)

        assert 'false' not in response


        jresp = json.loads(response.body)
        for user in jresp['result']['value']['rows']:
            user_parts = user['cell']
            realms = user_parts[8]
            assert 'mydefrealm' in realms
            assert len(realms) <= 1

        return



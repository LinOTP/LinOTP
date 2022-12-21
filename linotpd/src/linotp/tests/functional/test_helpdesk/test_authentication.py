# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
#

"""
test the authentication towards the helpdesk
- using the helpdesk session parameter
- getsession and dropsession api
"""

import json

from linotp.tests import TestController

from . import enable_helpdesk_controller
import pylons.test

class TestHelpdeskAuthorization(TestController):

    @classmethod
    def setup_class(cls):
        """add the helpdesk route to the test pylons app"""

        enable_helpdesk_controller(pylons.test.pylonsapp.config)

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

    def test_authorisation(self):
        """ connect to the helpdesk contoller """

        response = self.make_helpdesk_request('getsession')
        assert 'false' not in response

        cookies = self.get_cookies(response)

        assert 'helpdesk_session' in cookies

        session = cookies.get('helpdesk_session')

        params = {
            'session': session
            }

        response = self.make_helpdesk_request(
            'users', params=params, cookies=cookies)

        assert 'false' not in response

        params = {
            'session': session
            }

        self.set_cookie(self.app, 'helpdesk_session', session)

        response = self.make_helpdesk_request(
            'dropsession', params=params, cookies=cookies)

        assert 'false' not in response

        cookies = self.get_cookies(response)
        assert ' expires' in cookies
        assert cookies.get('helpdesk_session') == ''

# eof #

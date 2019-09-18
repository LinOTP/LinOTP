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
test for setPin
- pin as parameter
- random pin policy interaction
- random pin policy content
- test uses the pin message of the mocked smtp provider
"""

import json
import re
import os

from . import MockedSMTP

from linotp.tests import TestController


class TestHelpdeskSetPin(TestController):

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

    def test_setPin_admin_right(self):
        """verify that helpdesk can set pin according to the admin policies"""

        # ------------------------------------------------------------------ --

        # define the email provider

        email_config = {
            "SMTP_SERVER":"mail.example.com",
            "SMTP_USER":"secret_user",
            "SMTP_PASSWORD":"secret_pasword",
            "EMAIL_FROM":"linotp@example.com",
            "EMAIL_SUBJECT":"New token pin set"
        }

        params = {
            'name': 'setPinProvider',
            'class': 'linotp.provider.emailprovider.SMTPEmailProvider',
            'timeout': '120',
            'type': 'email',
            'config': json.dumps(email_config)
        }
        self.make_system_request('setProvider', params=params)

        # ------------------------------------------------------------------ --

        # define the notification provider policy

        policy = {
            'name': 'notify_enrollement',
            'action': 'setPin=email::setPinProvider ',
            'scope': 'notification',
            'active': True,
            'realm': '*',
            'user': '*',
            'client': '*',
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not  in response

        # ------------------------------------------------------------------ --

        # define admin policy which denies the enrollemt for the helpdesk user

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

        # define the restricted admin policy for helpdesk user 'helpdesk'

        policy = {
            'name': 'helpdesk',
            'scope': 'admin',
            'active': True,
            'user': 'helpdesk,',
            'action': 'setOTPPIN,',
            'realm': 'myotherrealm',
            'client': '*',
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not  in response

        # ------------------------------------------------------------------ --

        params = {
            'type': 'email',
            'user': 'hans',
            'realm': 'mydefrealm',
            'email_address': 'hans@example.com'
            }
        response = self.make_admin_request('init', params)
        assert 'false' not in response, response

        jresp = json.loads(response.body)
        serial = jresp['detail']['serial']

        # ------------------------------------------------------------------ --

        # enroll email token for hans has to fail as the helpdesk is not
        # allowed to enroll email token in the realm for hans

        with MockedSMTP() as mock_smtp_instance:

            mock_smtp_instance.sendmail.return_value = []

            params = {'serial': serial}
            response = self.make_helpdesk_request('setPin', params=params)

            assert 'not have the administrative right' in response, response

        # ------------------------------------------------------------------ --

        # now adjust the admin policy so that the helpdesk is allowed to enroll
        # email tokens in the realm mydefrealm as well

        policy = {
            'name': 'helpdesk',
            'scope': 'admin',
            'active': True,
            'user': 'helpdesk,',
            'action': 'setOTPPIN,',
            'realm': 'myotherrealm, mydefrealm',
            'client': '*',
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not  in response

        # ------------------------------------------------------------------ --

        # verify that the enrollment now is allowed

        with MockedSMTP() as mock_smtp_instance:

            mock_smtp_instance.sendmail.return_value = []

            params = {'serial': serial}
            response = self.make_helpdesk_request('setPin', params=params)

            assert 'have the administrative right' not in response, response
            assert serial in response, response

        return

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

from . import enable_helpdesk_controller
import pylons.test


class TestHelpdeskSetPin(TestController):

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

        # verify that the enrollment now is allowed and
        # the replacements are processed correctly for the default message

        with MockedSMTP() as mock_smtp_instance:

            mock_smtp_instance.sendmail.return_value = []

            params = {'serial': serial}
            response = self.make_helpdesk_request('setPin', params=params)

            assert 'have the administrative right' not in response, response
            assert serial in response, response

            call_args = mock_smtp_instance.sendmail.call_args
            _email_from, email_to, email_message = call_args[0]

            assert email_to == 'hans@example.com'
            assert (': new pin set for token ' + serial) in email_message
            assert ('been set for your token: ' + serial) in email_message

        return

    def test_setPin_random_pin(self):
        """verify: helpdesk setPin works according to the random policies"""

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

        # enroll token for hans via admin

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

        # verify that the enrollment now is allowed and
        # the replacements are processed correctly for the default message

        with MockedSMTP() as mock_smtp_instance:

            mock_smtp_instance.sendmail.return_value = []

            params = {'serial': serial, 'pin': 'Test123!'}
            response = self.make_helpdesk_request('setPin', params=params)

            assert serial in response, response

            call_args = mock_smtp_instance.sendmail.call_args
            _email_from, _email_to, email_message = call_args[0]

            assert 'Test123!' in email_message

        # ------------------------------------------------------------------ --

        # define random pin policy especially to use digits only

        policy = {
            'name': 'enrollment_pin_policy',
            'action': 'otp_pin_random=12, otp_pin_random_content=n',
            'scope': 'enrollment',
            'active': True,
            'realm': '*',
            'user': '*',
            'client': '*',
        }

        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not  in response

        # ------------------------------------------------------------------ --

        # verify that the setPin now usese an random pin

        with MockedSMTP() as mock_smtp_instance:

            mock_smtp_instance.sendmail.return_value = []

            params = {'serial': serial, 'pin': 'Test123!'}
            response = self.make_helpdesk_request('setPin', params=params)

            assert serial in response, response

            call_args = mock_smtp_instance.sendmail.call_args
            _email_from, _email_to, email_message = call_args[0]

            assert 'Test123!' not in email_message
            content = email_message.split('\n')[7]
            pin = content.split()[3]

            assert len(pin) == 12
            assert int(pin)

        return

    def test_tokens_admin_right(self):
        """test the tokens endpoint adhering the admin policies"""

        # ------------------------------------------------------------------ --

        # enroll token for hans

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
            'action': 'show,',
            'realm': 'myotherrealm',
            'client': '*',
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not  in response

        # ------------------------------------------------------------------ --

        # query the tokens of hans: h*

        params = {
            'qtype': 'loginname',
            'query': 'h*'
            }
        response = self.make_helpdesk_request('tokens', params=params)
        assert 'false' not in response
        assert serial not in response
        assert 'mydefrealm' not in response

        # ------------------------------------------------------------------ --

        # define the restricted admin policy for helpdesk user 'helpdesk'

        policy = {
            'name': 'helpdesk',
            'scope': 'admin',
            'active': True,
            'user': 'helpdesk,',
            'action': 'show,',
            'realm': 'myotherrealm, mydefrealm',
            'client': '*',
        }
        response = self.make_system_request('setPolicy', params=policy)
        assert 'false' not  in response

        # ------------------------------------------------------------------ --

        # query the tokens of hans: h*

        params = {
            'qtype': 'loginname',
            'query': 'h*'
            }
        response = self.make_helpdesk_request('tokens', params=params)
        assert 'false' not in response
        assert serial in response
        assert 'mydefrealm' in response

        return

    def test_tokens_query_params(self):
        """test the tokens endpoint adhering the admin policies"""

        # ------------------------------------------------------------------ --

        # enroll token for hans

        params = {
            'type': 'email',
            'user': 'hans',
            'realm': 'mydefrealm',
            'email_address': 'hans@example.com',
            'description': 'the token description',
            }
        response = self.make_admin_request('init', params)
        assert 'false' not in response, response

        jresp = json.loads(response.body)
        serial = jresp['detail']['serial']

        # ------------------------------------------------------------------ --

        # query the tokens of hans: h*

        params = {
            'qtype': 'loginname',
            'query': 'h*'
            }
        response = self.make_helpdesk_request('tokens', params=params)
        assert 'false' not in response
        assert serial in response
        assert 'mydefrealm' in response
        assert '"total": 1' in response

        # ------------------------------------------------------------------ --

        # query the tokens of realm: mydefrealm

        params = {
            'qtype': 'realm',
            'query': 'mydefrealm'
            }
        response = self.make_helpdesk_request('tokens', params=params)
        assert 'false' not in response
        assert serial in response
        assert 'mydefrealm' in response
        assert '"total": 1' in response

        # query the tokens of realm: myotherrealm

        params = {
            'qtype': 'realm',
            'query': 'myotherrealm'
            }
        response = self.make_helpdesk_request('tokens', params=params)

        assert 'false' not in response
        assert serial not in response
        assert 'mydefrealm' not in response
        assert '"total": 0' in response

        # ------------------------------------------------------------------ --

        # query the tokens of realm: mydefrealm

        params = {
            'qtype': 'all',
            'query': 'the token'
            }
        response = self.make_helpdesk_request('tokens', params=params)
        assert 'false' not in response
        assert serial in response
        assert 'mydefrealm' in response
        assert '"total": 1' in response

        return

# eof

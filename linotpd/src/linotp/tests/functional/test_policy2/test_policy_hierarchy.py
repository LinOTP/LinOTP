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
Test wether policies, which specify a username, are prefered over wildcard policies
"""
from datetime import datetime
from datetime import timedelta
from linotp.tests import TestController

class TestPolicyHierarchy(TestController):
    """
    Test if policies, which specify a username,
    are prefered over wildcard policies
    """

    def setUp(self):
        TestController.setUp(self)
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        TestController.tearDown(self)

    def _create_token(self, serial="12345", realm=None, user=None, active=True):
        """
        create an HMAC Token with given parameters

        :param serial:  serial number, must be unique per token and test
        :param realm:   optional: set token realm
        :param user:    optional: assign token to user
        :param active:  optional: if this is False, token will be disabled
        :return: serial of new token
        """
        parameters = {
            'serial': serial,
            'otpkey': 'AD8EABE235FC57C815B26CEF37090755',
            'description': 'TestToken' + serial,
        }
        if realm:
            parameters['realm'] = realm
        if user:
            parameters['user'] = user

        response = self.make_authenticated_request(controller='admin',
                                                   action='init',
                                                   params=parameters)
        self.assertTrue('"value": true' in response, response)
        if active is False:
            response = self.make_authenticated_request(
                controller='admin', action='disable', params={'serial': serial})

            self.assertTrue('"value": 1' in response, response)
        return serial

    def test_lostToken_policy_hierarchy_1(self):
        """
        The losttoken policy for specific user is prefered over the wildcard policy

        two policies are definded, one for specific user, one for wildcard user
        """
        serial = '0001'
        policy_special = {
            'name': 'losttoken_valid_hans',
            'scope': 'enrollment',
            'action': 'lostTokenValid=8',
            'realm': '*',
            'user': 'hans',
            'time': '',
            'client': '',
        }
        policy_wildcard = {
            'name': 'losttoken_valid_all',
            'scope': 'enrollment',
            'action': 'lostTokenValid=5',
            'realm': '*',
            'user': 'horst, *',
            'time': '',
            'client': '',
        }
        token = {'serial': serial}

        self._create_token(serial=serial, user='hans')
        self.create_policy(params=policy_special)
        self.create_policy(params=policy_wildcard)

        today = datetime.now()
        validity_special = (today + timedelta(days=8)).strftime("%d/%m/%y 23:59")
        losetoken = self.make_authenticated_request(
            controller='admin', action='losttoken', params=token)
        resp = TestController.get_json_body(losetoken)
        values = resp.get('result').get('value')
        self.assertEqual(values.get('end_date'), validity_special, resp)

    def test_lostToken_policy_hierarchy_2(self):
        """
        losttoken policy hierarchy test, create policies in different order

        two policies are definded, one for specific user, one for wildcard user
        """
        serial = '0001'
        policy_special = {
            'name': 'losttoken_valid_hans',
            'scope': 'enrollment',
            'action': 'lostTokenValid=8',
            'realm': '*',
            'user': 'hans',
            'time': '',
            'client': '',
        }
        policy_wildcard = {
            'name': 'losttoken_valid_all',
            'scope': 'enrollment',
            'action': 'lostTokenValid=5',
            'realm': '*',
            'user': '',
            'time': '',
            'client': '',
        }
        token = {'serial': serial}

        self._create_token(serial=serial, user='hans')
        self.create_policy(params=policy_wildcard)
        self.create_policy(params=policy_special)

        today = datetime.now()
        validity_special = (today + timedelta(days=8)).strftime("%d/%m/%y 23:59")
        losetoken = self.make_authenticated_request(
            controller='admin', action='losttoken', params=token)
        resp = TestController.get_json_body(losetoken)
        values = resp.get('result').get('value')
        self.assertEqual(values.get('end_date'), validity_special, resp)



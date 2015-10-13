# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
"""
"""

import json
import logging

from pylons import config

from linotp.tests import TestController, url

from linotp.lib.config import removeFromConfig
from linotp.lib.support import setSupportLicense

log = logging.getLogger(__name__)


class TestMonitoringController(TestController):

    def setUp(self):
        TestController.setUp(self)
        self.set_config_selftest()
        self.create_common_resolvers()
        self.create_common_realms()
        return

    def tearDown(self):
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        removeFromConfig('linotp.license')
        TestController.tearDown(self)
        return

    # helper function:
    def create_token(self, serial="1234567", realm=None, user=None,
                     active=True):
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
        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)
        self.assertTrue('"value": true' in response, response)
        if active is False:
            response = self.app.get(url(controller='admin', action='disable'),
                                    params={'serial': serial})
            self.assertTrue('"value": 1' in response, response)
        return serial

    # tests:
    def test_config(self):
        response = self.app.get(url(
            controller='monitoring', action='config'), params={})
        resp = json.loads(response.body)
        values = resp.get('result').get('value')
        self.assertEqual(values.get('realms'), 3, response)
        self.assertEqual(values.get('passwdresolver'), 2, response)
        self.assertEqual(values.get('sync'), True, response)
        return

    def test_token_realm_list(self):
        self.create_token(serial='0001')
        self.create_token(serial='0002', user='root')
        self.create_token(serial='0003', realm='mydefrealm')
        self.create_token(serial='0004', realm='myotherrealm')
        # test what happens if first realm is empty:git add
        parameters = {'realms': ',mydefrealm,myotherrealm'}
        response = self.app.get(url(
            controller='monitoring', action='tokens'), params=parameters)
        resp = json.loads(response.body)
        values = resp.get('result').get('value')
        self.assertEqual(values.get('Realms').get('mydefrealm').get('total'), 2,
                         response)
        self.assertEqual(values.get('Summary').get('total'), 3, response)
        return

    def test_token_active(self):
        self.create_token(serial='0011')
        self.create_token(serial='0012', user='root', active=True)
        self.create_token(serial='0013', realm='mydefrealm', active=True)
        self.create_token(serial='0014', realm='myotherrealm', active=False)
        parameters = {'realms': ',mydefrealm,myotherrealm', 'status': 'active'}
        response = self.app.get(url(
            controller='monitoring', action='tokens'), params=parameters)
        resp = json.loads(response.body)
        values = resp.get('result').get('value')
        self.assertEqual(values.get('Realms').get('mydefrealm').get('total'),
                         2, response)
        self.assertEqual(values.get('Realms').get('mydefrealm').get('active'),
                         2, response)
        self.assertEqual(values.get('Realms').get('myotherrealm').get('total'),
                         1, response)
        self.assertEqual(values.get('Realms').get('myotherrealm').get('active'),
                         0, response)
        self.assertEqual(values.get('Summary').get('total'), 3, response)
        self.assertEqual(values.get('Summary').get('active'), 2, response)
        return

    def test_token_status_combi(self):
        self.create_token(serial='0021')
        self.create_token(serial='0022', user='root')
        self.create_token(serial='0023', realm='mydefrealm')
        self.create_token(serial='0024', realm='myotherrealm')
        self.create_token(serial='0025', realm='myotherrealm', active=False)
        self.create_token(serial='0026', realm='myotherrealm', user='max2',
                          active=False)
        parameters = {
            'realms': '*',
            'status': 'unassigned&inactive'
        }
        response = self.app.get(url(
            controller='monitoring', action='tokens'), params=parameters)
        resp = json.loads(response.body)
        values = resp.get('result').get('value')
        self.assertEqual(values.get('Realms').get('mydefrealm').get('total'),
                         2, response)
        self.assertEqual(values.get('Realms').get('myotherrealm').get('total'),
                         3, response)
        self.assertEqual(
            values.get('Realms').get('myotherrealm').get('unassigned&inactive'),
            1, response)
        self.assertEqual(values.get('Realms').get('/:no realm:/').get('total'),
                         1, response)
        self.assertEqual(values.get('Summary').get('total'), 6, response)
        return

    def test_nolicense(self):
        response = self.app.get(url(
            controller='monitoring', action='license'), params={})
        resp = json.loads(response.body)
        self.assertEqual(resp.get('result').get('value'), {} , response)
        return

    def test_license(self):
        # Todo: skipp this test if no licensefile is available
        self.create_token(serial='0031')
        self.create_token(serial='0032', user='root')
        self.create_token(serial='0033', realm='mydefrealm')
        self.create_token(serial='0034', realm='myotherrealm')
        self.create_token(serial='0035', realm='myotherrealm', active=False)
        self.create_token(serial='0036', realm='myotherrealm', user='max2',
                          active=False)

        licpath = config.get('monitoringTests.licfile', '')
        self.assertTrue(licpath, 'Path to test license file is not configured, '
                                 'check test.ini!')
        with open(licpath, 'r') as licfile:
            data = licfile.readlines()

        licstring = ''
        for line in data:
            licstring += line
        res, msg = setSupportLicense(licstring)

        response = self.app.get(url(
            controller='monitoring', action='license'), params={})
        resp = json.loads(response.body)
        value = resp.get('result').get('value')
        self.assertEqual(value.get('token-num'), '10', response)
        self.assertEqual(value.get('token-left'), '6', response)
        return

## eof ########################################################################

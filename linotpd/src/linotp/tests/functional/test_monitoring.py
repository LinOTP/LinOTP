# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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

from linotp.tests import TestController

from linotp.lib.support import getSupportLicenseInfo
from linotp.lib.support import setSupportLicenseInfo
from linotp.lib.support import removeSupportLicenseInfo
from linotp.lib.support import readLicenseInfo
from linotp.lib.support import isSupportLicenseValid
from linotp.lib.support import InvalidLicenseException

log = logging.getLogger(__name__)


class TestMonitoringController(TestController):

    def setUp(self):
        super(TestMonitoringController, self).setUp()
        self.create_common_resolvers()
        self.create_common_realms()
        return

    def tearDown(self):
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        super(TestMonitoringController, self).tearDown()

    # helper functions
    def checkCurrentLicense(self):
        """

        :return: 1 if license is available
                -1 if license is invalid
                0 if license is not available
        """
        try:
            # Test current license...
            getSupportLicenseInfo(validate=True, raiseException=True)
            return 1
        except InvalidLicenseException as err:
            if err.type != 'UNLICENSED':
                # support license is invalid
                return -1
            else:
                # support license not available
                return 0

    def getCurrentLicense(self):
        # Test current license...
        lic, sig = getSupportLicenseInfo()
        isSupportLicenseValid(lic_dict=lic, lic_sign=sig,
                              raiseException=True)
        return (lic, sig)

    def setCurrentLicense(self, old_lic, old_sig):
        if old_lic is None and old_sig is None:
            removeSupportLicenseInfo()
        else:
            setSupportLicenseInfo(old_lic, old_sig)

    def installLicense(self, licfile):
        new_lic, new_sig = readLicenseInfo(licfile)
        setSupportLicenseInfo(new_lic, new_sig)
        return

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

        response = self.make_authenticated_request(controller='admin',
                                                   action='init',
                                                   params=parameters)
        self.assertTrue('"value": true' in response, response)
        if active is False:
            response = self.make_authenticated_request(controller='admin',
                                                       action='disable',
                                                       params={
                                                           'serial': serial})

            self.assertTrue('"value": 1' in response, response)
        return serial

    # UnitTests...
    def test_config(self):
        response = self.make_authenticated_request(
            controller='monitoring', action='config', params={})
        resp = json.loads(response.body)
        values = resp.get('result').get('value')
        self.assertEqual(values.get('realms'), 3, response)
        self.assertEqual(values.get('passwdresolver'), 2, response)
        # self.assertEqual(values.get('sync'), True, response)
        return

    def test_token_realm_list(self):
        self.create_token(serial='0001')
        self.create_token(serial='0002', user='root')
        self.create_token(serial='0003', realm='mydefrealm')
        self.create_token(serial='0004', realm='myotherrealm')
        # test what happens if first realm is empty:git add
        parameters = {'realms': ',mydefrealm,myotherrealm'}
        response = self.make_authenticated_request(
            controller='monitoring', action='tokens', params=parameters)
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
        response = self.make_authenticated_request(
            controller='monitoring', action='tokens', params=parameters)
        resp = json.loads(response.body)
        r_values = resp.get('result').get('value').get('Realms', {})
        self.assertEqual(r_values.get('mydefrealm', {}).get('total', -1),
                         2, response)
        self.assertEqual(r_values.get('mydefrealm', {}).get('active', -1),
                         2, response)
        self.assertEqual(r_values.get('myotherrealm', {}).get('total', -1),
                         1, response)
        self.assertEqual(r_values.get('myotherrealm', {}).get('active', -1),
                         0, response)
        s_values = resp.get('result').get('value').get('Summary', {})
        self.assertEqual(s_values.get('total', -1), 3, response)
        self.assertEqual(s_values.get('active', -1), 2, response)
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
        response = self.make_authenticated_request(
            controller='monitoring', action='tokens', params=parameters)
        resp = json.loads(response.body)
        values = resp.get('result').get('value').get('Realms')
        self.assertEqual(values.get('mydefrealm').get('total', -1),
                         2, response)
        self.assertEqual(values.get('myotherrealm').get('total', -1),
                         3, response)
        self.assertEqual(
            values.get('myotherrealm').get('unassigned&inactive', -1),
            1, response)
        self.assertEqual(values.get('/:no realm:/').get('total', -1),
                         1, response)
        s_values = resp.get('result').get('value').get('Summary')
        self.assertEqual(s_values.get('total', -1), 6, response)
        return

    def test_nolicense(self):
        """

        """
        old_lic = None
        old_sig = None
        try:
            old_lic, old_sig = self.getCurrentLicense()

        except InvalidLicenseException as exx:
            if (exx.message != "Support not available, your product is"
                    " unlicensed"):
                raise exx
        try:
            # Remove previous license...
            self.setCurrentLicense(None, None)

            response = self.make_authenticated_request(
                controller='monitoring', action='license', params={})
            resp = json.loads(response.body)
            self.assertEqual(resp.get('result').get('value'), {}, response)

        finally:
            # restore previous license...
            if old_lic and old_sig:
                self.setCurrentLicense(old_lic, old_sig)
        return

    def test_license(self):
        old_lic = None
        old_sig = None
        try:
            old_lic, old_sig = self.getCurrentLicense()
        except InvalidLicenseException as exx:
            if (exx.message != "Support not available, your product is "
                    "unlicensed"):
                raise exx

        try:
            # Load the license file...
            licfile = config.get('monitoringTests.licfile', '')

            if not licfile:
                self.skipTest('Path to test license file is not configured, '
                              'check your configuration (test.ini)!')
            lic_dict, lic_sig = readLicenseInfo(licfile)

            self.installLicense(licfile)

            self.create_token(serial='0031')
            self.create_token(serial='0032', user='root')
            self.create_token(serial='0033', realm='mydefrealm')
            self.create_token(serial='0034', realm='myotherrealm')
            self.create_token(serial='0035', realm='myotherrealm',
                              active=False)
            self.create_token(serial='0036', realm='myotherrealm', user='max2',
                              active=False)

            response = self.make_authenticated_request(controller='monitoring',
                                                       action='license',
                                                       params={})
            resp = json.loads(response.body)
            value = resp.get('result').get('value')
            self.assertEqual(value.get('token-num'),
                             int(lic_dict.get('token-num')),
                             response)
            token_left = int(lic_dict.get('token-num')) - 4
            self.assertEqual(value.get('token-left'), token_left, response)

        finally:
            # restore previous license...
            if old_lic and old_sig:
                self.setCurrentLicense(old_lic, old_sig)

        return

    def test_check_encryption(self):
        response = self.make_authenticated_request(
            controller='monitoring', action='storageEncryption', params={})
        resp = json.loads(response.body)
        values = resp.get('result').get('value')
        self.assertEqual(values.get('encryption'), True, response)
        self.assertEqual(values.get('cryptmodul_name'), 'Default', response)
        self.assertEqual(values.get('cryptmodul_type'), 'DefaultSecurityModule',
                         response)

        # and one more time:
        response = self.make_authenticated_request(
            controller='monitoring', action='storageEncryption', params={})
        resp = json.loads(response.body)
        values = resp.get('result').get('value')
        self.assertEqual(values.get('encryption'), True, response)

    def test_userinfo(self):
        response = self.make_authenticated_request(
            controller='monitoring', action='userinfo', params={})
        resp = json.loads(response.body)
        myotherrealm = resp.get('result').get('value').get('Realms').get(
            'myotherrealm')
        self.assertEqual(myotherrealm.get('myOtherRes'), 8, response)
        mymixrealm = resp.get('result').get('value').get('Realms').get(
            'mymixrealm')
        self.assertEqual(mymixrealm.get('myOtherRes'), 8, response)
        self.assertEqual(mymixrealm.get('myDefRes'), 24, response)


# eof ########################################################################

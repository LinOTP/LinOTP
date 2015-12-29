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
used to do functional testing of the remote token

These tests will only pass if you start a LinOTP server on 127.0.0.1.
For example with paster:

    paster serve test.ini

We assume port 5001 is used (default). If you want to use another port you can
specify it with nose-testconfig (e.g. --tc=paster.port:5005).
"""

import logging
from linotp.tests.functional_special import TestSpecialController
from linotp.tests import url

log = logging.getLogger(__name__)


class TestRemoteToken(TestSpecialController):

    def setUp(self):
        '''
        Overwrite the deleting of the realms!

        If the realms are deleted also the table TokenRealm gets deleted
        and we loose the information how many tokens are within a realm!
        '''
        TestSpecialController.setUp(self)
        self.set_config_selftest()
        self.remote_url = 'http://127.0.0.1:%s' % self.paster_port
        return

    def tearDown(self):
        ''' Overwrite parent tear down, which removes all realms '''
        return

    ### define Admins

    def test_00_000(self):
        '''
        Init the tests....
        '''
        self.delete_all_policies()
        self.delete_all_token()

        self.create_common_resolvers()
        self.create_common_realms()

        return

    def test_00_create_remote_token(self):
        # local token
        param_local_1 = {"serial": "LSPW1",
                         "type": "pw",
                         "otpkey": "123456",
                         "otppin": "",
                         "user": "",
                         "pin": "pin",
                         }
        param_local_2 = {
                         "serial": "LSPW2",
                      "type": "pw",
                      "otpkey": "234567",
                      "otppin": "",
                      "user": "",
                      "pin": "pin",
                         }

        # The token with the remote PIN
        parameters1 = {
                      "serial": "LSRE001",
                      "type": "remote",
                      "otpkey": "1234567890123456",
                      "otppin": "",
                      "user": "remoteuser",
                      "pin": "pin",
                      "description": "RemoteToken1",
                      'remote.server': self.remote_url,
                      'remote.local_checkpin': 0,
                      'remote.serial': 'LSPW1',
                      }

        # the token with the local PIN
        parameters2 = {
                      "serial": "LSRE002",
                      "type": "remote",
                      "otpkey": "1234567890123456",
                      "otppin": "",
                      "user": "localuser",
                      "pin": "pin",
                      "description": "RemoteToken2",
                      'remote.server':  self.remote_url,
                      'remote.local_checkpin': 1,
                      'remote.serial': 'LSPW2',
                      }

        response = self.make_admin_request('init', params=param_local_1)
        self.assertTrue('"value": true' in response, response)

        response = self.make_admin_request('init', params=param_local_2)
        self.assertTrue('"value": true' in response, response)

        response = self.make_admin_request('init', params=parameters1)
        self.assertTrue('"value": true' in response, response)

        response = self.make_admin_request('init', params=parameters2)
        self.assertTrue('"value": true' in response, response)

        response = self.make_admin_request('set',
                                           params={'serial': 'LSPW1',
                                                   'pin': 'lspw1'})
        self.assertTrue('"set pin": 1' in response, response)

        response = self.make_admin_request('set',
                                           params={'serial': 'LSPW2',
                                                   'pin': ''})
        self.assertTrue('"set pin": 1' in response, response)

        response = self.make_admin_request('set',
                                           params={'serial': 'LSRE001',
                                                   'pin': 'local'})
        self.assertTrue('"set pin": 1' in response, response)

        response = self.make_admin_request('set',
                                           params={'serial': 'LSRE002',
                                                   'pin': 'local'})
        self.assertTrue('"set pin": 1' in response, response)

        return

    def test_02_check_token_local_pin(self):
        '''
        Checking if token with local PIN works

        To successfully test the remote token, the paster must run locally.
        '''

        parameters = {"serial": "LSPW2", "pass": "234567"}
        response = self.make_validate_request('check_s',
                                              params=parameters)

        self.assertTrue('"value": true' in response, response)

        parameters = {"user": "localuser", "pass": "local234567"}
        response = self.make_validate_request('check',
                                              params=parameters)
        self.assertTrue('"value": true' in response, response)

        return

    def test_03_check_token_remote_pin(self):
        '''
        Checking if remote PIN works
        '''
        parameters = {"user": "remoteuser", "pass": "lspw1123456"}
        response = self.make_validate_request('check',
                                              params=parameters)

        self.assertTrue('"value": true' in response, response)

        return

    def test_04_check_token_local_pin_fail(self):
        '''
        Checking if a missing local PIN will fail
        '''

        parameters = {"user": "localuser", "pass": "234567"}
        response = self.make_validate_request('check',
                                              params=parameters)

        self.assertTrue('"value": false' in response, response)

        return

    def test_05_check_token_local_pin_fail2(self):
        '''
        Checking if a wrong local PIN will fail
        '''

        parameters = {"user": "localuser", "pass": "lspw1234567"}
        response = self.make_validate_request('check', params=parameters)

        self.assertTrue('"value": false' in response, response)

    def test_06_check_token_remote_pin_fail(self):
        '''
        Checking if a missing remote PIN will fail
        '''

        parameters = {"user": "remoteuser", "pass": "123456"}
        response = self.make_validate_request('check', params=parameters)

        self.assertTrue('"value": false' in response, response)

        return

    def test_06_check_token_remote_pin_fail2(self):
        '''
        Checking if a wrong remote PIN will fail
        '''

        parameters = {"user": "remoteuser", "pass": "local123456"}
        response = self.make_validate_request('check', params=parameters)

        self.assertTrue('"value": false' in response, response)

        return

    def create_local_tokens(self, serial):

        serial = "LSP%s" % serial

        # local token
        param_local_1 = {
                       "serial": serial,
                      "type": "spass",
                      "otpkey": "123456",
                      "otppin": "",
                      "user": "",
                      "pin": "pin",
                         }

        response = self.make_admin_request('init', params=param_local_1)
        self.assertTrue('"value": true' in response, response)
        return serial

    def test_07_fix_12061(self):
        '''
        ticket 12061: timeout with remote tokens: many tokens + unicode pins
        '''

        sqlconnect = self.appconf.get('sqlalchemy.url')
        log.debug('current test against %s' % (sqlconnect))

        from linotp.model import token_table
        for column in token_table.columns:
            log.debug("Column Table name: %s : %s : %r"
                      % (column.name, column.type, column.index))
            if column.name == 'LinOtpTokenSerialnumber':
                self.assertTrue(column.index == True, column.name)

        serials = []

        for i in range(1, 90):
            serial = self.create_local_tokens('tok_%d' % i)
            serials.append(serial)

        serial = serials[0]
        rserial = "%s_remote" % serial
        serials.append(rserial)

        parameters1 = {
                      "serial": rserial,
                      "type": "remote",
                      "otpkey": "1234567890123456",
                      "otppin": "",
                      "user": "root",
                      "pin": "",
                      "description": "RemoteToken",
                      'remote.server':  self.remote_url,
                      'remote.local_checkpin': 0,
                      'remote.serial': serial,
                      }

        response = self.make_admin_request('init', params=parameters1)
        self.assertTrue('"value": true' in response, response)

        for offset in range(1, 20):
            pin = "pin_"
            for i in range(1, 100):
                pin = "%s%s" % (pin, unichr(0x28 * offset + i))

            params = {'serial': serial, 'pin': pin}
            response = self.make_admin_request('set', params=params)
            self.assertTrue('"set pin": 1' in response, response)

            params = {'user': 'root', 'pass': pin}
            response = self.make_validate_request('check', params=params)
            self.assertTrue('"value": true' in response, response)

        for serial in serials:
            self.delete_token(serial)

        return

#eof###########################################################################

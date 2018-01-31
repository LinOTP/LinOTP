# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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


""" used to do functional testing of the radius token"""
import logging
from linotp.tests import TestController, url

log = logging.getLogger(__name__)

DEFAULT_NOSE_CONFIG = {
    'radius': {
        'authport': '18012',
        'acctport': '18013',
        }
    }
try:
    from testconfig import config as nose_config
except ImportError as exc:
    print "You need to install nose-testconfig. Will use default values."
    nose_config = None


class TestRadiusToken(TestController):

    p = None

    def setUp(self):
        if nose_config and 'radius' in nose_config:
            self.radius_authport = nose_config['radius']['authport']
            self.radius_acctport = nose_config['radius']['acctport']
        else:
            self.radius_authport = DEFAULT_NOSE_CONFIG['radius']['authport']
            self.radius_acctport = DEFAULT_NOSE_CONFIG['radius']['acctport']

        TestController.setUp(self)
        self.set_config_selftest()
        self.create_common_resolvers()
        self.create_common_realms()

        # cleanup from last run
        try:
            self.deleteRadiusToken()
        except:
            pass

        self.create_radius_token()

    def tearDown(self):
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def create_radius_token(self):
        # The token with the remote PIN
        parameters1 = {
                      "serial": "radius1",
                      "type": "radius",
                      "otpkey": "1234567890123456",
                      "otppin": "",
                      "user": "remoteuser",
                      "pin": "pin",
                      "description": "RadiusToken1",
                      'radius.server': 'localhost:%s' % self.radius_authport,
                      'radius.local_checkpin': 0,
                      'radius.user': 'user_with_pin',
                      'radius.secret': 'testing123',
                      }

        # the token with the local PIN
        parameters2 = {
                      "serial": "radius2",
                      "type": "radius",
                      "otpkey": "1234567890123456",
                      "otppin": "local",
                      "user": "localuser",
                      "pin": "pin",
                      "description": "RadiusToken2",
                      'radius.server': 'localhost:%s' % self.radius_authport,
                      'radius.local_checkpin': 1,
                      'radius.user': 'user_no_pin',
                      'radius.secret': 'testing123',
                      }

        response = self.make_admin_request('init', params=parameters1)
        self.assertTrue('"value": true' in response, response)

        response = self.make_admin_request('init', params=parameters2)
        self.assertTrue('"value": true' in response, response)

        params = {'serial': 'radius2', 'pin': 'local'}
        response = self.make_admin_request('set', params=params)
        self.assertTrue('"set pin": 1' in response, response)

        params = {'serial': 'radius1', 'pin': ''}
        response = self.make_admin_request('set', params=params)
        self.assertTrue('"set pin": 1' in response, response)

    def deleteRadiusToken(self):
        for serial in ["radius1", "radius2"]:
            parameters = {"serial": serial}
            response = self.make_admin_request('remove', params=parameters)
            self.assertTrue('"value": 1' in response, response)
            return

    def _start_radius_server(self):
        '''
        Start the dummy radius server
        '''
        '''
        We need to start the radius server for every test, since every test instantiates a new TestClass and thus the
        radius server process will not be accessable outside of a test anymore
        '''
        import subprocess
        import os.path

        radius_server_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            '..',
            'tools',
            'dummy_radius_server.py',
            )
        dictionary_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            '..',
            '..',
            '..',
            'config',
            'dictionary',
            )
        self.assertTrue(os.path.isfile(radius_server_file) is True,
                        "radius demo server not found: %s" % radius_server_file)

        self.p = subprocess.Popen(
            [
                radius_server_file,
                "--dict",
                dictionary_file,
                "--authport",
                self.radius_authport,
                "--acctport",
                self.radius_acctport,
                ]
            )
        assert self.p is not None

        return

    def _stop_radius_server(self):
        '''
        stopping the dummy radius server
        '''
        if self.p:
            r = self.p.kill()
            log.debug(r)

    def test_02_check_token_local_pin(self):
        '''
        Checking if token with local PIN works
        '''
        try:
            self._start_radius_server()
            parameters = {"user": "localuser", "pass": "local654321"}
            response = self.make_validate_request('check', params=parameters)
            self.assertTrue('"value": true' in response, response)
        finally:
            self._stop_radius_server()
        return

    def test_03_check_token_remote_pin(self):
        '''
        Checking if remote PIN works
        '''
        try:
            self._start_radius_server()
            parameters = {"user": "remoteuser", "pass": "test123456"}
            response = self.make_validate_request('check', params=parameters)
            self.assertTrue('"value": true' in response, response)
        finally:
            self._stop_radius_server()
        return

    def test_04_check_token_local_pin_fail(self):
        '''
        Checking if a missing local PIN will fail
        '''
        try:
            self._start_radius_server()
            parameters = {"user": "localuser", "pass": "654321"}
            response = self.make_validate_request('check', params=parameters)
            self.assertTrue('"value": false' in response, response)
        finally:
            self._stop_radius_server()

        return

    def test_05_check_token_local_pin_fail2(self):
        '''
        Checking if a wrong local PIN will fail
        '''
        try:
            self._start_radius_server()
            parameters = {"user": "localuser", "pass": "blabla654321"}
            response = self.make_validate_request('check', params=parameters)
            self.assertTrue('"value": false' in response, response)
        finally:
            self._stop_radius_server()

        return

    def test_06_check_token_remote_pin_fail(self):
        '''
        Checking if a missing remote PIN will fail
        '''
        try:
            self._start_radius_server()
            parameters = {"user": "remoteuser", "pass": "123456"}
            response = self.make_validate_request('check', params=parameters)
            self.assertTrue('"value": false' in response, response)
        finally:
            self._stop_radius_server()

        return

    def test_06_check_token_remote_pin_fail2(self):
        '''
        Checking if a wrong remote PIN will fail
        '''
        try:
            self._start_radius_server()
            parameters = {"user": "remoteuser", "pass": "abcd123456"}
            response = self.make_validate_request('check', params=parameters)
            self.assertTrue('"value": false' in response, response)
        finally:
            self._stop_radius_server()

        return

#eof##########################################################################

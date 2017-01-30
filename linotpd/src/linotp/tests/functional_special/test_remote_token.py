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
used to do functional testing of the remote token

 + spass token with local and remote token pin test
 + unicode pin through remote token 
      
"""

import binascii
import json
import logging
import smtplib
import urlparse

import httplib2
from mock import patch

from linotp.lib.util import str2unicode
from linotp.tests.functional_special import TestSpecialController


log = logging.getLogger(__name__)

# mocking hook is startting here
HTTP_RESPONSE_FUNC = None
HTTP_RESPONSE = None

def mocked_http_request(HttpObject, *argparams, **kwparams):

    resp = 200
    body = kwparams.get('body', '')
    params = dict(urlparse.parse_qsl(body))

    content = {
        "version": "LinOTP MOCK",
        "jsonrpc": "2.0",
        "result": {
            "status": True,
            "value": True
        },
        "id": 0
    }

    global HTTP_RESPONSE
    if HTTP_RESPONSE:
        status, response = HTTP_RESPONSE
        if response:
            content = response
            resp = status
        HTTP_RESPONSE = None

    global HTTP_RESPONSE_FUNC
    if HTTP_RESPONSE_FUNC:
        test_func = HTTP_RESPONSE_FUNC
        resp, content = test_func(params)
        HTTP_RESPONSE_FUNC = None

    return resp, json.dumps(content)




class TestRemoteToken(TestSpecialController):

    def setUp(self):
        '''
        Overwrite the deleting of the realms!

        If the realms are deleted also the table TokenRealm gets deleted
        and we loose the information how many tokens are within a realm!
        '''
        TestSpecialController.setUp(self)
        self.remote_url = 'http://127.0.0.1:%s' % self.paster_port

        self.delete_all_policies()
        self.delete_all_token()

        self.create_common_resolvers()
        self.create_common_realms()

        return

    def create_local_tokens(self, serial):

        serial = "LSP%s" % serial

        # local token
        param_local_1 = {"serial": serial,
                         "type": "spass",
                         "otpkey": "123456",
                         "otppin": "",
                         "user": "",
                         "pin": "pin",
                         }

        response = self.make_admin_request('init', params=param_local_1)
        self.assertTrue('"value": true' in response, response)
        return serial


    def create_remote_token(self):
        # local token
        param_local_1 = {"serial": "LSPW1",
                         "type": "pw",
                         "otpkey": "123456",
                         "otppin": "",
                         "user": "",
                         "pin": "pin",
                         }
        param_local_2 = {"serial": "LSPW2",
                         "type": "pw",
                         "otpkey": "234567",
                         "otppin": "",
                         "user": "",
                         "pin": "pin",
                        }

        # The token with the remote PIN
        parameters1 = {"serial": "LSRE001",
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
        parameters2 = {"serial": "LSRE002",
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

    @patch.object(httplib2.Http, 'request', mocked_http_request)
    def test_check_token_local_pin(self):
        '''
        Checking if token with local PIN works

        To successfully test the remote token, the paster must run locally.
        '''
        global HTTP_RESPONSE_FUNC
        
        self.create_remote_token()

        parameters = {"serial": "LSPW2", "pass": "234567"}
        response = self.make_validate_request('check_s',
                                              params=parameters)
        self.assertTrue('"value": true' in response, response)

        # test for local missing pin, which whould be 'local'
        parameters = {"user": "localuser", "pass": "234567"}
        response = self.make_validate_request('check',
                                              params=parameters)

        self.assertTrue('"value": false' in response, response)

        # test for local pin check + remote pw check
        def check_func1(params):
            resp = 200
            value = params.get('pass') == '234567'
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }
            return resp, content

        HTTP_RESPONSE_FUNC = check_func1

        parameters = {"user": "localuser", "pass": "local234567"}
        response = self.make_validate_request('check',
                                              params=parameters)
        self.assertTrue('"value": true' in response, response)

        # Checking if a wrong local PIN will fail
        parameters = {"user": "localuser", "pass": "lspw1234567"}
        response = self.make_validate_request('check', params=parameters)

        self.assertTrue('"value": false' in response, response)

        return

    @patch.object(httplib2.Http, 'request', mocked_http_request)
    def test_check_token_remote_pin(self):
        '''
        Checking if remote PIN works
        '''
        global HTTP_RESPONSE_FUNC
        self.create_remote_token()

        # test for remote pin, which should be lspw11 
        def check_func1(params):
            resp = 200
            value = params.get('pass') == 'lspw1123456'
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": value
                },
                "id": 0
            }
            return resp, content

        HTTP_RESPONSE_FUNC = check_func1
        
        parameters = {"user": "remoteuser", "pass": "lspw1123456"}
        response = self.make_validate_request('check', params=parameters)

        self.assertTrue('"value": true' in response, response)

        # Checking if a missing remote PIN will fail
        def check_func2(params):
            resp = 200
            value = params.get('pass') == '123456'
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": not value
                },
                "id": 0
            }
            return resp, content

        HTTP_RESPONSE_FUNC = check_func2

        parameters = {"user": "remoteuser", "pass": "123456"}
        response = self.make_validate_request('check', params=parameters)

        self.assertTrue('"value": false' in response, response)

        # Checking if a wrong remote PIN will fail
        def check_func2(params):
            resp = 200
            value = params.get('pass') == 'local123456'
            content = {
                "version": "LinOTP MOCK",
                "jsonrpc": "2.0",
                "result": {
                    "status": True,
                    "value": not value
                },
                "id": 0
            }
            return resp, content
        HTTP_RESPONSE_FUNC = check_func2

        parameters = {"user": "remoteuser", "pass": "local123456"}
        response = self.make_validate_request('check', params=parameters)

        self.assertTrue('"value": false' in response, response)

        return

    @patch.object(httplib2.Http, 'request', mocked_http_request)
    def test_fix_12061(self):
        '''
        ticket 12061: timeout with remote tokens: many tokens + unicode pins
        '''

        global HTTP_RESPONSE_FUNC
        self.create_remote_token()

        sqlconnect = self.appconf.get('sqlalchemy.url')
        log.debug('current test against %s' % (sqlconnect))

        # verify that there is n index on the TokenSerial number
        from linotp.model import token_table
        for column in token_table.columns:
            log.debug("Column Table name: %s : %s : %r"
                      % (column.name, column.type, column.index))
            if column.name == 'LinOtpTokenSerialnumber':
                self.assertTrue(column.index is True, column.name)


        # create token and remote token which points to this
        serials = []
        serial = self.create_local_tokens('tok_%d' % 1)
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

        # set pin to the target token and do remote token pin verification
        for offset in range(1, 20):
            pin_chars = []
            for i in range(1, 100):
                pin_chars.append(unichr(0x28 * offset + i))
            pin = u"pin" + u"".join(pin_chars)
            pin = pin.encode('utf-8')

            params = {'serial': serial, 'pin': pin}
            response = self.make_admin_request('set', params=params)
            self.assertTrue('"set pin": 1' in response, response)

            # Checking if a wrong remote PIN will fail
            def check_func3(params):
                resp = 200

                # during transfer through the callstack, the pin is 
                # transformed into utf-8. so for comparison, we have 
                # to do the same before comparing
                l_pin = params.get('pass')
                
                value = l_pin == pin
                content = {
                    "version": "LinOTP MOCK",
                    "jsonrpc": "2.0",
                    "result": {
                        "status": True,
                        "value": value
                    },
                    "id": 0
                }
                return resp, content
            HTTP_RESPONSE_FUNC = check_func3

            params = {'user': 'root', 'pass': pin}
            response = self.make_validate_request('check', params=params)
            self.assertTrue('"value": true' in response, response)

        for serial in serials:
            self.delete_token(serial)

        return

#eof###########################################################################

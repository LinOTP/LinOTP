# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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


from linotp.tests import TestController
from linotp.tests import url

try:
    import json
except ImportError:
    import simplejson as json

import logging
log = logging.getLogger(__name__)


class TestHttpSmsController(TestController):
    '''
    Here the HTTP SMS Gateway functionality is tested.
    '''


    def setUp(self):
        '''
        This sets up all the resolvers and realms
        '''
        TestController.setUp(self)
        self.removeTokens()
        self.initToken()
        self.initProvider()



###############################################################################
    def removeTokens(self):
        for serial in ['sms01', 'sms02']:
            parameters = {'serial':serial}
            response = self.app.get(url(controller='admin', action='remove'),
                                    params=parameters)
            #log.error(response)
            self.assertTrue('"status": true' in response, response)

    def initToken(self):
        '''
        Initialize the tokens
        '''
        parameters = { 'serial' : 'sms01',
                       'otpkey' : '1234567890123456789012345678901234567890' +
                                  '123456789012345678901234',
                       'realm' : 'myDefRealm',
                       'type' : 'sms',
                       'user' : 'user1',
                       'pin' : '1234',
                       'phone' : '016012345678',
                       'selftest_admin' : 'superadmin'
                      }
        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)

        self.assertTrue('"status": true' in response, response)

        parameters = { 'serial' : 'sms02',
                       'otpkey' : '1234567890123456789012345678901234567890' +
                                   '123456789012345678901234',
                       'realm' : 'myDefRealm',
                       'user' : 'user2',
                       'type' : 'sms',
                       'pin' : '1234',
                       'phone' : '016022222222',
                       'selftest_admin' : 'superadmin'
                      }
        response = self.app.get(url(controller='admin', action='init'),
                                                             params=parameters)

        self.assertTrue('"status": true' in response, response)

    def initProvider(self):
        '''
        Initialize the HttpSMSProvider
        '''
        parameters = {
                'SMSProvider' : 'smsprovider.HttpSMSProvider.HttpSMSProvider',
                'selftest_admin' : 'superadmin'
                   }
        response = self.app.get(url(controller='system', action='setConfig'),
                                                             params=parameters)

        self.assertTrue('"status": true' in response, response)

    def last_audit(self, num=3, page=1):
        '''
        Checks the last audit entry
        '''
        # audit/search?sortorder=desc&rp=1
        response = self.app.get(url(controller="audit", action="search"),
                                params={ 'sortorder':'desc',
                                         'rp':num, 'page':page,
                                         'selftest_admin':'superadmin'})
        return response

    def test_0001_missing_param(self):
        '''
        Missing parameter at the SMS Gateway config. send SMS will fail
        '''
        sms_conf = {
                "URL" : "http://localhost:5001/testing/http2sms",
                "PARAMETER" :
                    {"account" : "clickatel", "username" : "legit"},
                "SMS_TEXT_KEY":"text",
                "SMS_PHONENUMBER_KEY":"to",
                "HTTP_Method" : "GET",
                "RETURN_SUCCESS" : "ID",
                }

        parameters = {
                'SMSProviderConfig' : json.dumps(sms_conf),
                'selftest_admin' : 'superadmin'
                }
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)

        self.assertTrue('"status": true' in response, response)

        # check the saved configuration
        response = self.app.get(url(controller='system', action='getConfig'),
                                {'key' : 'SMSProviderConfig'})

        self.assertTrue('http://localhost:5001/testing/http2sms' in response,
                        response)

        response = self.app.get(url(controller='validate', action='smspin')
                                , params={'user' : 'user1', 'pass' : '1234'})
        self.assertTrue('Failed to send SMS.' in response, response)
        # check last audit entry
        response = self.last_audit()

        val = "-1"
        if '"total": null,' not in response:
            resp = json.loads(response.body)
            rows = resp.get("rows", [])
            for row in rows:
                cell = row.get('cell', {})
                if "validate/smspin" in cell:
                    idx = cell.index('validate/smspin')
                    val = cell[idx + 1]
                    break

        self.assertTrue(val == "0", response)


        return

    def test_02_succesful_auth(self):
        '''
        Successful SMS sending (via smspin) and authentication
        '''
        sms_conf = { "URL" : "http://localhost:5001/testing/http2sms",
                     "PARAMETER" : { "account" : "clickatel",
                                    "username" : "legit" },
                    "SMS_TEXT_KEY":"text",
                    "SMS_PHONENUMBER_KEY":"destination",
                    "HTTP_Method" : "GET",
                    "RETURN_SUCCESS" : "ID"
                    }

        parameters = { 'SMSProviderConfig' : json.dumps(sms_conf),
                       'selftest_admin' : 'superadmin'
                      }
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)

        self.assertTrue('"status": true' in response, response)

        response = self.app.get(url(controller='validate', action='smspin'),
                                params={'user' : 'user1', 'pass' : '1234'})
        self.assertTrue('"state":' in response,
                        "Expecting 'state' as challenge inidcator %r"
                        % response)

        # check last audit entry
        response2 = self.last_audit()
        # must be success == 1
        val = "-1"
        if '"total": null' not in response2:
            resp = json.loads(response2.body)
            rows = resp.get("rows", [])
            for row in rows:
                cell = row.get('cell', {})
                if "validate/smspin" in cell:
                    idx = cell.index('validate/smspin')
                    val = cell[idx + 1]
                    break

        self.assertTrue(val == "1", response2)

        # test authentication
        response = self.app.get(url(controller='validate', action='check'),
                                params={'user' : 'user1',
                                        'pass' : '1234973532'})
        self.assertTrue('"value": true' in response, response)

        return

    def test_03_succesful_auth(self):
        '''
        Successful SMS sending (via validate) and authentication
        '''
        sms_conf = {
            "URL" : "http://localhost:5001/testing/http2sms",
            "PARAMETER" : { "account" : "clickatel", "username" : "legit" },
            "SMS_TEXT_KEY":"text",
            "SMS_PHONENUMBER_KEY":"destination",
            "HTTP_Method" : "GET",
            "RETURN_SUCCESS" : "ID"
        }
        parameters = { 'SMSProviderConfig' : json.dumps(sms_conf),
                       'selftest_admin' : 'superadmin'
                      }
        response = self.app.get(url(controller='system', action='setConfig'),
                                                             params=parameters)

        self.assertTrue('"status": true' in response, response)

        response = self.app.get(url(controller='validate', action='check'),
                                params={'user' : 'user1', 'pass' : '1234'})

        # authentication fails but sms is sent
        self.assertTrue('"value": false' in response, response)

        # check last audit entry
        response2 = self.last_audit()
        # must be success == 1
        if '"total": null' not in response2:
            self.assertTrue('''challenge created''' in response2, response2)

        # test authentication
        response = self.app.get(url(controller='validate', action='check'),
                                params={'user' : 'user1',
                                        'pass' : '1234973532'})

        self.assertTrue('"value": true' in response, response)


    def test_04_successful_SMS(self):
        '''
        Successful SMS sending with RETURN_FAILED
        '''
        sms_conf = {
            "URL" : "http://localhost:5001/testing/http2sms",
            "PARAMETER" : { "account" : "clickatel", "username" : "legit" },
            "SMS_TEXT_KEY":"text",
            "SMS_PHONENUMBER_KEY":"destination",
            "HTTP_Method" : "GET",
            "RETURN_FAILED" : "FAILED"
            }
        parameters = { 'SMSProviderConfig' : json.dumps(sms_conf),
                       'selftest_admin' : 'superadmin'
                      }
        response = self.app.get(url(controller='system', action='setConfig'),
                                                            params=parameters)

        self.assertTrue('"status": true' in response, response)

        response = self.app.get(url(controller='validate', action='smspin'),
                                params={'user' : 'user1',
                                        'pass' : '1234'})

        self.assertTrue('"state"' in response, response)

        return

    def test_05_failed_SMS(self):
        '''
        Failed SMS sending with RETURN_FAIL
        '''
        sms_conf = { "URL" : "http://localhost:5001/testing/http2sms",
            "PARAMETER" : {"account" : "clickatel", "username" : "anotherone"},
            "SMS_TEXT_KEY":"text",
            "SMS_PHONENUMBER_KEY":"destination",
            "HTTP_Method" : "GET",
            "RETURN_FAIL" : "FAILED"
        }

        parameters = { 'SMSProviderConfig' : json.dumps(sms_conf),
                       'selftest_admin' : 'superadmin'
                      }
        response = self.app.get(url(controller='system', action='setConfig'),
                                                            params=parameters)

        self.assertTrue('"status": true' in response, response)

        response = self.app.get(url(controller='validate', action='smspin'),
                                params={'user' : 'user1',
                                        'pass' : '1234'})

        self.assertTrue('Failed to send SMS. We received a'
                        ' predefined error from the SMS Gateway.' in response)

        return

###eof#########################################################################


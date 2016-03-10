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
Test HttpSms Gateway

These tests will only pass if you start a LinOTP server on 127.0.0.1.
For example with paster:

    paster serve test.ini

We assume port 5001 is used (default). If you want to use another port you can
specify it with nose-testconfig (e.g. --tc=paster.port:5005).
"""


from linotp.tests import TestController
from linotp.tests import url
from linotp.lib.util import str2unicode

import tempfile
try:
    import json
except ImportError:
    import simplejson as json

import logging
log = logging.getLogger(__name__)

DEFAULT_NOSE_CONFIG = {
    'paster': {
        'port': '5001',
        }
    }
try:
    from testconfig import config as nose_config
except ImportError as exc:
    print "You need to install nose-testconfig. Will use default values."
    nose_config = None


class TestHttpSmsController(TestController):
    '''
    Here the HTTP SMS Gateway functionality is tested.
    '''

    def setUp(self):
        '''
        This sets up all the resolvers and realms
        '''
        self.serials = ['sms01', 'sms02']
        self.max = 22
        for num in range(3, self.max):
            serial = "sms%02d" % num
            self.serials.append(serial)

        TestController.setUp(self)
        self.set_config_selftest()
        self.create_common_resolvers()
        self.create_common_realms()
        self.removeTokens()
        self.initTokens()
        self.initProvider()
        if nose_config and 'paster' in nose_config:
            self.paster_port = nose_config['paster']['port']
        else:
            self.paster_port = DEFAULT_NOSE_CONFIG['paster']['port']

    def tearDown(self):
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)


###############################################################################
    def removeTokens(self):
        for serial in self.serials:
            parameters = {'serial': serial}
            response = self.app.get(url(controller='admin', action='remove'),
                                    params=parameters)
            #log.error(response)
            self.assertTrue('"status": true' in response, response)

    def initTokens(self):
        '''
        Initialize the tokens
        '''

        parameters = {'serial': self.serials[0],
                      'otpkey': '1234567890123456789012345678901234567890' +
                                  '123456789012345678901234',
                      'realm': 'myDefRealm',
                      'type': 'sms',
                      'user': 'user1',
                      'pin': '1234',
                      'phone': '016012345678',
                      'selftest_admin': 'superadmin'
                      }
        response = self.app.get(url(controller='admin', action='init'),
                                params=parameters)

        self.assertTrue('"status": true' in response, response)

        parameters = {'serial': self.serials[1],
                      'otpkey': '1234567890123456789012345678901234567890' +
                                  '123456789012345678901234',
                      'realm': 'myDefRealm',
                      'user': 'user2',
                      'type': 'sms',
                      'pin': '1234',
                      'phone': '016022222222',
                      'selftest_admin': 'superadmin'
                      }
        response = self.app.get(url(controller='admin', action='init'),
                                                             params=parameters)

        self.assertTrue('"status": true' in response, response)

        for serial in self.serials[2:self.max]:
            parameters = {'serial': serial,
                          'otpkey': '1234567890123456789012345678901234567890' +
                                      '123456789012345678901234',
                          'realm': 'myDefRealm',
                          'type': 'sms',
                          'pin': '',
                          'phone': '+49 01602/2222-222',
                          'selftest_admin': 'superadmin'
                          }
            response = self.app.get(url(controller='admin', action='init'),
                                                                 params=parameters)

            self.assertTrue('"status": true' in response, response)

        return self.serials

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

    def test_missing_param(self):
        '''
        Missing parameter at the SMS Gateway config. send SMS will fail
        '''
        sms_conf = {
                "URL" : "http://localhost:%s/testing/http2sms" % self.paster_port,
                "PARAMETER" :
                    {"account" : "clickatel", "username" : "legit"},
                "SMS_TEXT_KEY":"text",
                "SMS_PHONENUMBER_KEY":"to",
                "HTTP_Method" : "GET",
                "RETURN_SUCCESS" : "ID",
                }

        parameters = {
                'SMSProvider': 'smsprovider.HttpSMSProvider.HttpSMSProvider',
                'SMSProviderConfig' : json.dumps(sms_conf),
                'selftest_admin' : 'superadmin'
                }
        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)

        self.assertTrue('"status": true' in response, response)

        # check the saved configuration
        response = self.app.get(url(controller='system', action='getConfig'),
                                {'key' : 'SMSProviderConfig'})

        self.assertIn(
            'http://localhost:%s/testing/http2sms' % self.paster_port,
            response,
            response
            )

        response = self.app.get(url(controller='validate', action='smspin')
                                , params={'user' : 'user1', 'pass' : '1234'})
        # due to security fix to prevent information leakage the response
        # of validate/check will be only true or false
        # but wont contain the following message anymore
        #    'Failed to send SMS. We received a'
        #                'Failed to send SMS.'
        self.assertTrue('"value": false' in response, response)

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

    def test_succesful_auth(self):
        '''
        Successful SMS sending (via smspin) and authentication
        '''
        sms_conf = { "URL" : "http://localhost:%s/testing/http2sms" % self.paster_port,
                     "PARAMETER" : { "account" : "clickatel",
                                    "username" : "legit" },
                    "SMS_TEXT_KEY":"text",
                    "SMS_PHONENUMBER_KEY":"destination",
                    "HTTP_Method" : "GET",
                    "RETURN_SUCCESS" : "ID"
                    }

        parameters = {
              'SMSProvider': 'smsprovider.HttpSMSProvider.HttpSMSProvider',
              'SMSProviderConfig': json.dumps(sms_conf),
               'selftest_admin': 'superadmin'
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

    def test_succesful_auth2(self):
        '''
        Successful SMS sending (via validate) and authentication
        '''
        sms_conf = {
            "URL" : "http://localhost:%s/testing/http2sms" % self.paster_port,
            "PARAMETER" : { "account" : "clickatel", "username" : "legit" },
            "SMS_TEXT_KEY":"text",
            "SMS_PHONENUMBER_KEY":"destination",
            "HTTP_Method" : "GET",
            "RETURN_SUCCESS" : "ID"
        }
        parameters = {
              'SMSProvider': 'smsprovider.HttpSMSProvider.HttpSMSProvider',
              'SMSProviderConfig': json.dumps(sms_conf),
              'selftest_admin': 'superadmin'
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

    def test_successful_SMS(self):
        '''
        Successful SMS sending with RETURN_FAILED
        '''
        sms_conf = {
            "URL" : "http://localhost:%s/testing/http2sms" % self.paster_port,
            "PARAMETER" : { "account" : "clickatel", "username" : "legit" },
            "SMS_TEXT_KEY":"text",
            "SMS_PHONENUMBER_KEY":"destination",
            "HTTP_Method" : "GET",
            "RETURN_FAILED" : "FAILED"
            }
        parameters = {
              'SMSProvider': 'smsprovider.HttpSMSProvider.HttpSMSProvider',
              'SMSProviderConfig': json.dumps(sms_conf),
              'selftest_admin': 'superadmin'
                }
        response = self.app.get(url(controller='system', action='setConfig'),
                                                            params=parameters)

        self.assertTrue('"status": true' in response, response)

        response = self.app.get(url(controller='validate', action='smspin'),
                                params={'user' : 'user1',
                                        'pass' : '1234'})

        self.assertTrue('"state"' in response, response)

        return

    def test_successful_File_SMS(self):
        '''
        Successful test of the File SMS Provider
        '''
        # locate the lookup file in the servers home
        here = self.appconf.get('here', None)

        # create a temporary filename, to avoid conflicts
        f = tempfile.NamedTemporaryFile(delete=False, dir=here)
        filename = f.name
        sms_conf = {"file": filename}
        parameters = {
              'SMSProvider': 'smsprovider.FileSMSProvider.FileSMSProvider',
              'SMSProviderConfig': json.dumps(sms_conf),
               'selftest_admin': 'superadmin'
              }
        response = self.app.get(url(controller='system', action='setConfig'),
                                                            params=parameters)

        self.assertTrue('"status": true' in response, response)

        response = self.app.get(url(controller='validate', action='check'),
                                params={'user': 'user1', 'pass': '1234',
                                        'message': 'Täst<otp>'})

        self.assertTrue('"message": "sms submitted"' in response, response)
        self.assertTrue('"state"' in response, response)

        with open(filename, 'r') as f:
            line = f.read()

        line = str2unicode(line)
        self.assertTrue(u'Täst' in line, u"'Täst' not found in line")

        _left, otp = line.split(u'Täst')
        response = self.app.get(url(controller='validate', action='check'),
                                params={'user': 'user1',
                                        'pass': '1234%s' % otp})

        self.assertTrue('"value": true' in response, response)

        import os
        os.remove(filename)
        return

    def test_failed_SMS(self):
        '''
        Failed SMS sending with RETURN_FAIL
        '''
        sms_conf = { "URL" : "http://localhost:%s/testing/http2sms" % self.paster_port,
            "PARAMETER" : {"account" : "clickatel", "username" : "anotherone"},
            "SMS_TEXT_KEY":"text",
            "SMS_PHONENUMBER_KEY":"destination",
            "HTTP_Method" : "GET",
            "RETURN_FAIL" : "FAILED",
            "MSISDN": True,
            "SUPPRESS_PREFIX" : '+',
        }

        parameters = {
              'SMSProvider': 'smsprovider.HttpSMSProvider.HttpSMSProvider',
              'SMSProviderConfig': json.dumps(sms_conf),
              'selftest_admin': 'superadmin'
                      }
        response = self.app.get(url(controller='system', action='setConfig'),
                                                            params=parameters)

        self.assertTrue('"status": true' in response, response)

        response = self.app.get(url(controller='validate', action='smspin'),
                                params={'user' : 'user1',
                                        'pass' : '1234'})

        # due to security fix to prevent information leakage the response
        # of validate/check will be only true or false
        # but wont contain the following message anymore
        #    'Failed to send SMS. We received a'
        #                ' predefined error from the SMS Gateway.
        self.assertTrue('"value": false' in response, response)
        return

    def setSMSProvider(self, preferred_httplib=None, method='GET',
                       return_check=None, PARAMETERS=None):
        """
        use the internal testing server for
        """
        sms_conf = {"URL": "http://localhost:%s/testing/http2sms"
                        % self.paster_port,
                    "PARAMETER": {"account": "clickatel", "username": "legit"},
                    "SMS_TEXT_KEY": "text",
                    "SMS_PHONENUMBER_KEY": "destination",
                    }

        # set the return check
        if not return_check:
            sms_conf["RETURN_SUCCESS"] = "ID"
        else:
            sms_conf.update(return_check)

        if PARAMETERS:
            sms_conf["PARAMETER"] = PARAMETERS

        sms_conf["HTTP_Method"] = method
        if preferred_httplib:
            sms_conf["PREFERRED_HTTPLIB"] = preferred_httplib

        parameters = {
              'SMSProvider': 'smsprovider.HttpSMSProvider.HttpSMSProvider',
              'SMSProviderConfig': json.dumps(sms_conf),
              'selftest_admin': 'superadmin'
            }

        response = self.app.get(url(controller='system', action='setConfig'),
                                params=parameters)

        self.assertTrue('"status": true' in response, response)
        return

    def test_httpsmsprovider_httplib(self):
        '''
        Test SMSProvider httplibs for working with GET and POST
        '''
        self.setSMSProvider(preferred_httplib='httplib', method='POST')

        response = self.app.get(url(controller='validate', action='check_s'),
                                params={'serial': self.serials[2],
                                        'pass': ''})
        self.assertTrue('"state":' in response,
                        "Expecting 'state' as challenge inidcator %r"
                        % response)

        self.setSMSProvider(preferred_httplib='httplib', method='GET')

        response = self.app.get(url(controller='validate', action='check_s'),
                                params={'serial': self.serials[3],
                                        'pass': ''})
        self.assertTrue('"state":' in response,
                        "Expecting 'state' as challenge inidcator %r"
                        % response)

    def test_httpsmsprovider_urllib(self):
        '''
        Test SMSProvider urllib for working with GET and POST
        '''

        self.setSMSProvider(preferred_httplib='urllib', method='POST')

        response = self.app.get(url(controller='validate', action='check_s'),
                                params={'serial': self.serials[4],
                                        'pass': ''})
        self.assertTrue('"state":' in response,
                        "Expecting 'state' as challenge inidcator %r"
                        % response)

        self.setSMSProvider(preferred_httplib='urllib', method='GET')

        response = self.app.get(url(controller='validate', action='check_s'),
                                params={'serial': self.serials[5],
                                        'pass': ''})
        self.assertTrue('"state":' in response,
                        "Expecting 'state' as challenge inidcator %r"
                        % response)

        return

    def test_httpsmsprovider_requests(self):
        '''
        Test SMSProvider 'requests' for working with GET and POST
        '''
        # now we check as well the requests lib if its available
        skip = False
        try:
            import requests
            requests.__version__
        except ImportError:
            skip = True

        if skip:
            skip_reason = "Httplib 'requests' not supported in this env!"
            if hasattr(self, "skipTest"):
                self.skipTest(skip_reason)
            else:
                log.error(skip_reason)
                return

        self.setSMSProvider(preferred_httplib='requests', method='POST')

        response = self.app.get(url(controller='validate',
                                    action='check_s'),
                                params={'serial': self.serials[6],
                                        'pass': ''})
        self.assertTrue('"state":' in response,
                        "Expecting 'state' as challenge inidcator %r"
                        % response)

        self.setSMSProvider(preferred_httplib='requests', method='GET')

        response = self.app.get(url(controller='validate',
                                    action='check_s'),
                                params={'serial': self.serials[7],
                                        'pass': ''})
        self.assertTrue('"state":' in response,
                        "Expecting 'state' as challenge inidcator %r"
                        % response)

        return

    def test_twilio_httpsmsprovider_httplib(self):
        '''
        Test Twilio as HttpSMSProvider which requires patter nmatch for result
        '''
        # TODO: Fix and re-enable twilio tests
        self.skipTest("Temporarily skip twilio tests due to known problems")

        args = [
         {'preferred_httplib': 'httplib', 'method': 'GET'},
         {'preferred_httplib': 'httplib', 'method': 'POST'},
        ]
        i = 7
        for arg in args:
            i = i + 1
            parameters = {"account": "twilio", "username": "legit"}
            arguments = {'return_check': {"RETURN_SUCCESS_REGEX":
                                              '<Status>queued</Status>'},
                         'PARAMETERS': parameters,
                         }
            arguments.update(arg)
            self.setSMSProvider(**arguments)

            response = self.app.get(url(controller='validate', action='check_s'),
                                    params={'serial': self.serials[i],
                                            'pass': ''})
            self.assertTrue('"state":' in response,
                            "Expecting 'state' %d: %r"
                            % (i, response))

            parameters = {"account": "twilio", "username": "fail"}
            arguments = {'return_check': {"RETURN_FAIL_REGEX":
                                            '<Status>400</Status>'},
                        'PARAMETERS': parameters,
                        }
            arguments.update(arg)
            self.setSMSProvider(**arguments)
            i = i + 1
            response = self.app.get(url(controller='validate', action='check_s'),
                                    params={'serial': self.serials[i],
                                            'pass': ''})
            self.assertTrue('predefined error from the SMS Gateway' in response,
                            "Expecting error %d: %r" % (i, response))

        return

    def test_twilio_httpsmsprovider_urllib(self):
        '''
        Test Twilio as HttpSMSProvider which requires patter nmatch for result
        '''
        # TODO: Fix and re-enable twilio tests
        self.skipTest("Temporarily skip twilio tests due to known problems")

        args = [
         {'preferred_httplib': 'urllib', 'method': 'GET'},
         {'preferred_httplib': 'urllib', 'method': 'POST'}
        ]

        i = 9
        for arg in args:
            i = i + 1
            parameters = {"account": "twilio", "username": "legit"}
            arguments = {'return_check': {"RETURN_SUCCESS_REGEX":
                                              '<Status>queued</Status>'},
                         'PARAMETERS': parameters,
                         }
            arguments.update(arg)
            self.setSMSProvider(**arguments)

            response = self.app.get(url(controller='validate', action='check_s'),
                                    params={'serial': self.serials[i],
                                            'pass': ''})
            self.assertTrue('"state":' in response,
                            "Expecting 'state' %d: %r"
                            % (i, response))

            parameters = {"account": "twilio", "username": "fail"}
            arguments = {'return_check': {"RETURN_FAIL_REGEX":
                                            '<Status>400</Status>'},
                        'PARAMETERS': parameters,
                        }
            arguments.update(arg)
            self.setSMSProvider(**arguments)
            i = i + 1
            response = self.app.get(url(controller='validate', action='check_s'),
                                    params={'serial': self.serials[i],
                                            'pass': ''})
            self.assertTrue('predefined error from the SMS Gateway' in response,
                            "Expecting error %d: %r" % (i, response))

        return

    def test_twilio_httpsmsprovider_requests(self):
        '''
        Test Twilio as HttpSMSProvider which requires patter nmatch for result
        '''
        # TODO: Fix and re-enable twilio tests
        self.skipTest("Temporarily skip twilio tests due to known problems")

        # now we check as well the requests lib if its available
        skip = False
        try:
            import requests
            requests.__version__
        except ImportError:
            skip = True

        if skip:
            skip_reason = "Httplib 'requests' not supported in this env!"
            if hasattr(self, "skipTest"):
                self.skipTest(skip_reason)
            else:
                log.error(skip_reason)
                return

        args = [
         {'preferred_httplib': 'requests', 'method': 'GET'},
         {'preferred_httplib': 'requests', 'method': 'POST'}
        ]

        i = 11
        for arg in args:
            i = i + 1
            parameters = {"account": "twilio", "username": "legit"}
            arguments = {'return_check': {"RETURN_SUCCESS_REGEX":
                                              '<Status>queued</Status>'},
                         'PARAMETERS': parameters,
                         }
            arguments.update(arg)
            self.setSMSProvider(**arguments)

            response = self.app.get(url(controller='validate', action='check_s'),
                                    params={'serial': self.serials[i],
                                            'pass': ''})
            self.assertTrue('"state":' in response,
                            "Expecting 'state' %d: %r"
                            % (i, response))

            parameters = {"account": "twilio", "username": "fail"}
            arguments = {'return_check': {"RETURN_FAIL_REGEX":
                                            '<Status>400</Status>'},
                        'PARAMETERS': parameters,
                        }
            arguments.update(arg)
            self.setSMSProvider(**arguments)
            i = i + 1
            response = self.app.get(url(controller='validate', action='check_s'),
                                    params={'serial': self.serials[i],
                                            'pass': ''})
            self.assertTrue('predefined error from the SMS Gateway' in response,
                            "Expecting error %d: %r" % (i, response))

        return

###eof#########################################################################


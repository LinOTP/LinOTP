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
Test challenge response functionality

These tests will only pass if you start a LinOTP server on 127.0.0.1.
For example with paster:

    paster serve test.ini

We assume port 5001 is used (default). If you want to use another port you can
specify it with nose-testconfig (e.g. --tc=paster.port:5005).
"""

import os
import binascii

import urllib
import httplib2

try:
    import json
except ImportError:
    import simplejson as json

from linotp.tests import TestController, url

from linotp.lib.HMAC import HmacOtp
from mock import patch
import smtplib
import re
import time

import smsprovider
import smsprovider.HttpSMSProvider
import smsprovider.SmtpSMSProvider

import logging
log = logging.getLogger(__name__)

DEFAULT_NOSE_CONFIG = {
    'radius': {
        'authport': '18012',
        'acctport': '18013',
        },
    'paster': {
        'port': '5001',
        }
    }
try:
    from testconfig import config as nose_config
except ImportError as exc:
    print "You need to install nose-testconfig. Will use default values."
    nose_config = None


def email_otp_func(call_args):
    '''
    callback to extract the otp value from the mock interface parameters

    :param call_args: arguments to the smtp.SMTP.sendmail method
    :return: the extracted otp value as string
    '''
    otp = None
    try:
        ordered_args = call_args[0]
        email_from = ordered_args[0]
        email_to = ordered_args[1]
        message = ordered_args[2]
        matches = re.search('\d{6}', message)
        otp = matches.group(0)
    except Exception as exx:
        pass
    return otp

def sms_otp_func(call_args):
    '''
    callback to extract the otp value from the mock interface parameters

    :param call_args: arguments to the smtp.SMTP.sendmail method
    :return: the extracted otp value as string
    '''
    otp = None
    try:
        ordered_args = call_args[0]
        phone = ordered_args[0]
        otp = ordered_args[1]
    except Exception as exx:
        pass
    return otp


def get_otp(counter=0, otpkey=None, mock_obj=None, otp_func=None, typ='hmac'):
    '''
    extract from the context the otp value
    - if we have a mock_obj and a extractor callback, we are using this one
    - else we take the given otp value and the secret to calculate the new one

    :param counter: counter base for the otp calculation
    :param otpkey: the otpkey secret
    :param mock_obj: the mock hooked function which recieved the parameters
    :param otp_func: the otp extractor function
    '''
    otp = None
    if mock_obj is not None:
        call_args = mock_obj.call_args
        # compare type of otp_func with known function
        if otp_func is not None and type(otp_func) == type(get_otp):
            otp = otp_func(call_args)

    if otp is None:
        counter = counter + 1
        otp = calcOTP(otpkey, counter=counter, typ=typ)

    return otp

def calcOTP(key, counter=0, digits=6, typ=None):
    '''
    as we have to use this method in a not class related function
    this function is extracted

    :param key: the otpkey secret
    :param counter: the related counter
    :param digits: the number of to be returned digits

    :return: the otp value as string
    '''
    htoken = HmacOtp(digits=digits)
    if typ == 'totp':
        log.warn("waiting for next time slot")
        timestep = 30
        time.sleep(timestep + 1)
        counter = int((time.time() / timestep) + 0.5)

    otp = htoken.generate(counter=counter, key=binascii.unhexlify(key))

    return otp


def do_http(remoteServer, params=None):

        if params is None:
            params = {}

        data = urllib.urlencode(params)
        request_url = "%s" % (remoteServer)

        # prepare the submit and receive headers
        headers = {"Content-type": "application/x-www-form-urlencoded",
                    "Accept": "text/plain"}
        if 'session' in params:
            headers['Cookie'] = "admin_session=%s" % params['session']

        # submit the request
        http = httplib2.Http()
        (resp, content) = http.request(request_url,
                                        method="POST",
                                        body=data,
                                        headers=headers)
        return content

class TestChallengeResponseController(TestController):

    def setUp(self):
        '''
        This sets up all the resolvers and realms
        '''
        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

        if hasattr(self, "policies") is False:
            setattr(self, "policies", [])

        if hasattr(self, "serials") is False:
            setattr(self, "serials", [])

        self.patch_smtp = None
        self.patch_sms = None

        self.delete_all_token()
        self.delete_all_policies()

        if nose_config and 'radius' in nose_config:
            self.radius_authport = nose_config['radius']['authport']
            self.radius_acctport = nose_config['radius']['acctport']
        else:
            self.radius_authport = DEFAULT_NOSE_CONFIG['radius']['authport']
            self.radius_acctport = DEFAULT_NOSE_CONFIG['radius']['acctport']

        if nose_config and 'paster' in nose_config:
            self.paster_port = nose_config['paster']['port']
        else:
            self.paster_port = DEFAULT_NOSE_CONFIG['paster']['port']

        return

    def tearDown(self):
        if self.patch_smtp is not None:
            self.patch_smtp.stop()
        if self.patch_sms is not None:
            self.patch_sms.stop()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestController.tearDown(self)

    def delete_all_policies(self):
        '''
        '''
        response = self.make_system_request(action='getPolicy')
        self.assertTrue('"status": true' in response, response)

        body = json.loads(response.body)
        policies = body.get('result', {}).get('value', {}).keys()

        for policy in policies:
            self.delete_policy(policy)

        return

    def calcOTP(self, key, counter=0, digits=6, typ='hmac'):
        otp = calcOTP(key, counter=counter, digits=digits, typ=typ)
        return otp

    def createToken(self, serial='F722362', user='root', pin="pin",
                    description="TestToken1", typ='hmac',
                    otpkey="AD8EABE235FC57C815B26CEF3709075580B44738",
                    phone=None,
                    email_address=None
                    ):

        params = {
            "serial": serial,
            "otpkey": otpkey,
            "user": user,
            "pin": pin,
            "type": typ,
            "description": description,
            'session': self.session,
            }
        if phone is not None:
            params['phone'] = phone
        if email_address is not None:
            params['email_address'] = email_address

        response = self.make_admin_request(action='init', params=params)
        self.assertTrue('"value": true' in response, response)
        self.serials.append(serial)
        return serial

    def setPinPolicy(self, name='otpPin', realm='ldap_realm',
                     action='otppin=1, ', scope='authentication',
                     active=True, remoteurl=None):
        params = {
            'name': name,
            'user': '*',
            'action': action,
            'scope': scope,
            'realm': realm,
            'time': '',
            'client': '',
            'active': active,
            'session': self.session,
            }

        r_url = url(controller='system', action='setPolicy')

        if remoteurl is not None:
            r_url = "%s/%s" % (remoteurl, "system/setPolicy")
            response = do_http(r_url, params=params)
        else:
            response = self.app.get(r_url, params=params)



        self.assertTrue('"status": true' in response, response)


        r_url = url(controller='system', action='getPolicy')

        if remoteurl is not None:
            r_url = "%s/%s" % (remoteurl, "system/getPolicy")
            response = do_http(r_url, params=params)
        else:
            response = self.app.get(r_url, params=params)

        self.assertTrue('"status": true' in response, response)


        self.policies.append(name)
        return response

    def delete_remote_policy(self, name, url):
        """
        Delete policy on remote LinOTP found at url
        """
        params = {
            'name': name,
            'selftest_admin': 'superadmin',
            'session': self.session,
            }

        r_url = "%s/%s" % (url, "system/delPolicy")
        response = do_http(r_url, params=params)

    def setup_remote_token(self,
                           typ="pw",
                           otpkey="123456",
                           remoteurl=None):
        if remoteurl is None:
            remoteurl = "http://127.0.0.1:%s" % self.paster_port
        # local token
        serials = []
        params_list = [
                  # the token set with remote pin checking
                  {
                        "serial"  : "LSRE001",
                        "type"    : "remote",
                        "otpkey"  : otpkey,
                        "otppin"  : "",
                        "user"    : "remoteuser",
                        "pin"     : "lpin",
                        "description" : "RemoteToken1",
                        'remote.server' : remoteurl,
                        'remote.local_checkpin' : 0,
                        'remote.serial' : 'LSPW1',
                        'session': self.session,
                      },
                  { # the target is accessed via serial, so no user is required
                        "serial"  : "LSPW1",
                        "type"    : typ,
                        "otpkey"  : otpkey,
                        "otppin"  : "",
                        "user"    : "",
                        "pin"     : "rpin",
                        'session': self.session,
                  },
                  # the token set with local pin checking
                  {
                        "serial"  : "LSRE002",
                        "type"    : "remote",
                        "otpkey"  : otpkey,
                        "user"    : "localuser",
                        "pin"     : "lpin",
                        "description" : "RemoteToken2",
                        'remote.server' : remoteurl,
                        'remote.local_checkpin' : 1,
                        'remote.serial' : 'LSPW2',
                        'session': self.session,
                        },
                  { # the target is accessed via serial, so no user is required
                        "serial"  : "LSPW2",
                        "type"    : typ,
                        "otpkey"  : otpkey,
                        "otppin"  : "",
                        "user"    : "",
                        "pin"     : "",
                        'session': self.session,
                         },
                  ]
        for params in params_list:
            serials.append(params.get('serial'))
            response = self.make_admin_request(action='init', params=params)
            self.assertTrue('"value": true' in response, response)

        # enforce the awareness of policy changes
        params = {
            'enableReplication': 'true',
            'session': self.session,
            }
        resp = self.make_system_request(action='setConfig', params=params)
        assert('"setConfig enableReplication:true": true' in resp)

        params = {
            'enableReplication': 'true',
            'session': self.session,
            }
        resp = do_http(
            "%s/system/setConfig" % remoteurl,
            params=params,
            )
        assert('"setConfig enableReplication:true": true' in resp)

        return serials

    def setup_radius_token(self):

        serials = []

        # The token with the remote PIN
        params_list = [{
                      "serial"  : "radius1",
                      "type"    : "radius",
                      "otpkey"  : "1234567890123456",
                      "otppin"  : "",
                      "user"    : "remoteuser",
                      "pin"     : "",
                      "description" : "RadiusToken1",
                      'radius.server' : 'localhost:%s' % self.radius_authport,
                      'radius.local_checkpin' : 0,
                      'radius.user' : 'challenge',
                      'radius.secret' : 'testing123',
                      'session': self.session,
                      },

                    # the token with the local PIN
                    {
                      "serial"  : "radius2",
                      "type"    : "radius",
                      "otpkey"  : "1234567890123456",
                      "otppin"  : "local",
                      "user"    : "localuser",
                      "pin"     : "local",
                      "description" : "RadiusToken2",
                      'radius.server' : 'localhost:%s' % self.radius_authport,
                      'radius.local_checkpin' : 1,
                      'radius.user' : 'user_no_pin',
                      'radius.secret' : 'testing123',
                      'session': self.session,
                      },
                     ]
        for params in params_list:
            response = self.make_admin_request(action='init', params=params)
            self.assertTrue('"value": true' in response, response)
            serials.append(params.get("serial"))

        return serials

    def _start_radius_server(self):
        """
        Start the dummy radius server

        We need to start the radius server for every test, since every test instatiates a new TestClass and thus the
        radius server process will not be accessable outside of a test anymore
        """
        import subprocess
        try:
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
        except Exception as exx:
            raise exx
        assert self.p is not None

    def _stop_radius_server(self):
        '''
        stopping the dummy radius server
        '''
        if self.p:
            r = self.p.kill()
            log.debug(r)

        return

    def test_03_hmac_regression(self):
        '''
        Challenge Response Test: test if HMAC tokens still works -
                this is a potential challenge token
        '''

        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"
        # normal test
        serial = self.createToken(pin="shortpin", otpkey=otpkey,
                                                    user='passthru_user1')

        otp = self.calcOTP(otpkey, counter=counter)
        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1", "pass": "shortpin" + otp}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": true' in response, response)
        self.delete_token(serial)


        # with otppin==1 the pin should be the same
        self.setPinPolicy(realm='myDefRealm', action='otppin=1, ')

        serial = self.createToken(pin="otppin", user='passthru_user1')

        otp = self.calcOTP(otpkey, counter=counter)
        params = {"user": "passthru_user1", "pass": "geheim1" + otp}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        self.assertTrue('"value": true' in response, response)
        self.delete_token(serial)

        self.delete_policy('otpPin')

        # with otppin==2 the pin is not required at all
        self.setPinPolicy(realm='myDefRealm', action='otppin=2, ')

        serial = self.createToken(pin="otppin", user='passthru_user1')
        otp = self.calcOTP(otpkey, counter=1)
        params = {"user": "passthru_user1", "pass": otp}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        self.assertTrue('"value": true' in response, response)

        # finally otppin == 2 and wrong otp would trigger
        params = {"user": "passthru_user1", "pass": "123456"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        if '"value": true' not in response:
            log.error(response)
        self.assertTrue('"value": false' in response, response)
        self.assertTrue('transactionid"' not in response, response)

        self.setPinPolicy(name="ch_resp", realm='myDefRealm',
                                            action='challenge_response=hmac, ')

        # no challenge request - empty pin + otp does not match
        params = {"user": "passthru_user1", "pass": "123456"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        if '"value": true' not in response:
            log.error(response)
        self.assertTrue('"value": false' in response, response)
        self.assertTrue('transactionid"' not in response, response)

        self.delete_token(serial)
        self.delete_policy(name="ch_resp")

        return


    def test_02_spass_regression(self):
        '''
        Challenge Response Test: test if SPASS tokens still work - it is a no challenge token
        '''

        # normal test
        serial = self.createToken(pin="shortpin", typ='spass',
                                                        user='passthru_user1')

        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": true' in response, response)
        self.delete_token(serial)


        # with otppin==1 the pin should be the same
        self.setPinPolicy(realm='myDefRealm')
        serial = self.createToken(pin="otppin", typ='spass',
                                  user='passthru_user1')

        params = {"user": "passthru_user1", "pass": "geheim1"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        self.assertTrue('"value": true' in response, response)
        self.delete_token(serial)
        self.delete_policy('otpPin')

        # with otppin==2 the pin is not required at all
        self.setPinPolicy(realm='myDefRealm', action='otppin=2, ')
        serial = self.createToken(pin="otppin", typ='spass',
                                  user='passthru_user1')

        params = {"user": "passthru_user1", "pass": ""}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        self.assertTrue('"value": true' in response, response)
        self.delete_token(serial)
        self.delete_policy('otpPin')

        return

    def test_09_remote_regression(self):
        '''
        Challenge Response Test: regression remoteToken can splits passw localy or remote
        '''

        serials = self.setup_remote_token()

        params = {"user": "remoteuser", "pass": "rpin123456"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        params = {"user": "localuser", "pass": "lpin123456"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertTrue('"value": true' in response, response)

        for serial in serials:
            self.delete_token(serial)
        return


    def test_11_hmac_challenge_otppin1(self):
        '''
        Challenge Response Test: test hmac token with otppin=1 and challenge response
        '''

        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"

        # with otppin==1 the pin should be the same
        self.setPinPolicy(realm='myDefRealm', action='otppin=1, ')

        serial = self.createToken(pin="otppin", user='passthru_user1')


        otp = self.calcOTP(otpkey, counter=counter)
        params = {"user": "passthru_user1", "pass": "geheim1" + otp}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        self.assertTrue('"value": true' in response, response)
        self.delete_token(serial)

        self.delete_policy('otpPin')

        # with otppin==2 the pin is not required at all
        self.setPinPolicy(realm='myDefRealm', action='otppin=2, ')

        otp = self.calcOTP(otpkey, counter=counter)
        serial = self.createToken(pin="otppin", user='passthru_user1')
        params = {"user": "passthru_user1", "pass": otp}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        self.assertTrue('"value": true' in response, response)
        self.delete_token(serial)

        self.delete_policy('otpPin')

        return

    def test_01_hmac_challenge_std(self):
        '''
        Challenge Response Test: test if HMAC tokens still works - this is a potential challenge token
        '''
        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"
        # normal test
        serial = self.createToken(pin="shortpin", otpkey=otpkey,
                                                    user='passthru_user1')

        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": false' in response, response)
        self.assertTrue('"transactionid":' not in response, response)

        self.setPinPolicy(name="ch_resp", realm='myDefRealm',
                                            action='challenge_response=hmac, ')

        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": false' in response, response)
        self.assertTrue('"transactionid":' in response, response)

        # in the response we expect an transaction reference (=state)
        # and a reply message message
        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', None)
        self.assertNotEqual(state, None, response)

        # submit a otp only challenge response
        otp = self.calcOTP(otpkey, counter=counter)
        params = {"user": "passthru_user1", "pass": otp}
        params['transactionid'] = state
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": true' in response, response)


        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": false' in response, response)
        self.assertTrue('"transactionid":' in response, response)

        # in the response we expect an transaction reference (=state)
        # and a reply message message
        body = json.loads(response.body)
        state = body.get('detail').get('transactionid')


        # submit a pin + otp challenge response
        counter = counter + 1
        otp = self.calcOTP(otpkey, counter=counter)
        params = {"user": "passthru_user1", "pass": otp}
        params['transactionid'] = state
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": true' in response, response)

        # now create two open challenges

        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": false' in response, response)
        self.assertTrue('"transactionid":' in response, response)

        # in the response we expect an transaction reference (=state)
        # and a reply message message
        body = json.loads(response.body)
        state = body.get('detail').get('transactionid')

        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": false' in response, response)
        self.assertTrue('"transactionid":' in response, response)

        # in the response we expect an transaction reference (=state)
        # and a reply message message
        body = json.loads(response.body)
        state = body.get('detail').get('transactionid')


        # submit a pin + otp challenge response
        counter = counter + 1
        otp = self.calcOTP(otpkey, counter=counter)
        params = {"user": "passthru_user1", "pass": otp}
        params['transactionid'] = state
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": true' in response, response)



        self.delete_token(serial)

        self.delete_policy(name="ch_resp")
        return

    def test_10_multiple_tokens(self):
        """
        Challenge Response Test: authentication of multiple tokens using the transactionid

        Remark:
            with the hmac token, the transaction is not bound to a counter!
        """

        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"

        self.setPinPolicy(name="ch_resp", realm='myDefRealm',
                                       action='challenge_response=hmac topt,')

        serial = self.createToken(serial="H1", pin="h1", otpkey=otpkey,
                                  user='passthru_user1', typ='hmac')

        serial = self.createToken(serial="H2", pin="h2", otpkey=otpkey,
                                  user='passthru_user1', typ='hmac')

        # submit a pin only request - to trigger a challenge
        for _i in range(1, 3):

            params = {"user": "passthru_user1", "pass": "h1"}
            response = self.app.get(url(controller='validate',
                                        action='check'), params=params)

            self.assertTrue('"value": false' in response, response)
            self.assertTrue('"transactionid":' in response, response)


            # submit a pin only request - to trigger a challenge
            params = {"user": "passthru_user1", "pass": "h2"}
            response2 = self.app.get(url(controller='validate',
                                         action='check'), params=params)

            self.assertTrue('"value": false' in response2, response2)
            self.assertTrue('"transactionid":' in response2, response2)

            counter = counter + 1

        # in the response we expect an transaction reference (=state)
        body = json.loads(response.body)
        state1 = body.get('detail').get('transactionid')

        body = json.loads(response2.body)
        state2 = body.get('detail').get('transactionid')

        # have a look, if all challenges are removed
        params = {
            "user": "passthru_user1",
            'session': self.session,
            }
        response = self.make_admin_request(action='checkstatus', params=params)
        self.assertTrue(state2 in response, response)

        # now check if the challenge could be identified by the last transaction
        otp = self.calcOTP(otpkey, counter=counter - 1)
        params = {"user": "passthru_user1", "pass": otp}
        params['transactionid'] = state2
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": true' in response, response)

        # have a look, if all challenges are removed
        params = {
            "user": "passthru_user1",
            'session': self.session,
            }
        response = self.make_admin_request(action='checkstatus', params=params)
        self.assertTrue(state2 not in response, response)

        # reusage of the challenge should not work
        otp = self.calcOTP(otpkey, counter=counter)
        params = {"user": "passthru_user1", "pass": otp, 'state':state2}
        params['transactionid'] = state2
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": false' in response, response)

        # but the challenge for the other token should still be valid
        otp = self.calcOTP(otpkey, counter=counter)
        params = {"user": "passthru_user1", "pass": otp, 'state':state1}
        params['transactionid'] = state1
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": true' in response, response)

        # have a look, if all challenges are removed
        params = {
            "user": "passthru_user1",
            'session': self.session,
            }
        response = self.make_admin_request(action='checkstatus', params=params)

        # assure that all challenges are removed
        self.assertTrue(state2 not in response, response)
        self.assertTrue(state1 not in response, response)


        self.delete_token("H1")
        self.delete_token("H2")

        self.delete_policy(name="ch_resp")
        return


    def test_12_sms_otppin(self):
        '''
        Challenge Response Test: SMS token challenge with otppin=1
        '''
        params = {
            'SMSProvider': 'smsprovider.HttpSMSProvider.HttpSMSProvider',
            'selftest_admin': 'superadmin',
            'session': self.session,
            }
        _response = self.make_system_request(action='setConfig', params=params)
        sms_conf = {"URL": "http://localhost:%s/testing/http2sms" %
                        self.paster_port,
                    "PARAMETER": {"account": "clickatel",
                                   "username": "legit"},
                    "SMS_TEXT_KEY": "text",
                    "SMS_PHONENUMBER_KEY": "destination",
                    "HTTP_Method" : "GET",
                    "RETURN_SUCCESS" : "ID"
                    }

        params = {
            'SMSProviderConfig': json.dumps(sms_conf),
            'selftest_admin': 'superadmin',
            'session': self.session,
            }

        response = self.make_system_request(action='setConfig', params=params)
        log.error(response)
        self.assertTrue('"status": true' in response, response)

        # Patch (replace) smsprovider.HttpSMSProvider.HttpSMSProvider class
        # class to prevent sms from being sent out
        self.patch_sms = patch('smsprovider.HttpSMSProvider.HttpSMSProvider',
                             spec=smsprovider.HttpSMSProvider.HttpSMSProvider)
        mock_sms_class = self.patch_sms.start()
        mock_sms_instance = mock_sms_class.return_value
        mock_sms_instance.submitMessage.return_value = True
        mock_obj = mock_sms_instance.submitMessage

        typ = "sms"
        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"

        # normal test
        serial = self.createToken(pin="shortpin", typ='sms', phone='12345',
                                        otpkey=otpkey, user='passthru_user1')

        # trigger challenge
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": false' in response, response)

        otp = get_otp(counter, otpkey, mock_obj, sms_otp_func, typ)
        params = {"user": "passthru_user1", "pass": "shortpin" + otp}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertTrue('"value": true' in response, response)

        # now test same with otppin policy
        self.setPinPolicy(realm='myDefRealm', action='otppin=1, ')


        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1", "pass": "geheim1"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": false' in response, response)

        # validate sms
        otp = get_otp(counter, otpkey, mock_obj, sms_otp_func, typ)
        params = {"user": "passthru_user1", "pass": "geheim1" + otp}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        self.assertTrue('"value": true' in response, response)

        # now try same with a wron challenge reply

        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1", "pass": "geheim1"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": false' in response, response)

        # validate sms
        otp = get_otp(counter, otpkey, mock_obj, sms_otp_func, typ)
        params = {"user": "passthru_user1", "pass": "geheim2" + otp}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        self.assertTrue('"value": false' in response, response)


        self.delete_token(serial)
        self.delete_policy('otpPin')

        return

    def test_16_remote_token_remote_challenge(self):
        '''
        Challenge Response Test: remoteToken with with remote pin check
        '''
        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"
        user = "remoteuser"
        remoteurl = "http://127.0.0.1:%s" % self.paster_port

        # setup the remote token pairs
        serials = self.setup_remote_token(typ="hmac", otpkey=otpkey,
                                          remoteurl=remoteurl)

        # now switch policy on for challenge_response for hmac token
        response = self.setPinPolicy(name="ch_resp", realm='*',
                                action='challenge_response=hmac remote')
        self.assertTrue('"status": true,' in response, response)

        response = self.setPinPolicy(name="ch_resp", realm='*',
                                action='challenge_response=hmac remote',
                                remoteurl=remoteurl)
        self.assertTrue('"status": true,' in response, response)

        # 1. part - pin belongs to remote token
        # check is simple auth works
        otp = calcOTP(key=otpkey, counter=counter, typ="hmac")
        params = {"user": user, "pass": "rpin" + otp}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertTrue('"value": true' in response, response)

        # 1.1 now trigger a challenge
        otp = calcOTP(key=otpkey, counter=counter + 1, typ="hmac")
        params = {"user": user, "pass": "rpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertTrue('"value": false' in response, response)

        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', '')
        self.assertTrue(state != '', response)

        # 1.2 check the challenge
        otp = calcOTP(key=otpkey, counter=counter + 1, typ="hmac")
        params = {"user": user, "pass": otp, "state" : state}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        # hey, if this ok, we are done for the remote pin check
        self.assertTrue('"value": true' in response, response)

        for serial in serials:
            self.delete_token(serial)

        self.delete_policy(name="ch_resp")
        self.delete_remote_policy("ch_resp", remoteurl)

        return

    def test_17_remote_token_local_challenge(self):
        '''
        Challenge Response Test: remoteToken with with local pin check
        '''
        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"
        user = "localuser"
        remoteurl = "http://127.0.0.1:%s" % self.paster_port

        # setup the remote token pairs
        serials = self.setup_remote_token(typ="hmac",
                                          otpkey=otpkey,
                                          remoteurl=remoteurl)

        # now switch policy on for challenge_response for hmac token
        response = self.setPinPolicy(name="ch_resp",
                                     realm='*',
                                     action='challenge_response=hmac remote')
        self.assertTrue('"status": true,' in response, response)

        response = self.setPinPolicy(name="ch_resp",
                                     realm='*',
                                     action='challenge_response=hmac remote',
                                     remoteurl=remoteurl)

        # now we have to test the local pin
        # when using the local pin, we will keep the challenge in the
        # src token

        # 1. part - pin belongs to local token - remote has no pin
        # check is simple auth works
        otp = calcOTP(key=otpkey, counter=counter, typ="hmac")
        params = {"user": user, "pass": "lpin" + otp}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertTrue('"value": true' in response, response)

        # 2.1 now trigger a challenge
        counter = counter + 1
        otp = calcOTP(key=otpkey, counter=counter, typ="hmac")
        params = {"user": user, "pass": "lpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertTrue('"value": false' in response, response)

        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', '')
        self.assertTrue(state != '', response)

        # 2.2 check the challenge
        counter = counter + 1
        otp = calcOTP(key=otpkey, counter=counter, typ="hmac")
        params = {"user": user, "pass": otp, "state" : state}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        # hey, if this ok, we are done for the remote pin check
        self.assertTrue('"value": true' in response, response)

        for serial in serials:
            self.delete_token(serial)

        self.delete_policy(name="ch_resp")
        self.delete_remote_policy("ch_resp", remoteurl)

        return

    def test_22_radiustoken_remote_pin(self):
        """
        Challenge Response Test: radius token with remote PIN
        """
        serials = self.setup_radius_token()

        self._start_radius_server()
        user = "remoteuser"
        otp = "test123456"

        # now switch policy on for challenge_response for hmac token
        response = self.setPinPolicy(name="ch_resp", realm='*',
                                action='challenge_response=radius')
        self.assertTrue('"status": true,' in response, response)

        # 1.1 now trigger a challenge
        params = {"user": user, "pass": "test"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertTrue('"value": false' in response, response)

        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', '')
        self.assertTrue(state != '', response)

        # 1.2 check the challenge
        params = {"user": user, "pass": otp, "state" : state}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        # hey, if this ok, we are done for the remote pin check
        self.assertTrue('"value": true' in response, response)

        self._stop_radius_server()

        for serial in serials:
            self.delete_token(serial)

        return

    def test_23_radiustoken_local_pin(self):
        """
        Challenge Response Test: radius token with local PIN
        """
        serials = self.setup_radius_token()
        self._start_radius_server()

        user = "localuser"
        otp = "654321"

        # now switch policy on for challenge_response for hmac token
        response = self.setPinPolicy(name="ch_resp", realm='*',
                                action='challenge_response=radius')
        self.assertTrue('"status": true,' in response, response)

        # 1.1 now trigger a challenge
        params = {"user": user, "pass": "local"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertTrue('"value": false' in response, response)

        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', '')
        self.assertTrue(state != '', response)

        # 1.2 check the challenge
        params = {"user": user, "pass": otp, "state" : state}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        # hey, if this ok, we are done for the remote pin check
        self.assertTrue('"value": true' in response, response)

        self._stop_radius_server()

        for serial in serials:
            self.delete_token(serial)

        return

    def do_auth(self, pin='',
                    counter=0,
                    otpkey="AD8EABE235FC57C815B26CEF3709075580B44738",
                    typ='hmac',
                    mock_obj=None,
                    otp_func=None,
                    user='passthru_user1',
                    ):
        """
        run a set of different authentication schemes:
        * std auth with pin+otp
        * challenge + response w. pin+otp
        * challenge + response w. transid+otp

        :param pin: the pin, depending on otppin policy: pin/pass/empty
        :param counter: the counter increment to provide the correct otp
        :param otpkey: the key to calculate the next otp

        :return: the last otpcount to continue authentication
        """


        if typ not in  ['email', 'sms']:
            # 1 std auth with user with pin+otp
            counter = counter + 1
            otp = self.calcOTP(otpkey, counter=counter, typ=typ)
            params = {"user": user, "pass": pin + otp}
            response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
            self.assertTrue('"value": true' in response, response)

        # 2. challenge response with pin+otp
        # 2.1. challenge
        params = {"user": user, "pass": pin, }
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": false' in response, response)

        # 2.2 response
        counter = counter + 1
        otp = get_otp(counter, otpkey, mock_obj, otp_func, typ=typ)
        params = {"user": user, "pass": pin + otp}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": true' in response, response)

        # 3. challenge response with otp+state
        # 3.1 trigger challenge
        params = {"user": user, "pass": pin}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": false' in response, response)

        body = json.loads(response.body)
        state = body.get('detail').get('transactionid')

        # 3.2 response
        counter = counter + 1
        otp = get_otp(counter, otpkey, mock_obj, otp_func, typ=typ)
        params = {"user": user, "pass": otp, "state" : state}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": true' in response, response)

        # 4 std auth with user with pin+otp though outstanding challenge
        # 4.1 trigger challenge
        params = {"user": user, "pass": pin}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": false' in response, response)

        # 4.2 do std auth
        counter = counter + 1
        otp = get_otp(counter, otpkey, mock_obj, otp_func, typ=typ)
        params = {"user": user, "pass": pin + otp}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": true' in response, response)

        return counter

    def test_50_hmac_auth(self):
        '''
        Challenge Response Test: hmac token challenge with otppin=1 + otppin=2
        '''

        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"

        serial = self.createToken(pin="shortpin", typ='hmac',
                                        otpkey=otpkey, user='passthru_user1')

        # now switch policy on for challenge_response
        response = self.setPinPolicy(name="ch_resp", realm='myDefRealm',
                                action='challenge_response=hmac,')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("shortpin", counter)

        # with otppin==1 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm', action='otppin=1, ')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("geheim1", counter + 1)

        # with otppin==2 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm', action='otppin=2, ')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("", counter + 1)

        self.delete_token(serial)
        self.delete_policy(name="ch_resp")
        self.delete_policy(name="otpPin")

        return


    def test_51_sms_auth(self):
        '''
        Challenge Response Test: sms token challenge with otppin=1 + otppin=2
        '''
        typ = 'sms'
        params = {
            'SMSProvider': 'smsprovider.HttpSMSProvider.HttpSMSProvider',
            'selftest_admin': 'superadmin',
            'session': self.session,
            }
        _response = self.make_system_request(action='setConfig', params=params)

        sms_conf = {"URL": "http://localhost:%s/testing/http2sms" %
                    self.paster_port,
                    "PARAMETER": {"account": "clickatel",
                                  "username": "legit"},
                    "SMS_TEXT_KEY": "text",
                    "SMS_PHONENUMBER_KEY": "destination",
                    "HTTP_Method": "GET",
                    "RETURN_SUCCESS": "ID"
                    }

        params = {
            'SMSProviderConfig': json.dumps(sms_conf),
            'selftest_admin': 'superadmin',
            'session': self.session,
            }

        response = self.make_system_request(action='setConfig', params=params)
        log.error(response)
        self.assertTrue('"status": true' in response, response)

        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"

        serial = self.createToken(pin="shortpin", typ='sms', phone="123456",
                                        otpkey=otpkey, user='passthru_user1')

        # Patch (replace) smsprovider.HttpSMSProvider.HttpSMSProvider class
        # class to prevent sms from being sent out
        self.patch_sms = patch('smsprovider.HttpSMSProvider.HttpSMSProvider',
                             spec=smsprovider.HttpSMSProvider.HttpSMSProvider)
        mock_sms_class = self.patch_sms.start()
        mock_sms_instance = mock_sms_class.return_value
        mock_sms_instance.submitMessage.return_value = True
        mock_obj = mock_sms_instance.submitMessage

        # sms token should do challenge response even without policy
        counter = self.do_auth("shortpin", counter, typ=typ,
                                            mock_obj=mock_obj,
                                            otp_func=sms_otp_func
                                            )

        # now switch policy on for challenge_response - should not harm
        response = self.setPinPolicy(name="ch_resp", realm='myDefRealm',
                                action='challenge_response=hmac topt sms,')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("shortpin", counter, typ=typ,
                                            mock_obj=mock_obj,
                                            otp_func=sms_otp_func
                                            )

        # with otppin==1 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm', action='otppin=1, ')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("geheim1", counter, typ=typ,
                                            mock_obj=mock_obj,
                                            otp_func=sms_otp_func
                                            )

        # with otppin==2 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm', action='otppin=2, ')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("", counter, typ=typ,
                                            mock_obj=mock_obj,
                                            otp_func=sms_otp_func
                                            )
        self.delete_token(serial)
        self.delete_policy(name="ch_resp")
        self.delete_policy(name="otpPin")

        return


    def test_52_email_auth(self):
        """
        Challenge Response Test: email token challenge with otppin=1 + otppin=2
        """
        typ = 'email'

        params = {
            'EmailProvider': 'linotp.lib.emailprovider.SMTPEmailProvider',
            'EmailProviderConfig': '{ "SMTP_SERVER": "mail.example.com",\
                               "SMTP_USER": "secret_user",\
                               "SMTP_PASSWORD": "secret_pasword" }',
            'EmailChallengeValidityTime': 300,
            'EmailBlockingTimeout': 0,
            'session': self.session,
            }
        response = self.make_system_request(action='setConfig', params=params)
        self.assertTrue('"status": true' in response, response)

        # Patch (replace) smtplib.SMTP class to prevent e-mails from being sent out
        self.patch_smtp = patch('smtplib.SMTP', spec=smtplib.SMTP)
        mock_smtp_class = self.patch_smtp.start()
        mock_smtp_instance = mock_smtp_class.return_value
        mock_smtp_instance.sendmail.return_value = []
        mock_obj = mock_smtp_instance.sendmail

        # Enroll token
        pin = "shortpin"
        description = "E-mail token enrolled in functional tests",
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"

        serial = self.createToken(pin=pin,
                                typ=typ,
                                email_address='paul@example.com',
                                description="email token",
                                otpkey=otpkey,
                                user='passthru_user1')

        counter = 0

        # email token should do challenge response even without policy
        counter = self.do_auth("shortpin", counter, typ=typ,
                                            mock_obj=mock_obj,
                                            otp_func=email_otp_func
                                            )

        # now switch policy on for challenge_response - should not harm
        response = self.setPinPolicy(name="ch_resp", realm='myDefRealm',
                                action='challenge_response=hmac email,')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("shortpin", counter, typ=typ,
                                            mock_obj=mock_obj,
                                            otp_func=email_otp_func
                                            )

        # with otppin==1 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm',
                                                    action='otppin=1, ')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("geheim1", counter, typ=typ,
                                            mock_obj=mock_obj,
                                            otp_func=email_otp_func
                                            )

        # with otppin==2 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm',
                                                    action='otppin=2, ')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("", counter, typ=typ,
                                            mock_obj=mock_obj,
                                            otp_func=email_otp_func
                                            )

        return

    def test_54_totp_auth(self):
        '''
        Challenge Response Test: totp token challenge with otppin=1 + otppin=2
        '''

        typ = 'totp'
        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"

        serial = self.createToken(pin="shortpin", typ=typ,
                                        otpkey=otpkey, user='passthru_user1')

        # now switch policy on for challenge_response
        response = self.setPinPolicy(name="ch_resp", realm='myDefRealm',
                                action='challenge_response=hmac totp,')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("shortpin", counter, typ=typ)

        # with otppin==1 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm', action='otppin=1, ')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("geheim1", counter + 1, typ=typ)

        # with otppin==2 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm', action='otppin=2, ')
        self.assertTrue('"status": true,' in response, response)

        counter = self.do_auth("", counter + 1, typ=typ)

        self.delete_token(serial)
        self.delete_policy(name="ch_resp")
        self.delete_policy(name="otpPin")

        return

    def test_60_hmac_two_tokens(self):
        '''
        Challenge Response Test: two hmac token in different realms

        test with
        * passthru_user1 - using default realm - using  token2
        * passthru_user1@myMixRealm .- using token1
        * passthru_user1@myDefRealm - using token2

        in combination with optpin=1 and otppin=2
        '''
        typ = "hmac"

        # now switch policy on for challenge_response
        response = self.setPinPolicy(name="ch_resp1", realm='myDefRealm',
                                action='challenge_response=hmac,')
        self.assertTrue('"status": true,' in response, response)

        response = self.setPinPolicy(name="ch_resp2", realm='myMixRealm',
                                action='challenge_response=hmac,')
        self.assertTrue('"status": true,' in response, response)

        counter1 = 0
        counter2 = 0

        otpkey1 = "AD8EABE235FC57C815B26CEF3709075580B44738"
        otpkey2 = "38AD8EABE235FC57C815B26CEF3709075580B447"

        serial1 = self.createToken(serial='myMixRealm', pin="shortpin",
                        typ=typ, otpkey=otpkey1,
                        user='passthru_user1@myMixRealm')

        serial2 = self.createToken(serial='myDefRealm', pin="shortpin",
                        typ=typ, otpkey=otpkey2,
                        user='passthru_user1@myDefRealm')

        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": false' in response, response)
        self.assertTrue('"transactionid":' in response, response)

        # in the response we expect a transaction reference (=state)
        # and a reply message
        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', '')
        self.assertTrue(len(state) > 0, body)

        counter2 = counter2 + 1
        otp = get_otp(counter2, otpkey2, None, None, typ)
        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1", "pass": otp, "state":state}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": true' in response, response)

        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1@myMixRealm", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": false' in response, response)
        self.assertTrue('"transactionid":' in response, response)

        # in the response we expect a transaction reference (=state)
        # and a reply message
        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', '')
        self.assertTrue(len(state) > 0, body)

        counter1 = counter1 + 1
        otp = get_otp(counter1, otpkey1, None, None, typ)
        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1@myMixRealm",
                                                "pass": otp, "state":state}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": true' in response, response)

        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1@myDefRealm", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": false' in response, response)
        self.assertTrue('"transactionid":' in response, response)

        # in the response we expect a transaction reference (=state)
        # and a reply message
        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', '')
        self.assertTrue(len(state) > 0, body)

        counter2 = counter2 + 1
        otp = get_otp(counter2, otpkey2, None, None, typ)
        # submit a pin only request - to trigger a challenge
        params = {"user": "passthru_user1@myDefRealm",
                                                "pass": otp, "state":state}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": true' in response, response)

        counter2 = self.do_auth("shortpin", counter2 + 1 , otpkey=otpkey2,
                                user="passthru_user1@myDefRealm")

        # with otppin==1 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm', action='otppin=1, ')
        self.assertTrue('"status": true,' in response, response)

        counter2 = self.do_auth("geheim1", counter2 + 1, otpkey=otpkey2,
                                user="passthru_user1@myDefRealm")

        # with otppin==2 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm', action='otppin=2, ')
        self.assertTrue('"status": true,' in response, response)

        counter2 = self.do_auth("", counter2 + 1, otpkey=otpkey2,
                               user="passthru_user1@myDefRealm")

        self.delete_policy('otpPin')

        counter1 = self.do_auth("shortpin", counter1 + 1 , otpkey=otpkey1,
                                user="passthru_user1@myMixRealm")

        # with otppin==1 the pin should be the same as the password
        response = self.setPinPolicy(realm='myMixRealm', action='otppin=1, ')
        self.assertTrue('"status": true,' in response, response)

        counter1 = self.do_auth("geheim1", counter1 + 1, otpkey=otpkey1,
                                user="passthru_user1@myMixRealm")

        # with otppin==2 the pin should be the same as the password
        response = self.setPinPolicy(realm='myMixRealm', action='otppin=2, ')
        self.assertTrue('"status": true,' in response, response)

        counter1 = self.do_auth("", counter1 + 1, otpkey=otpkey1,
                               user="passthru_user1@myMixRealm")

        self.delete_policy('otpPin')

        counter2 = self.do_auth("shortpin", counter2 + 1 , otpkey=otpkey2,
                                user="passthru_user1")

        # with otppin==1 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm', action='otppin=1, ')
        self.assertTrue('"status": true,' in response, response)

        counter2 = self.do_auth("geheim1", counter2 + 1, otpkey=otpkey2,
                                user="passthru_user1")

        # with otppin==2 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm', action='otppin=2, ')
        self.assertTrue('"status": true,' in response, response)

        counter2 = self.do_auth("", counter2 + 1, otpkey=otpkey2,
                               user="passthru_user1")


        return

    def test_61_hmac_active_inactive_tokens(self):
        '''
        Challenge Response Test: two hmac token (active/inactive) for one user

        tests fix for #12413
        '''
        typ = "hmac"
        otpkey1 = "AD8EABE235FC57C815B26CEF3709075580B44738"
        otpkey2 = "38AD8EABE235FC57C815B26CEF3709075580B447"

        # now switch policy on for challenge_response
        response = self.setPinPolicy(name="ch_resp1", realm='myDefRealm',
                                action='challenge_response=hmac,')
        self.assertTrue('"status": true,' in response, response)

        serial1 = self.createToken(serial='one',
                                   pin="shortpin",
                                   typ=typ,
                                   otpkey=otpkey1,
                                   description="one",
                                   user='passthru_user1@myDefRealm')

        serial2 = self.createToken(serial='two',
                                   pin="shortpin2",
                                   typ=typ,
                                   otpkey=otpkey2,
                                   description="two",
                                   user='passthru_user1@myDefRealm')

        # if the pin is a unique identifier a challenge should be triggered
        # though there are two tokens belonging to one user and both are
        # active
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate',
                                    action='check'),
                                params=params)

        self.assertTrue('"value": false' in response, response)
        self.assertTrue('"transactionid":' in response, response)

        serial2 = self.createToken(serial='two',
                                   pin="shortpin",
                                   typ=typ,
                                   otpkey=otpkey2,
                                   description="two",
                                   user='passthru_user1@myDefRealm')

        # now the pin is not a unique identifier anymore and both tokens are
        # active an error will return because multiple challenges could have
        # been triggered
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertIn('Multiple challenges submitted.', response, response)

        params = {
            "serial": serial2,
            }
        response = self.make_admin_request(action='disable', params=params)
        self.assertTrue('"value": 1' in response, response)

        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertTrue('"value": false' in response, response)
        self.assertTrue('"transactionid":' in response, response)

        return

    def test_62_email_active_inactive_tokens(self):
        '''
        Challenge Response Test: two email token (active/inactive) for one user

        tests fix for #12416
        '''
        typ = 'email'

        params = {
            'EmailProvider': 'linotp.lib.emailprovider.SMTPEmailProvider',
            'EmailProviderConfig': '{ "SMTP_SERVER": "mail.example.com",\
                               "SMTP_USER": "secret_user",\
                               "SMTP_PASSWORD": "secret_pasword" }',
            'EmailChallengeValidityTime': 300,
            'EmailBlockingTimeout': 0,
            'session': self.session,
            }
        response = self.make_system_request(action='setConfig', params=params)
        self.assertTrue('"status": true' in response, response)

        # Patch (replace) smtplib.SMTP class to prevent
        # e-mails from being sent out
        self.patch_smtp = patch('smtplib.SMTP', spec=smtplib.SMTP)
        mock_smtp_class = self.patch_smtp.start()
        mock_smtp_instance = mock_smtp_class.return_value
        mock_smtp_instance.sendmail.return_value = []
        mock_obj = mock_smtp_instance.sendmail

        otpkey1 = "AD8EABE235FC57C815B26CEF3709075580B44738"
        otpkey2 = "38AD8EABE235FC57C815B26CEF3709075580B447"

        # create two email tokens
        _serial1 = self.createToken(serial='one',
                                    pin="shortpin",
                                    typ=typ,
                                    email_address='paul@example.com',
                                    otpkey=otpkey1,
                                    description="one",
                                    user='passthru_user1@myDefRealm')

        serial2 = self.createToken(serial='two',
                                   pin="shortpin2",
                                   typ=typ,
                                   email_address='paul@example.com',
                                   otpkey=otpkey2,
                                   description="two",
                                   user='passthru_user1@myDefRealm')

        counter = 0
        # email token should do challenge response even without policy
        counter = self.do_auth("shortpin", counter, typ=typ,
                               mock_obj=mock_obj, otp_func=email_otp_func,
                               user="passthru_user1")

        serial2 = self.createToken(serial='two',
                                   pin="shortpin",
                                   typ=typ,
                                   email_address='paul@example.com',
                                   otpkey=otpkey2,
                                   description="two",
                                   user='passthru_user1@myDefRealm')

        # now the pin is not a unique identifier anymore and both tokens are
        # active an error will return because multiple challenges could have
        # been triggered
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertIn('Multiple challenges submitted.', response, response)

        params = {
            "serial": serial2,
            'session': self.session,
            }
        response = self.make_admin_request(action='disable', params=params)

        self.assertTrue('"value": 1' in response, response)

        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertTrue('"value": false' in response, response)
        self.assertTrue('"transactionid":' in response, response)

        # email token should do challenge response even without policy
        counter = self.do_auth("shortpin", counter, typ=typ,
                               mock_obj=mock_obj, otp_func=email_otp_func,
                               user="passthru_user1")

        # with otppin==1 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm',
                                        action='otppin=1, ')
        self.assertTrue('"status": true,' in response, response)

        # email token should do challenge response even with pin == passw
        counter = self.do_auth("geheim1", counter, typ=typ,
                               mock_obj=mock_obj, otp_func=email_otp_func,
                               user="passthru_user1")

        # with otppin==2 the pin should be the same as the password
        response = self.setPinPolicy(realm='myDefRealm',
                                        action='otppin=2, ')
        self.assertTrue('"status": true,' in response, response)

        # email token should do challenge response even with pin is none
        counter = self.do_auth("", counter, typ=typ,
                               mock_obj=mock_obj, otp_func=email_otp_func,
                               user="passthru_user1")

        return

    def test_63_sms_config_error(self):
        '''
        Challenge Response Test: sms token challenge and error in config
        '''
        typ = 'sms'
        params = {
            'SMSProvider': 'smsprovider.SmtpSMSProvider.SmtpSMSProvider',
            'selftest_admin': 'superadmin',
            'session': self.session,
            }
        _response = self.make_system_request(action='setConfig', params=params)

        sms_conf = {"mailserver": "somemailserverthatdoesntexist.com",
                    "mailsender": "linotp-sms@lsexperts.de",
                    "mailto": "omar.kohl@lsexperts.de",
                    "mailuser": "myuser",
                    "mailpassword": "12345",
                    "subject": "<phone>",
                    "body": "This is your OTP-value: <otp>"}

        params = {
            'SMSProviderConfig': json.dumps(sms_conf),
            'selftest_admin': 'superadmin',
            'session': self.session,
            }

        response = self.make_system_request(action='setConfig', params=params)
        log.error(response)
        self.assertTrue('"status": true' in response, response)

        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"

        serial = self.createToken(pin="shortpin", typ=typ, phone="123456",
                                        otpkey=otpkey, user='passthru_user1')

        # as the config contains an error, the result message should contain
        # a error message and not the otppin

        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)

        self.assertTrue('the SMS could not be sent' in response, response)

        return

    def test_72_exception_in_challenge(self):
        '''
        Challenge Response Test: handle exception during create_challenge

        '''
        typ = 'email'

        params = {
            'EmailProvider': 'linotp.lib.emailprovider.SMTPEmailProvider',
            'EmailProviderConfig': '{ "SMTP_SERVER": "mailss.example.com",\
                               "SMTP_USER": "secret_user",\
                               "SMTP_PASSWORD": "secret_pasword" }',
            'EmailChallengeValidityTime': 300,
            'EmailBlockingTimeout': 0,
            'session': self.session,
            }
        response = self.make_system_request(action='setConfig', params=params)
        self.assertTrue('"status": true' in response, response)

        otpkey1 = "AD8EABE235FC57C815B26CEF3709075580B44738"

        # create email tokens
        serial1 = self.createToken(serial='one',
                                    pin="shortpin",
                                    typ=typ,
                                    email_address='paul@example.com',
                                    otpkey=otpkey1,
                                    description="one",
                                    user='passthru_user1@myDefRealm')

        # does validate/check displays an error and the status false
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        # due to security fix to prevent information leakage the response
        # of validate/check will be only true or false
        # but wont contain the following message anymore
        #    'Failed to send SMS. We received a'
        #                "message": "validate/check failed:'
        self.assertTrue('"value": false' in response, response)

        # check if simplecheck displays as well an error
        params = {"user": "passthru_user1", "pass": "shortpin"}
        response = self.app.get(url(controller='validate',
                                    action='simplecheck'),
                                params=params)

        # due to security fix to prevent information leakage the response
        # of validate/check will be only true or false
        # but wont contain the following message anymore
        #    ':-/'
        self.assertTrue(':-(' in response, response)

        # finally check, if there is no open challenge left
        params = {
            "serial": serial1,
            'session': self.session,
            }

        response = self.make_admin_request(action='checkstatus', params=params)

        self.assertTrue('"values": {}' in response, response)

        return

    def test_13_multiple_challenges(self):
        """
        Challenge Response Test: multiple challenges

        Remark:
            if a user owns multiple challenge tokens with same pin
            multiple challenges are triggerd under a virtual transactionid
            The reply to the challenge must work for either token and remove
            all challenges of this top transaction on success.
        """

        counter = 0
        otpkey = "AD8EABE235FC57C815B26CEF3709075580B44738"
        otpkey2 = "AD8EABE235FC57C815B26CEF3709075580B44739"

        self.setPinPolicy(name="ch_resp", realm='myDefRealm',
                                       action='challenge_response=hmac topt,')

        serial = self.createToken(serial="H1", pin="pin", otpkey=otpkey,
                                  user='passthru_user1', typ='hmac')

        serial = self.createToken(serial="H2", pin="pin", otpkey=otpkey2,
                                  user='passthru_user1', typ='hmac')

        # submit a pin only request - to trigger a challenge
        transactions = []

        for _i in range(1, 5):

            # submit a pin only request - to trigger a challenge
            params = {"user": "passthru_user1", "pass": "pin"}
            response = self.app.get(url(controller='validate',
                                        action='check'), params=params)

            self.assertTrue('"value": false' in response, response)
            self.assertTrue('"transactionid":' in response, response)

            # in the response we expect an transaction reference (=state)
            body = json.loads(response.body)
            challenges = body.get('detail').get('challenges', {})
            state1 = challenges.get('H1', {}).get('transactionid')
            state2 = challenges.get('H2', {}).get('transactionid')
            transactionid = body.get('detail').get('transactionid')

            otp1 = self.calcOTP(otpkey, counter=counter)
            otp2 = self.calcOTP(otpkey, counter=counter)
            # create a tupple of the finished transactios
            transactions.append((transactionid, state1, state2, otp1, otp2))
            counter = counter + 1

        # check if the admin checkstatus api supports finding of challenges
        # by top transactionid
        for (t, s1, s2, o1, o2) in transactions:

            params = {"transactionid": t, 'session': self.session}
            response = self.make_admin_request(action='checkstatus',
                                               params=params)
            self.assertIn(s1, response, response)
            self.assertIn(s2, response, response)
            self.assertIn(t, response, response)

        # check if the challenge could be identified by the top transactionid
        # in the validate/check
        (transactionid, state1, state2, otp1, otp2) = transactions[1]
        params = {'user': 'passthru_user1',
                  'pass': otp1,
                  'transactionid': transactionid}
        response = self.app.get(url(controller='validate', action='check'),
                                params=params)
        self.assertTrue('"value": true' in response, response)

        # check if the second token could be identified as well by the
        # top transactionid but with the negative case as the challenge
        # is aready removed
        params['pass'] = otp2
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)
        self.assertTrue('"value": false' in response, response)

        # check if all sub transactions are removed as well
        params = {
            "user": "passthru_user1",
            }
        response = self.make_admin_request(action='checkstatus', params=params)
        self.assertTrue(transactionid not in response, response)

        (transactionid, state1, state2, otp1, otp2) = transactions[3]

        # check if the authentication works as well if the subtransaction
        # is provided
        params = {"user": "passthru_user1", "pass": otp2, 'state': state2}
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": true' in response, response)

        # the challenge for the other token should become invalid after the
        # successfull authentication
        params = {"user": "passthru_user1", "pass": otp1}
        params['transactionid'] = state1
        response = self.app.get(url(controller='validate', action='check'),
                                                            params=params)

        self.assertTrue('"value": false' in response, response)

        # have a look, if all challenges are removed
        params = {
            "user": "passthru_user1",
            'session': self.session,
            }
        response = self.make_admin_request(action='checkstatus', params=params)

        # assure that all challenges are removed
        self.assertTrue(transactionid not in response, response)

        # final cleanup
        self.delete_token("H1")
        self.delete_token("H2")

        self.delete_policy(name="ch_resp")
        return


##eof##########################################################################

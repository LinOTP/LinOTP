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
Test challenge response functionality for the radius token
"""

import binascii
import smtplib
import httplib2
import re
import time
import json
import logging
import urlparse

# we need this for the radius token
import pyrad
import pyrad.packet as packet
from pyrad.packet import AccessAccept, AccessReject, AccessChallenge

from mock import patch
from linotp.lib.HMAC import HmacOtp

from . import TestChallengeResponseController


log = logging.getLogger(__name__)


RADIUS_RESPONSE_FUNC = None

class RadiusResponse(object):

    def __init__(self, auth, reply=None):
        if auth is True:
            self.code = pyrad.packet.AccessAccept
        elif auth is False:
            self.code = pyrad.packet.AccessReject
        else:
            self.code = pyrad.packet.AccessChallenge

        if not reply:
            self.reply = {}
        else:
            self.reply = reply

    # response[attr]
    def __getitem__(self, key):
        return self.reply.get(key)

    def keys(self):
        return self.reply.keys()


def mocked_radius_SendPacket(Client, *argparams, **kwparams):

    auth = True
    reply = None

    global RADIUS_RESPONSE_FUNC
    if RADIUS_RESPONSE_FUNC:
        test_func = RADIUS_RESPONSE_FUNC
        pkt = argparams[0]

        params = {}
        # contents of User-Name
        params['username'] = pkt[1][0]
        # encrypted User-Password
        params['password'] = pkt.PwDecrypt(pkt[2][0])

        try:
            params['state'] = pkt["State"][0]
        except Exception as exx:
            pass

        if test_func:
            auth, reply = test_func(params)

    response = RadiusResponse(auth, reply)

    return response


class TestRadiusTokenChallengeController(TestChallengeResponseController):

    def setUp(self):
        '''
        This sets up all the resolvers and realms
        '''
        TestChallengeResponseController.setUp(self)
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

        self.radius_url = 'localhost:%s' % self.radius_authport,
        return

    def tearDown(self):

        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        TestChallengeResponseController.tearDown(self)

    def setPinPolicy(self, name='otpPin', realm='ldap_realm',
                     action='otppin=1, ', scope='authentication',
                     active=True):
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
        cookies = {"admin_session": self.session}

        response = self.make_system_request("setPolicy", params=params)
        self.assertTrue('"status": true' in response, response)

        response = self.make_system_request("getPolicy", params=params)
        self.assertTrue('"status": true' in response, response)

        self.policies.append(name)
        return response

    def setup_radius_token(self):

        serials = []

        # The token with the remote PIN
        params_list = [{
                      "serial": "radius1",
                      "type": "radius",
                      "otpkey": "1234567890123456",
                      "otppin": "",
                      "user": "remoteuser",
                      "pin": "",
                      "description": "RadiusToken1",
                      'radius.server': self.radius_url,
                      'radius.local_checkpin': 0,
                      'radius.user': 'challenge',
                      'radius.secret': 'testing123',
                      'session': self.session,
                      },

                    # the token with the local PIN
                    {
                      "serial": "radius2",
                      "type": "radius",
                      "otpkey": "1234567890123456",
                      "otppin": "local",
                      "user": "localuser",
                      "pin": "local",
                      "description": "RadiusToken2",
                      'radius.server': self.radius_url,
                      'radius.local_checkpin': 1,
                      'radius.user': 'user_no_pin',
                      'radius.secret': 'testing123',
                      'session': self.session,
                      },
                     ]
        for params in params_list:
            response = self.make_admin_request(action='init', params=params)
            self.assertTrue('"value": true' in response, response)
            serials.append(params.get("serial"))

        return serials

    @patch.object(pyrad.client.Client, 'SendPacket', mocked_radius_SendPacket)
    def test_radiustoken_remote_pin(self):
        """
        Challenge Response Test: radius token with remote PIN
        """
        global RADIUS_RESPONSE_FUNC
        serials = self.setup_radius_token()
        user = "remoteuser"
        otp = "test123456"

        # now switch policy on for challenge_response for hmac token
        response = self.setPinPolicy(name="ch_resp", realm='*',
                                action='challenge_response=radius')
        self.assertTrue('"status": true,' in response, response)

        # define validation function
        def check_func1(params):
            resp = False
            opt = None

            # check if we are in a chellenge request
            if params.get('password') == 'test':
                opt = {}
                opt["State"] = ['012345678901']
                opt["Reply-Message"] = ["text"]
                resp = opt

            return resp, opt

        # establish this in the global context as validation hook
        RADIUS_RESPONSE_FUNC = check_func1

        # 1.1 now trigger a challenge
        params = {"user": user, "pass": "test"}
        response = self.make_validate_request('check', params=params)
        self.assertTrue('"value": false' in response, response)

        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', '')
        self.assertTrue(state != '', response)

        # 1.2 check the challenge

        # define validation function
        def check_func2(params):
            resp = False
            opt = None

            # check if we are in a chellenge request
            if (params.get('password') == 'test123456' and
                params.get('state') == '012345678901'):
                resp = True

            return resp, opt

        # establish this in the global context as validation hook
        RADIUS_RESPONSE_FUNC = check_func2

        params = {"user": user, "pass": otp, "state": state}
        response = self.make_validate_request('check', params=params)

        # hey, if this ok, we are done for the remote pin check
        self.assertTrue('"value": true' in response, response)

        for serial in serials:
            self.delete_token(serial)

        return

    @patch.object(pyrad.client.Client, 'SendPacket', mocked_radius_SendPacket)
    def test_radiustoken_local_pin(self):
        """
        Challenge Response Test: radius token with local PIN
        """
        global RADIUS_RESPONSE_FUNC

        serials = self.setup_radius_token()

        user = "localuser"
        otp = "654321"

        # now switch policy on for challenge_response for hmac token
        response = self.setPinPolicy(name="ch_resp", realm='*',
                                action='challenge_response=radius')
        self.assertTrue('"status": true,' in response, response)

        # 1.1 now trigger a challenge
        # define validation function
        def check_func1(params):
            resp = False
            opt = None

            # check if we are in a chellenge request
            if params.get('password') == 'test':
                opt = {}
                opt["State"] = ['012345678901']
                opt["Reply-Message"] = ["text"]
                resp = opt

            return resp, opt

        # establish this in the global context as validation hook
        RADIUS_RESPONSE_FUNC = check_func1

        params = {"user": user, "pass": "local"}
        response = self.make_validate_request('check', params=params)
        self.assertTrue('"value": false' in response, response)

        body = json.loads(response.body)
        state = body.get('detail', {}).get('transactionid', '')
        self.assertTrue(state != '', response)

        # 1.2 check the challenge
        def check_func2(params):
            resp = False
            opt = None

            # check if we got the correct otp
            if params.get('password') == otp:
                resp = True

            return resp, opt

        # establish this in the global context as validation hook
        RADIUS_RESPONSE_FUNC = check_func2

        params = {"user": user, "pass": otp, "state": state}
        response = self.make_validate_request('check', params=params)
        # hey, if this ok, we are done for the remote pin check
        self.assertTrue('"value": true' in response, response)

        for serial in serials:
            self.delete_token(serial)

        return


##eof##########################################################################

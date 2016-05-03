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
  Test linotp.lib.tokens.yk_challenge_response token
"""

import json
import hmac
import binascii
from hashlib import sha1, sha512


from linotp.tests import TestController


def get_response_for_challenge(seed, challenge, pairing_id=None):
    """
    helper - same algo as on the server side
    """

    if not pairing_id:
        return hmac.new(seed, challenge, sha1).digest()

    p_id = pairing_id.encode('utf-8')

    h1 = hmac.new(challenge, p_id, sha512).digest()
    h2 = hmac.new(seed, h1, sha1).digest()
    h3 = hmac.new(h2, p_id, sha512).digest()

    return h3


class TestYKChallengeResponsetokenController(TestController):

    def setUp(self):
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        TestController.setUp(self)
        self.create_common_resolvers()
        self.create_common_realms()

    def tearDown(self):
        TestController.tearDown(self)

    def setPolicy(self, param):
        params = {'name': 'losttoken_user_1',
                  'scope': 'enrollment',
                  'realm': 'myOtherRealm',
                  'user': 'max1',
                  'action': 'lostTokenPWLen=8',
                  'client': '',
                  'selftest_admin': 'superadmin'
                  }
        if not param:
            param = {}

        params.update(param)
        response = self.make_system_request('setPolicy', params=params)
        self.assertTrue('"status": true' in response, response)
        return params['name']

    def createYKToken(self, params=None):

        parameters = {
              "otpkey": "AD8EABE235FC57C815B26CEF3709075580B44738",
              "description": "yk challenge reponse",
              'type': 'yk_challenge_response'
              }

        if not params:
            params = {}

        if params:
            parameters.update(params)

        seed = parameters.get('otpkey')
        response = self.make_admin_request('init', params=parameters)
        self.assertTrue('"value": true' in response, response)

        jresp = json.loads(response.body)
        serial = jresp.get('detail', {}).get('serial')

        return serial, seed

    def test_default_challenge_response(self):
        """
        Test the default challenge response
        """
        serial, seed = self.createYKToken()

        params = {'serial': serial,
                  'pass': ''}
        response = self.make_validate_request('check_s', params)

        self.assertTrue('"value": false' in response, response)

        jresp = json.loads(response.body)
        transid = jresp.get("detail", {}).get('transactionid')
        challenge = jresp.get("detail", {}).get('message')

        ch_resp = get_response_for_challenge(binascii.unhexlify(seed),
                                             binascii.unhexlify(challenge))

        params = {'serial': serial,
                  'pass': binascii.hexlify(ch_resp),
                  'transactionid': transid}
        response = self.make_validate_request('check_s', params)

        self.assertTrue('"value": true' in response, response)

        return

    def test_0000000_pairing_challenge_response(self):

        pairing_id = 'Test123!'

        # enable the autobinding
        params = {'scope': 'authentication',
                  'realm': '*',
                  'user': '*',
                  'action': 'yk_challenge_response::autobinding, '}

        self.setPolicy(params)

        serial, seed = self.createYKToken()

        params = {'serial': serial,
                  'pass': ''}
        response = self.make_validate_request('check_s', params)
        self.assertTrue('"value": false' in response, response)

        jresp = json.loads(response.body)
        challenge = jresp.get("detail", {}).get('message')
        self.assertTrue(challenge is None)

        params = {'serial': serial,
                  'pass': '',
                  'id': pairing_id}
        response = self.make_validate_request('check_s', params)

        self.assertTrue('"value": false' in response, response)

        jresp = json.loads(response.body)
        transid = jresp.get("detail", {}).get('transactionid')
        challenge = jresp.get("detail", {}).get('message')

        ch_resp = get_response_for_challenge(binascii.unhexlify(seed),
                                             binascii.unhexlify(challenge),
                                             pairing_id=pairing_id)

        params = {'serial': serial,
                  'pass': binascii.hexlify(ch_resp),
                  'transactionid': transid}
        response = self.make_validate_request('check_s', params)

        self.assertTrue('"value": true' in response, response)

        # auto pairing works only for the first time
        params = {'serial': serial,
                  'pass': '',
                  'id': pairing_id}
        response = self.make_validate_request('check_s', params)

        self.assertTrue('"value": false' in response, response)

        jresp = json.loads(response.body)
        challenge = jresp.get("detail", {}).get('message')
        self.assertTrue(challenge is None)

        for _i in range(1, 10):
            params = {'serial': serial,
                      'pass': ''}
            response = self.make_validate_request('check_s', params)
            self.assertTrue('"value": false' in response, response)

            jresp = json.loads(response.body)
            transid = jresp.get("detail", {}).get('transactionid')
            challenge = jresp.get("detail", {}).get('message')

            ch_resp = get_response_for_challenge(binascii.unhexlify(seed),
                                                 binascii.unhexlify(challenge),
                                                 pairing_id=pairing_id)

            params = {'serial': serial,
                    'pass': binascii.hexlify(ch_resp),
                    'transactionid': transid
                    }
            response = self.make_validate_request('check_s', params)
            self.assertTrue('"value": true' in response, response)


        return


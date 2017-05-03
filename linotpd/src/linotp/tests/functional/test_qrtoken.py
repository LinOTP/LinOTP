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


import struct
import json
import logging
import os
from collections import defaultdict
from linotp.tests import TestController
from linotp.lib.crypto import encode_base64_urlsafe
from linotp.lib.crypto import decode_base64_urlsafe
from linotp.lib.crypto import extract_tan
from linotp.lib.crypto import dsa_to_dh_public
from pysodium import crypto_scalarmult_curve25519 as calc_dh
from pysodium import crypto_scalarmult_curve25519_base as calc_dh_base
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import HMAC
from Cryptodome.Cipher import AES
from base64 import b64encode

log = logging.getLogger(__name__)

FLAG_PAIR_PK = 1 << 0
FLAG_PAIR_SERIAL = 1 << 1
FLAG_PAIR_CBURL = 1 << 2
FLAG_PAIR_CBSMS = 1 << 3
FLAG_PAIR_DIGITS = 1 << 4
FLAG_PAIR_HMAC = 1 << 5

TYPE_QRTOKEN = 2
QRTOKEN_VERSION = 1
PAIR_RESPONSE_VERSION = 1
PAIRING_URL_VERSION = 2

QRTOKEN_CT_FREE = 0
QRTOKEN_CT_PAIR = 1
QRTOKEN_CT_AUTH = 2

FLAG_QR_COMP = 1
FLAG_QR_HAVE_URL = 2
FLAG_QR_HAVE_SMS = 4
FLAG_QR_SRVSIG = 8


def u64_to_transaction_id(u64_int):
    # HACK! counterpart to transaction_id_to_u64 in
    # lib.tokens.qrtokenclass
    rest = u64_int % 100
    if rest == 0:
        return str(u64_int / 100)
    else:
        before = u64_int // 100
        return '%s.%s' % (str(before), str(rest))


class TestQRToken(TestController):

    def setPinPolicy(self, name='otpPin', realm='myDefRealm',
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

        response = self.make_system_request("setPolicy", params=params)
        self.assertTrue('"status": true' in response, response)

        response = self.make_system_request("getPolicy", params=params)
        self.assertTrue('"status": true' in response, response)

        return response

# --------------------------------------------------------------------------- --

    def setOfflinePolicy(self, realm='*', name='qr_offline',
                         action='support_offline=qr', active=True):

        params = {
            'name': name,
            'user': '*',
            'action': action,
            'scope': 'authentication',
            'realm': realm,
            'time': '',
            'client': '',
            'active': active,
            'session': self.session,
        }

        response = self.make_system_request("setPolicy", params=params)
        self.assertTrue('"status": true' in response, response)

# --------------------------------------------------------------------------- --

    def setUnassignPolicy(self):

        # just a dummy policy that is set to active, because if
        # no active policy is present in admin scope, everything
        # is possible. used in unpairing tests

        params = {
            'name': 'dummy_unassign',
            'user': '*',
            'action': 'unassign',
            'scope': 'admin',
            'realm': '*',
            'time': '',
            'client': '',
            'active': True,
            'session': self.session,
        }

        response = self.make_system_request("setPolicy", params=params)
        self.assertTrue('"status": true' in response, response)

# --------------------------------------------------------------------------- --

    def setUnpairPolicy(self, active=True):

        params = {
            'name': 'dummy_unpairing',
            'user': '*',
            'action': 'unpair',
            'scope': 'admin',
            'realm': '*',
            'time': '',
            'client': '',
            'active': active,
            'session': self.session,
        }

        response = self.make_system_request("setPolicy", params=params)
        self.assertTrue('"status": true' in response, response)

# --------------------------------------------------------------------------- --

    def create_dummy_cb_policies(self):
        """ sets some dummy callback policies. callback policies get ignored
        by the tests, but are nonetheless necessary for the backend """

        # ------------------------------------------------------------------- --

        # set pairing callback policies

        params = {'name': 'dummy1',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'qrtoken_pairing_callback_url=foo',
                  'user': '*'}

        self.setPolicy(params)

        params = {'name': 'dummy2',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'qrtoken_pairing_callback_sms=foo',
                  'user': '*'}

        self.setPolicy(params)

        # ------------------------------------------------------------------- --

        # set challenge callback policies

        params = {'name': 'dummy3',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'qrtoken_challenge_callback_url=foo',
                  'user': '*'}

        self.setPolicy(params)

        params = {'name': 'dummy4',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'qrtoken_challenge_callback_sms=foo',
                  'user': '*'}

        self.setPolicy(params)

# --------------------------------------------------------------------------- --

    def setUp(self):
        # do the cleanup upfront for better post mortem debuggability
        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()

        super(TestQRToken, self).setUp()
        self.create_common_resolvers()
        self.create_common_realms()
        self.create_dummy_cb_policies()
        self.secret_key = os.urandom(32)
        self.public_key = calc_dh_base(self.secret_key)
        self.tokens = defaultdict(dict)
        self.tan_length = 8

    def tearDown(self):
        self.delete_all_policies()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_token()
        super(TestQRToken, self).tearDown()

# --------------------------------------------------------------------------- --

    def enroll_qrtoken(self, hashlib=None, user=None, pin='1234'):
        """
        enrolls a qrtoken

        :param hashlib: the identifier for the hash algorithm that
            is used during tan generation ('sha1', 'sha256', 'sha512')
            default is sha256

        :returns pairing url
        """

        self.hashlib = hashlib

        # initialize an unfinished token on the server

        params = {'type': 'qr', 'pin': pin}

        if hashlib is not None:
            params['hashlib'] = hashlib

        if user:
            params['user'] = user

        response = self.make_admin_request('init', params)

        # ------------------------------------------------------------------- --

        # response should contain pairing url, check if it was
        # sent and validate

        response_dict = json.loads(response.body)
        self.assertIn('pairing_url', response_dict.get('detail', {}))

        pairing_url = response_dict.get('detail', {}).get('pairing_url')
        self.assertIsNotNone(pairing_url)
        self.assertTrue(pairing_url.startswith('lseqr://pair/'))

        return pairing_url, pin

    def get_challenge(self, params=None):

        if not params:
            params = {}

        response = self.make_validate_request('check_s', params)
        response_dict = json.loads(response.body)

        # ------------------------------------------------------------------- --

        # check if challenge was triggered

        self.assertIn('detail', response_dict)
        detail = response_dict.get('detail')

        self.assertIn('transactionid', detail)
        self.assertIn('message', detail)

        challenge_url = detail.get('message')

        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        return challenge_url, detail.get('transactionid')
# --------------------------------------------------------------------------- --

    def setPolicy(self, params):
        """ sets a system policy defined by param """

        response = self.make_system_request('setPolicy', params)
        response_dict = json.loads(response.body)

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        self.assertIn('status', result)
        status = result.get('status')

        self.assertTrue(status)

        response = self.make_system_request('getPolicy', params)

# --------------------------------------------------------------------------- --

    def test_callback_policies(self):
        """QRTOKEN: check if callback policies returned callbacks are correct"""
        # ------------------------------------------------------------------- --

        # set pairing callback policies

        params = {'name': 'dummy1',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'qrtoken_pairing_callback_url=/foo/bar/url',
                  'user': '*'}

        self.setPolicy(params)

        params = {'name': 'dummy2',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'qrtoken_pairing_callback_sms=1234',
                  'user': '*'}

        self.setPolicy(params)

        # ------------------------------------------------------------------- --

        # set challenge callback policies

        params = {'name': 'dummy3',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'qrtoken_challenge_callback_url=/bar/baz/url',
                  'user': '*'}

        self.setPolicy(params)

        params = {'name': 'dummy4',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'qrtoken_challenge_callback_sms=5678',
                  'user': '*'}

        self.setPolicy(params)

        # ------------------------------------------------------------------- --

        # check callback definitions in pairing url

        pairing_url, pin = self.enroll_qrtoken()
        user_token_id = self.create_user_token_by_pairing_url(pairing_url, pin)

        token = self.tokens[user_token_id]
        callback_url = token['callback_url']
        callback_sms = token['callback_sms']

        self.assertEqual(callback_url, '/foo/bar/url')
        self.assertEqual(callback_sms, '1234')

        # ------------------------------------------------------------------- --

        # create the pairing response

        pairing_response = self.create_pairing_response_by_serial(
            user_token_id)

        # ------------------------------------------------------------------- --

        # send pairing response

        response_dict = self.send_pairing_response(pairing_response)

        # ------------------------------------------------------------------- --

        # check if returned json is correct

        self.assertFalse(response_dict.get('result', {}).get('value', True))
        self.assertTrue(response_dict.get('result', {}).get('status', False))

        # ------------------------------------------------------------------- --

        # get challenge

        params = {'serial': token['serial'],
                  'pass': token['pin'],
                  'data': token['serial']}

        challenge_url, transid = self.get_challenge(params=params)
        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        # ------------------------------------------------------------------- --

        # check if returned callbacks are correct

        callback_url = challenge['callback_url']
        self.assertEqual(callback_url, '/bar/baz/url')

        callback_sms = challenge['callback_sms']
        self.assertEqual(callback_sms, '5678')

# --------------------------------------------------------------------------- --

    def assign_token_to_user(self, serial, user_login, pin=None):
        """
        assign a token to a user

        :serial the serial number of the pin
        :user_login the login name of the user
        :pin (optional) a pin that will be set. if parameter is left
            out our is set to None, no pin will be set

        """

        params = {'serial': serial, 'user': user_login}

        if pin is not None:
            params['pin'] = pin

        response = self.make_admin_request('assign', params)
        response_dict = json.loads(response.body)

        # ------------------------------------------------------------------- --

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        self.assertIn('value', result)
        value = result.get('value')

        self.assertTrue(value)

# --------------------------------------------------------------------------- --

    def send_pairing_response(self, pairing_response):

        params = {'pairing_response': pairing_response}

        # we use the standard calback url in here
        # in a real client we would use the callback
        # defined in the pairing url (and saved in
        # the 'token database' of the user)

        response = self.make_validate_request('pair', params)
        response_dict = json.loads(response.body)

        return response_dict

# --------------------------------------------------------------------------- --

    def pair_until_challenge(self, pairing_url, pin='1234'):
        """
        Executes a pairing for an existing token until the last
        step in which the challenge response is sent.

        :param pairing_url: the pairing url provided by the token

        :returns the response dictionary received by the server. if all goes
            right it will include the challenge url
        """

        # save data extracted from pairing url to the 'user database'

        user_token_id = self.create_user_token_by_pairing_url(pairing_url, pin)

        # ------------------------------------------------------------------- --

        # create the pairing response

        pairing_response = self.create_pairing_response_by_serial(
            user_token_id)

        # ------------------------------------------------------------------- --

        # send pairing response

        response_dict = self.send_pairing_response(pairing_response)

        # ------------------------------------------------------------------- --

        # check if returned json is correct

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        self.assertIn('value', result)
        value = result.get('value')
        self.assertFalse(value)

        self.assertIn('status', result)
        status = result.get('status')
        self.assertTrue(status)

        # ------------------------------------------------------------------- --

        # trigger challenge

        serial = self.tokens[user_token_id]['serial']
        pin = self.tokens[user_token_id]['pin']

        params = {'serial': serial,
                  'pass': pin,
                  'data': serial}

        response = self.make_validate_request('check_s', params)
        response_dict = json.loads(response.body)

        # ------------------------------------------------------------------- --

        # check if challenge was triggered
        challenge_url = None
        try:
            self.assertIn('detail', response_dict)
            detail = response_dict.get('detail')

            self.assertIn('transactionid', detail)
            self.assertIn('message', detail)

            challenge_url = detail.get('message')
        except:
            pass

        return challenge_url

# --------------------------------------------------------------------------- --

    def execute_correct_pairing(self, hashlib=None, user=None,
                                use_tan=False, tan_length=8, pin='1234'):
        """
        do the pairing for given parameters

        :param pub_client:
        :param id:
        :return:
        """

        self.tan_length = tan_length

        # ------------------------------------------------------------------- --

        # enroll token

        pairing_url, pin = self.enroll_qrtoken(hashlib, user=user, pin=pin)

        # ------------------------------------------------------------------- --

        # execute the first step of the pairing

        challenge_url = self.pair_until_challenge(pairing_url, pin)

        # ------------------------------------------------------------------- --

        # check request response

        # ------------------------------------------------------------------- --

        return self.verify_pairing(challenge_url, use_tan=use_tan)

    # ----------------------------------------------------------------------- --

    def verify_pairing(self, challenge_url, use_tan=False):

        # parse, descrypt and verify the challenge url

        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        # ------------------------------------------------------------------- --

        # check if the content type is right (we are doing pairing
        # right now, so type must be QRTOKEN_CT_PAIR)

        content_type = challenge['content_type']
        self.assertEqual(content_type, QRTOKEN_CT_PAIR)

        # challenge message in content type QRTOKEN_CT_PAIR is defined
        # as the token serial - check, if this is the case

        user_token_id = challenge['user_token_id']
        serial = self.tokens[user_token_id]['serial']
        self.assertEqual(challenge['message'], serial)

        # ------------------------------------------------------------------- --

        # prepare params for validate

        pass_ = tan if use_tan else sig

        params = {'transactionid': challenge['transaction_id'],
                  'pass': pass_}

        # again, we ignore the callback definitions

        response = self.make_validate_request('check_t', params)
        response_dict = json.loads(response.body)

        self.assertIn('status', response_dict.get('result', {}))

        status = response_dict.get('result', {}).get('status')
        self.assertEqual(status, True)

        # ------------------------------------------------------------------- --

        value = response_dict.get('result', {}).get('value')

        self.assertIn('value', value)
        self.assertIn('failcount', value)

        value_value = value.get('value')

        self.assertTrue(value_value)

        return user_token_id

# --------------------------------------------------------------------------- --

    def create_user_token_by_pairing_url(self, pairing_url, pin='1234'):
        """
        parses the pairing url and saves the extracted data in
        the fake token database of this test class.

        :param pairing_url: the pairing url received from the server
        :returns: user_token_id of newly created token
        """

        # extract metadata and the public key

        data_encoded = pairing_url[len('lseqr://pair/'):]
        data = decode_base64_urlsafe(data_encoded)
        version, token_type, flags = struct.unpack('<bbI', data[0:6])
        partition = struct.unpack('<I', data[6:10])[0]

        server_public_key_dsa = data[10:10 + 32]
        server_public_key = dsa_to_dh_public(server_public_key_dsa)

        # validate protocol versions and type id

        self.assertEqual(token_type, TYPE_QRTOKEN)
        self.assertEqual(version, PAIRING_URL_VERSION)

        # ------------------------------------------------------------------- --

        # extract custom data that may or may not be present
        # (depending on flags)

        custom_data = data[10 + 32:]

        token_serial = None
        if flags & FLAG_PAIR_SERIAL:
            token_serial, __, custom_data = custom_data.partition(b'\x00')

        callback_url = None
        if flags & FLAG_PAIR_CBURL:
            callback_url, __, custom_data = custom_data.partition(b'\x00')
        else:
            raise NotImplementedError('SMS is not implemented. Callback URL'
                                      'is mandatory.')

        callback_sms = None
        if flags & FLAG_PAIR_CBSMS:
            callback_sms, __, custom_data = custom_data.partition(b'\x00')

        # ------------------------------------------------------------------- --

        # save token data for later use

        user_token_id = len(self.tokens)
        self.tokens[user_token_id] = {'serial': token_serial,
                                      'server_public_key': server_public_key,
                                      'partition': partition,
                                      'callback_url': callback_url,
                                      'callback_sms': callback_sms,
                                      'pin': pin}

        # ------------------------------------------------------------------- --

        return user_token_id


# --------------------------------------------------------------------------- --

    def decrypt_and_verify_challenge(self, challenge_url):
        """
        Decrypts the data packed in the challenge url, verifies
        its content, returns the parsed data as a dictionary,
        calculates and returns the signature and TAN.

        The calling method must then send the signature/TAN
        back to the server. (The reason for this control flow
        is that the challenge data must be checked in different
        scenarios, e.g. when we have a pairing the data must be
        checked by the method that simulates the pairing)

        :param challenge_url: the challenge url as sent by the server

        :returns: (challenge, signature, tan)

            challenge has the keys

                * message - the signed message sent from the server
                * content_type - one of the three values QRTOKEN_CT_PAIR,
                    QRTOKEN_CT_FREE or QRTOKEN_CT_AUTH
                    (all defined in this module
                * callback_url (optional) - the url to which the challenge
                    response should be set
                * callback_sms (optional) - the sms number the challenge
                    can be sent to (typicall used as a fallback)
                * transaction_id - used to identify the challenge
                    on the server
                * user_token_id - used to identify the token in the
                    user database for which this challenge was created

            signature is the generated user signature used to
            respond to the challenge

            tan is the TAN-Number used as a substitute if the signature
            cant' be sent be the server (is generated from signature)
        """

        challenge_data_encoded = challenge_url[len('lseqr://chal/'):]
        challenge_data = decode_base64_urlsafe(challenge_data_encoded)

        # ------------------------------------------------------------------- --

        # parse and verify header information in the
        # encrypted challenge data

        header = challenge_data[0:5]
        version, user_token_id = struct.unpack('<bI', header)
        self.assertEqual(version, QRTOKEN_VERSION)

        # ------------------------------------------------------------------- --

        # get token from client token database

        token = self.tokens[user_token_id]

        # ------------------------------------------------------------------- --

        # prepare decryption by seperating R from
        # ciphertext and tag

        R = challenge_data[5:5 + 32]
        ciphertext = challenge_data[5 + 32:-16]
        tag = challenge_data[-16:]

        # ------------------------------------------------------------------- --

        # key derivation

        ss = calc_dh(self.secret_key, R)
        U1 = SHA256.new(ss).digest()
        U2 = SHA256.new(U1).digest()

        skA = U1[0:16]
        skB = U2[0:16]
        nonce = U2[16:32]

        # ------------------------------------------------------------------- --

        # decrypt and verify challenge

        cipher = AES.new(skA, AES.MODE_EAX, nonce)
        cipher.update(header)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # ------------------------------------------------------------------- --

        # parse/check plaintext header

        pt_header = plaintext[0:10]
        content_type, flags, transaction_id = struct.unpack('<bbQ', pt_header)
        transaction_id = u64_to_transaction_id(transaction_id)

        # make sure a flag for the server signature is
        # present, if the content type is 'pairing'

        if content_type == QRTOKEN_CT_PAIR:
            self.assertTrue(flags & FLAG_QR_SRVSIG)

        # ------------------------------------------------------------------- --

        # retrieve plaintext data depending on flags

        if flags & FLAG_QR_SRVSIG:

            # plaintext has a server signature as a header
            # extract it and check if it is correct

            server_signature = plaintext[10:10 + 32]
            data = plaintext[10 + 32:]

            # calculate secret

            server_public_key = token['server_public_key']
            secret = calc_dh(self.secret_key, server_public_key)

            # check hmac

            message = nonce + pt_header + data
            signed = HMAC.new(secret, msg=message, digestmod=SHA256).digest()
            self.assertEqual(server_signature, signed)

        else:

            # no server signature found - just remove
            # the plaintext header

            data = plaintext[10:]

            # we have to define an empty server signature in
            # here because we need it later to create the
            # client signature

            server_signature = b''

        # ------------------------------------------------------------------- --

        # extract message and (optional) callback
        # parameters from data

        message, _, suffix = data.partition(b'\x00')

        callback_url = token['callback_url']
        if flags & FLAG_QR_HAVE_URL:
            callback_url, _, suffix = suffix.partition(b'\x00')

        callback_sms = token['callback_sms']
        if flags & FLAG_QR_HAVE_SMS:
            callback_sms, _, suffix = suffix.partition(b'\x00')

        # ------------------------------------------------------------------- --

        # prepare the parsed challenge data

        challenge = {}
        challenge['message'] = message
        challenge['content_type'] = content_type
        challenge['callback_url'] = callback_url
        challenge['callback_sms'] = callback_sms
        challenge['transaction_id'] = transaction_id
        challenge['user_token_id'] = user_token_id

        # calculate signature and tan

        message = nonce + pt_header + server_signature + data
        sig_hmac = HMAC.new(skB, message, digestmod=SHA256)
        sig = sig_hmac.digest()

        tan = extract_tan(sig, self.tan_length)
        encoded_sig = encode_base64_urlsafe(sig)

        return challenge, encoded_sig, tan


# --------------------------------------------------------------------------- --

    def create_pairing_response_by_serial(self, user_token_id):
        """
        Creates a base64-encoded pairing response that identifies
        the token by its serial

        :param user_token_id: the token id (primary key for the user token db)
        :returns base64 encoded pairing response
        """

        token_serial = self.tokens[user_token_id]['serial']
        server_public_key = self.tokens[user_token_id]['server_public_key']
        partition = self.tokens[user_token_id]['partition']

        header = struct.pack('<bI', PAIR_RESPONSE_VERSION, partition)

        pairing_response = b''
        pairing_response += struct.pack('<bI', TYPE_QRTOKEN, user_token_id)

        pairing_response += self.public_key

        pairing_response += token_serial.encode('utf8') + b'\x00\x00'

        # ------------------------------------------------------------------- --

        # create public diffie hellman component
        # (used to decrypt and verify the reponse)

        r = os.urandom(32)
        R = calc_dh_base(r)

        # ------------------------------------------------------------------- --

        # derive encryption key and nonce

        ss = calc_dh(r, server_public_key)
        U = SHA256.new(ss).digest()
        encryption_key = U[0:16]
        nonce = U[16:32]

        # ------------------------------------------------------------------- --

        # encrypt in EAX mode

        cipher = AES.new(encryption_key, AES.MODE_EAX, nonce)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(pairing_response)

        return encode_base64_urlsafe(header + R + ciphertext + tag)

# --------------------------------------------------------------------------- --

    def test_pairing_sig(self):
        """QRTOKEN: check if pairing mechanism works correctly (sig based)"""

        self.execute_correct_pairing()

        return

# --------------------------------------------------------------------------- --

    def test_pairing_sig_with_user(self):
        """QRTOKEN: check if pairing mechanism works correctly (sig based)"""

        self.execute_correct_pairing(user='def')

        return

# --------------------------------------------------------------------------- --

    def test_pairing_sig_with_fquser(self):
        """QRTOKEN: check if pairing mechanism works correctly (sig based)"""

        self.execute_correct_pairing(user='def@mymixrealm')

        return

# --------------------------------------------------------------------------- --

    def test_pairing_tan(self):
        """QRTOKEN: check if pairing mechanism works correctly (tan based)"""

        self.execute_correct_pairing(use_tan=True)

# --------------------------------------------------------------------------- --

    def test_pairing_response_after_pairing(self):
        """QRTOKEN: check if a sent pairing response after pairing will fail"""

        user_token_id = self.execute_correct_pairing()

        # ------------------------------------------------------------------- --

        # create another pairing response

        pairing_response = self.create_pairing_response_by_serial(
            user_token_id)

        # ------------------------------------------------------------------- --

        # send pairing response

        response_dict = self.send_pairing_response(pairing_response)

        # ------------------------------------------------------------------- --

        result = response_dict.get('result', {})
        self.assertIn('status', result)

        status = result.get('status')
        self.assertEqual(status, False)

        # FIXME: removed since the new interface doesn't
        # propagate error messages (should be fixed in
        # the future, when there is a stable debug mode)

        # self.assertIn('error', result)
        # error = result.get('error')

        # # ---------------------------------------------------------------- --

        # self.assertIn('message', error)
        # self.assertIn('code', error)

        # # ---------------------------------------------------------------- --

        # self.assertIn('Unfitting request for this token', error.get('message'))
        # self.assertEqual(905, error.get('code'))

# --------------------------------------------------------------------------- --

    def test_pairing_ill_formatted_pairing_response(self):
        """QRTOKEN: check if error is thrown on ill-formatted pairing response """

        self.enroll_qrtoken()
        response_dict = self.send_pairing_response('look, mom! i\'m crashing '
                                                   'the server')

        # ------------------------------------------------------------------- --

        result = response_dict.get('result', {})
        self.assertIn('status', result)

        status = result.get('status')
        self.assertEqual(status, False)

        # FIXME: removed since the new interface doesn't
        # propagate error messages (should be fixed in
        # the future, when there is a stable debug mode)

        # self.assertIn('error', result)
        # error = result.get('error')

        # ------------------------------------------------------------------- --

        # self.assertIn('message', error)
        # self.assertIn('code', error)

        # ------------------------------------------------------------------- --

        # self.assertIn('Malformed pairing response', error.get('message'))
        # self.assertEqual(905, error.get('code'))

# --------------------------------------------------------------------------- --

    def test_wrong_challenge_response(self):
        """
        QRTOKEN: Testing if a wrong challenge response in pairing will fail
        """

        # ------------------------------------------------------------------- --

        # enroll token

        pairing_url, pin = self.enroll_qrtoken()

        # ------------------------------------------------------------------- --

        # execute the first step of the pairing

        challenge_url = self.pair_until_challenge(pairing_url, pin)

        # ------------------------------------------------------------------- --

        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        serial = challenge['user_token_id']

        params = {'serial': serial,
                  'transactionid': challenge['transaction_id'],
                  'pass': 'certainly a wrong otp'}

        response = self.make_validate_request('check_s', params)
        response_dict = json.loads(response.body)

        # ------------------------------------------------------------------- --

        result = response_dict.get('result', {})
        self.assertIn('status', result)
        self.assertIn('value', result)

        status = result.get('status')
        self.assertEqual(status, True)

        value = result.get('value')
        self.assertEqual(value, False)

# --------------------------------------------------------------------------- --

    def test_pairing_response_wrong_response_version(self):
        """
        QRTOKEN: pairing response with wrong response version should fail
        """

        # enroll token

        pairing_url, pin = self.enroll_qrtoken()

        # ------------------------------------------------------------------- --

        # save data extracted from pairing url to the 'user database'

        user_token_id = self.create_user_token_by_pairing_url(pairing_url, pin)

        # ------------------------------------------------------------------- --

        # create the pairing response

        token_serial = self.tokens[user_token_id]['serial']
        server_public_key = self.tokens[user_token_id]['server_public_key']

        NONEXISTENT_RESPONSE_VERSION = 127
        header = struct.pack('<bI', NONEXISTENT_RESPONSE_VERSION, TYPE_QRTOKEN)

        pairing_response = b''
        pairing_response += struct.pack('<bI', TYPE_QRTOKEN, user_token_id)

        pairing_response += self.public_key

        pairing_response += token_serial.encode('utf8') + b'\x00\x00'

        # ------------------------------------------------------------------- --

        # create public diffie hellman component

        r = os.urandom(32)
        R = calc_dh_base(r)

        # ------------------------------------------------------------------- --

        # derive encryption key and nonce

        ss = calc_dh(r, server_public_key)
        U = SHA256.new(ss).digest()
        encryption_key = U[0:16]
        nonce = U[16:32]

        # ------------------------------------------------------------------- --

        # encrypt in EAX mode

        cipher = AES.new(encryption_key, AES.MODE_EAX, nonce)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(pairing_response)

        wrong_pairing_response = encode_base64_urlsafe(header + R +
                                                       ciphertext + tag)

        response_dict = self.send_pairing_response(wrong_pairing_response)

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        # ------------------------------------------------------------------- --

        self.assertIn('status', result)
        status = result.get('status')
        self.assertEqual(status, False)

        # FIXME: removed since the new interface doesn't
        # propagate error messages (should be fixed in
        # the future, when there is a stable debug mode)

        # self.assertIn('error', result)
        # error = result.get('error')

        # # ---------------------------------------------------------------- --

        # self.assertIn('message', error)
        # self.assertIn('code', error)

        # # ---------------------------------------------------------------- --

        # self.assertIn('Unexpected pair-response version', error.get('message'))
        # self.assertEqual(-311, error.get('code'))

# --------------------------------------------------------------------------- --

    def test_pairing_response_wrong_serial(self):
        """
        QRTOKEN: checking, if pairing response with wrong serial will fail
        """

        # enroll token

        pairing_url, pin = self.enroll_qrtoken()

        # ------------------------------------------------------------------- --

        # save data extracted from pairing url to the 'user database'

        user_token_id = self.create_user_token_by_pairing_url(pairing_url, pin)

        # ------------------------------------------------------------------- --

        # create the pairing response

        header = struct.pack('<bI', PAIR_RESPONSE_VERSION, TYPE_QRTOKEN)

        token_serial = "WRONGSERIAL!!11!!1"
        server_public_key = self.tokens[user_token_id]['server_public_key']

        pairing_response = b''
        pairing_response += struct.pack('<bI', TYPE_QRTOKEN, user_token_id)

        pairing_response += self.public_key

        pairing_response += token_serial.encode('utf8') + b'\x00\x00'

        # ------------------------------------------------------------------- --

        # create public diffie hellman component

        r = os.urandom(32)
        R = calc_dh_base(r)

        # ------------------------------------------------------------------- --

        # derive encryption key and nonce

        ss = calc_dh(r, server_public_key)
        U = SHA256.new(ss).digest()
        encryption_key = U[0:16]
        nonce = U[16:32]

        # ------------------------------------------------------------------- --

        # encrypt in EAX mode

        cipher = AES.new(encryption_key, AES.MODE_EAX, nonce)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(pairing_response)

        wrong_pairing_response = encode_base64_urlsafe(header + R +
                                                       ciphertext + tag)

        response_dict = self.send_pairing_response(wrong_pairing_response)

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        # ------------------------------------------------------------------- --

        self.assertIn('status', result)
        status = result.get('status')
        self.assertEqual(status, False)

        # FIXME: removed since the new interface doesn't
        # propagate error messages (should be fixed in
        # the future, when there is a stable debug mode)

        # self.assertIn('error', result)
        # error = result.get('error')

        # # ---------------------------------------------------------------- --

        # self.assertIn('message', error)
        # self.assertIn('code', error)

        # # ---------------------------------------------------------------- --

        # # TODO: error mesage in here is pretty cryptic, because linotp
        # # creates a new token for WRONGSERIAL and then exits because it
        # # has the wrong state

        # self.assertIn('Unfitting request for this token', error.get('message'))
        # self.assertEqual(905, error.get('code'))

# --------------------------------------------------------------------------- --

    def test_pairing_response_wrong_token_type(self):
        """
        QRTOKEN: checking, if pairing response with wrong token type will fail
        """

        # enroll token

        pairing_url, pin = self.enroll_qrtoken()

        # ------------------------------------------------------------------- --

        # save data extracted from pairing url to the 'user database'

        user_token_id = self.create_user_token_by_pairing_url(pairing_url, pin)

        # ------------------------------------------------------------------- --

        # create the pairing response

        header = struct.pack('<bI', PAIR_RESPONSE_VERSION, TYPE_QRTOKEN)

        token_serial = self.tokens[user_token_id]['serial']
        server_public_key = self.tokens[user_token_id]['server_public_key']

        NON_EXISTENT_PROTOCOL = 127

        pairing_response = b''
        pairing_response += struct.pack('<bI', NON_EXISTENT_PROTOCOL,
                                        user_token_id)

        pairing_response += self.public_key

        pairing_response += token_serial.encode('utf8') + b'\x00\x00'

        # ------------------------------------------------------------------- --

        # create public diffie hellman component

        r = os.urandom(32)
        R = calc_dh_base(r)

        # ------------------------------------------------------------------- --

        # derive encryption key and nonce

        ss = calc_dh(r, server_public_key)
        U = SHA256.new(ss).digest()
        encryption_key = U[0:16]
        nonce = U[16:32]

        # ------------------------------------------------------------------- --

        # encrypt in EAX mode

        cipher = AES.new(encryption_key, AES.MODE_EAX, nonce)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(pairing_response)

        wrong_pairing_response = encode_base64_urlsafe(header + R +
                                                       ciphertext + tag)

        response_dict = self.send_pairing_response(wrong_pairing_response)

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        # ------------------------------------------------------------------- --

        self.assertIn('status', result)
        status = result.get('status')
        self.assertEqual(status, False)

        # FIXME: removed since the new interface doesn't
        # propagate error messages (should be fixed in
        # the future, when there is a stable debug mode)

        # self.assertIn('error', result)
        # error = result.get('error')

        # # ---------------------------------------------------------------- --

        # self.assertIn('message', error)
        # self.assertIn('code', error)

        # # ---------------------------------------------------------------- --

        # self.assertIn('wrong token type', error.get('message'))
        # self.assertEqual(-311, error.get('code'))

# --------------------------------------------------------------------------- --

    def test_pairing_response_wrong_R(self):
        """
        QRTOKEN: checking, if pairing response with wrong R will fail
        """

        # enroll token

        pairing_url, pin = self.enroll_qrtoken()

        # ------------------------------------------------------------------- --

        # save data extracted from pairing url to the 'user database'

        user_token_id = self.create_user_token_by_pairing_url(pairing_url, pin)

        # ------------------------------------------------------------------- --

        # create the pairing response
        header = struct.pack('<bI', PAIR_RESPONSE_VERSION, TYPE_QRTOKEN)

        token_serial = self.tokens[user_token_id]['serial']
        server_public_key = self.tokens[user_token_id]['server_public_key']

        pairing_response = b''
        pairing_response += struct.pack('<bI', TYPE_QRTOKEN, user_token_id)

        pairing_response += self.public_key

        pairing_response += token_serial.encode('utf8') + b'\x00\x00'

        # ------------------------------------------------------------------- --

        # create wrong public diffie hellman component

        r = os.urandom(32)
        probably_not_the_same_r = os.urandom(32)
        R = calc_dh_base(probably_not_the_same_r)

        # ------------------------------------------------------------------- --

        # derive encryption key and nonce

        ss = calc_dh(r, server_public_key)
        U = SHA256.new(ss).digest()
        encryption_key = U[0:16]
        nonce = U[16:32]

        # ------------------------------------------------------------------- --

        # encrypt in EAX mode

        cipher = AES.new(encryption_key, AES.MODE_EAX, nonce)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(pairing_response)

        wrong_pairing_response = encode_base64_urlsafe(header + R +
                                                       ciphertext + tag)

        response_dict = self.send_pairing_response(wrong_pairing_response)

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        # ------------------------------------------------------------------- --

        self.assertIn('status', result)
        status = result.get('status')
        self.assertEqual(status, False)

        # FIXME: removed since the new interface doesn't
        # propagate error messages (should be fixed in
        # the future, when there is a stable debug mode)

        # self.assertIn('error', result)
        # error = result.get('error')

        # # ---------------------------------------------------------------- --

        # self.assertIn('message', error)
        # self.assertIn('code', error)

        # # ---------------------------------------------------------------- --

        # self.assertIn('MAC check failed', error.get('message'))
        # self.assertEqual(-311, error.get('code'))

# --------------------------------------------------------------------------- --

    def test_pairing_response_double_send(self):
        """
        QRTOKEN: Testing if sending 2 pairing responses will fail.
        """

        # ------------------------------------------------------------------- --

        # enroll token

        pairing_url, pin = self.enroll_qrtoken()

        # ------------------------------------------------------------------- --

        # save data extracted from pairing url to the 'user database'

        user_token_id = self.create_user_token_by_pairing_url(pairing_url, pin)

        # ------------------------------------------------------------------- --

        # create the pairing response

        pairing_response = self.create_pairing_response_by_serial(
            user_token_id)

        # ------------------------------------------------------------------- --

        # send pairing responses

        __ = self.send_pairing_response(pairing_response)  # should be ok
        response_dict = self.send_pairing_response(pairing_response)

        # ------------------------------------------------------------------- --

        result = response_dict.get('result', {})
        self.assertIn('status', result)

        status = result.get('status')
        self.assertEqual(status, False)

        # FIXME: removed since the new interface doesn't
        # propagate error messages (should be fixed in
        # the future, when there is a stable debug mode)

        # self.assertIn('error', result)
        # error = result.get('error')

        # # ---------------------------------------------------------------- --

        # self.assertIn('message', error)
        # self.assertIn('code', error)

        # # ---------------------------------------------------------------- --

        # self.assertIn('Unfitting request for this token', error.get('message'))
        # self.assertEqual(905, error.get('code'))

# --------------------------------------------------------------------------- --

    def test_challenge_response_serial_signature(self):
        """ QRTOKEN: Executing complete challenge response with serial/sig """

        self.execute_correct_serial_challenge(QRTOKEN_CT_FREE)

# --------------------------------------------------------------------------- --

    def test_challenge_response_serial_signature_login(self):
        """ QRTOKEN: Executing complete login flow with serial/sig """

        self.execute_correct_serial_challenge(QRTOKEN_CT_AUTH)

# --------------------------------------------------------------------------- --

    def test_challenge_response_serial_tan(self):
        """ QRTOKEN: Executing complete challenge response with serial/tan """

        self.execute_correct_serial_challenge(QRTOKEN_CT_FREE, use_tan=True)

# --------------------------------------------------------------------------- --

    def test_challenge_response_serial_tan_login(self):
        """ QRTOKEN: Executing complete login flow with serial/tan """

        self.execute_correct_serial_challenge(QRTOKEN_CT_AUTH, use_tan=True)

# --------------------------------------------------------------------------- --

    def test_wrong_serial_challenge_response(self):
        """ QRTOKEN: Sending a wrong challenge response on token (serial) """

        challenge_url = self.trigger_challenge_by_serial(QRTOKEN_CT_FREE)

        # ------------------------------------------------------------------- --

        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        serial = challenge['user_token_id']

        params = {'serial': serial,
                  'transactionid': challenge['transaction_id'],
                  'pass': 'certainly a wrong otp'}

        response = self.make_validate_request('check_s', params)
        response_dict = json.loads(response.body)

        # ------------------------------------------------------------------- --

        result = response_dict.get('result', {})
        self.assertIn('status', result)
        self.assertIn('value', result)

        status = result.get('status')
        self.assertEqual(status, True)

        value = result.get('value')
        self.assertEqual(value, False)

# --------------------------------------------------------------------------- --

    def trigger_challenge_by_serial(self, content_type):

        user_token_id = self.execute_correct_pairing()

        # ------------------------------------------------------------------- --

        token = self.tokens[user_token_id]
        serial = token['serial']
        pin = token['pin']

        params = {'serial': serial,
                  'pass': pin,
                  'content_type': content_type}

        if content_type == QRTOKEN_CT_FREE:
            params['data'] = '5 million dollar sheeeeesh'
        elif content_type == QRTOKEN_CT_AUTH:
            params['data'] = 'root@localhost'

        response = self.make_validate_request('check_s', params)
        response_dict = json.loads(response.body)

        self.assertIn('detail', response_dict)
        detail = response_dict.get('detail')

        # ------------------------------------------------------------------- --

        self.assertIn('transactionid', detail)
        self.assertIn('message', detail)

        challenge_url = detail.get('message')

        self.assertTrue(challenge_url.startswith('lseqr://'))

        return challenge_url

# --------------------------------------------------------------------------- --

    def test_unpaired_challenge_serial(self):
        """
         QRTOKEN: Check if unpaired token refuses incoming challenge requests
        """

        pairing_url, pin = self.enroll_qrtoken()
        user_token_id = self.create_user_token_by_pairing_url(pairing_url, pin)

        # ------------------------------------------------------------------- --

        token = self.tokens[user_token_id]
        serial = token['serial']

        # ------------------------------------------------------------------- --

        params = {'serial': serial,
                  'data': 'yikes! another possible catastrophe',
                  'pass': pin}

        response = self.make_validate_request('check_s', params)
        response_dict = json.loads(response.body)

        # ------------------------------------------------------------------- --

        result = response_dict.get('result', {})
        self.assertIn('status', result)
        self.assertIn('value', result)

        status = result.get('status')
        self.assertEqual(status, True, response)

        value = result.get('value')
        self.assertEqual(value, False, response)

# --------------------------------------------------------------------------- --

    def test_validate_user_pin_policy_1_wrong_pin(self):
        """ QRTOKEN: Validating user with pin policy 1 (wrong pin)"""

        user_token_id = self.execute_correct_pairing()
        token = self.tokens[user_token_id]
        serial = token['serial']

        # ------------------------------------------------------------------- --

        self.setPinPolicy(action='otppin=1, ')
        self.assign_token_to_user(serial=serial, user_login='molière')

        # ------------------------------------------------------------------- --

        params = {'user': 'molière', 'pass': 'wrongpassword',
                  'data': '2000 dollars to that nigerian prince'}
        response = self.make_validate_request('check', params)
        response_dict = json.loads(response.body)

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        self.assertIn('value', result)
        value = response_dict.get('value')

        self.assertFalse(value)

# --------------------------------------------------------------------------- --

    def set_pin(self, serial, pin):
        """
        sets the pin for a token

        :param serial: The serial of the token
        :pin: The pin that should be set
        """

        params = {'serial': serial, 'pin': pin}

        response = self.make_admin_request('set', params)
        response_dict = json.loads(response.body)

        # ------------------------------------------------------------------- --

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        self.assertIn('status', result)
        status = result.get('status')

        self.assertTrue(status)

        # ------------------------------------------------------------------- --

        self.assertIn('value', result)
        value = result.get('value')

        self.assertIn('set pin', value)
        set_pin = value.get('set pin')

        self.assertEqual(set_pin, 1)

# --------------------------------------------------------------------------- --

    def create_multiple_challenges(self, user_login, pin):
        """
        Creates 2 tokens, pairs them and assigns them to the same user
        with the same pin, then calls validate/check with user and pin
        supplied

        :returns the response dict
        """

        user_token_id1 = self.execute_correct_pairing()
        serial1 = self.tokens[user_token_id1]['serial']

        user_token_id2 = self.execute_correct_pairing()
        serial2 = self.tokens[user_token_id2]['serial']

        self.assign_token_to_user(serial=serial1, user_login=user_login)
        self.assign_token_to_user(serial=serial2, user_login=user_login)
        self.set_pin(serial1, pin)
        self.set_pin(serial2, pin)

        # ------------------------------------------------------------------- --

        params = {'user': 'root', 'pass': '1234',
                  'data': '2000 dollars to that nigerian prince'}

        # ------------------------------------------------------------------- --

        response = self.make_validate_request('check', params)
        response_dict = json.loads(response.body)

        self.assertIn('detail', response_dict)
        detail = response_dict.get('detail')

        self.assertIn('challenges', detail)
        challenges = detail.get('challenges')

        # ------------------------------------------------------------------- --

        self.assertIn(serial1, challenges)
        data_1 = challenges.get(serial1)

        self.assertIn(serial2, challenges)
        data_2 = challenges.get(serial2)

        # ------------------------------------------------------------------- --

        self.assertIn('transactionid', data_1)
        self.assertIn('transactionid', data_2)

        self.assertIn('message', data_1)
        self.assertIn('message', data_2)

        # ------------------------------------------------------------------- --

        return response_dict

# --------------------------------------------------------------------------- --

    def test_multiple_challenges(self):
        """ QRTOKEN: creating multiple challenges and validate them """

        # ------------------------------------------------------------------- --

        # validate by parent transaction_id

        # ------------------------------------------------------------------- --

        response_dict = self.create_multiple_challenges('root', '1234')
        challenges = response_dict['detail']['challenges']

        serial = challenges.keys()[0]
        challenge_url = challenges[serial]['message']

        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        transaction_id = response_dict['detail']['transactionid']
        params = {'transactionid': transaction_id, 'pass': sig}

        # ------------------------------------------------------------------- --

        response = self.make_validate_request('check_t', params)
        response_dict = json.loads(response.body)
        self.assertIn('status', response_dict.get('result', {}))

        status = response_dict.get('result', {}).get('status')
        self.assertEqual(status, True)

        # ------------------------------------------------------------------- --

        value = response_dict.get('result', {}).get('value')

        self.assertIn('value', value)
        self.assertIn('failcount', value)

        value_value = value.get('value')

        self.assertTrue(value_value)

        # ------------------------------------------------------------------- --

        # validate by child transaction_id

        # ------------------------------------------------------------------- --

        response_dict = self.create_multiple_challenges('root', '1234')
        challenges = response_dict['detail']['challenges']

        serial = challenges.keys()[0]
        challenge_url = challenges[serial]['message']

        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        transaction_id = challenges[serial]['transactionid']
        params = {'transactionid': transaction_id, 'pass': sig}

        # ------------------------------------------------------------------- --

        response = self.make_validate_request('check_t', params)
        response_dict = json.loads(response.body)
        self.assertIn('status', response_dict.get('result', {}))

        status = response_dict.get('result', {}).get('status')
        self.assertEqual(status, True)

        # ------------------------------------------------------------------- --

        value = response_dict.get('result', {}).get('value')

        self.assertIn('value', value)
        self.assertIn('failcount', value)

        value_value = value.get('value')

        self.assertTrue(value_value)

# --------------------------------------------------------------------------- --

    def test_validate_user_pin_policy_1(self):
        """ QRTOKEN: Validating user with pin policy 1 """

        user_token_id = self.execute_correct_pairing()
        token = self.tokens[user_token_id]
        serial = token['serial']

        # ------------------------------------------------------------------- --

        self.setPinPolicy(action='otppin=1, ')
        self.assign_token_to_user(serial=serial, user_login='molière')

        # ------------------------------------------------------------------- --

        params = {'user': 'molière', 'pass': 'molière',
                  'data': '2000 dollars to that nigerian prince'}
        response = self.make_validate_request('check', params)
        response_dict = json.loads(response.body)

        self.assertIn('detail', response_dict)
        detail = response_dict.get('detail')

        # ------------------------------------------------------------------- --

        self.assertIn('transactionid', detail)
        self.assertIn('message', detail)

        challenge_url = detail.get('message')

        self.assertTrue(challenge_url.startswith('lseqr://'))

        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        # ------------------------------------------------------------------- --

        transaction_id = challenge["transaction_id"]

        params = {'user': 'molière',
                  'transactionid': transaction_id,
                  'pass': sig}
        response = self.make_validate_request('check', params)
        response_dict = json.loads(response.body)

        # ------------------------------------------------------------------- --

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        self.assertIn('value', result)
        value = result.get('value')

        # ------------------------------------------------------------------- --

        self.assertTrue(value)

# --------------------------------------------------------------------------- --

    def test_validate_user_pin_policy_2(self):
        """ QRTOKEN: Validating user with pin policy 2 """

        user_token_id = self.execute_correct_pairing()
        token = self.tokens[user_token_id]
        serial = token['serial']

        # ------------------------------------------------------------------- --

        # otppin=2 - on validation NO PIN should be entered atall
        self.setPinPolicy(action='otppin=2, ')
        self.assign_token_to_user(serial=serial, user_login='root')

        # ------------------------------------------------------------------- --

        params = {'user': 'root', 'pass': '',
                  'data': '2000 dollars to that nigerian prince'}
        response = self.make_validate_request('check', params)
        response_dict = json.loads(response.body)

        self.assertIn('detail', response_dict)
        detail = response_dict.get('detail')

        # ------------------------------------------------------------------- --

        self.assertIn('transactionid', detail)
        self.assertIn('message', detail)

        challenge_url = detail.get('message')

        self.assertTrue(challenge_url.startswith('lseqr://'))

        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        # ------------------------------------------------------------------- --

        transaction_id = challenge["transaction_id"]

        params = {'user': 'root', 'transactionid': transaction_id, 'pass': sig}
        response = self.make_validate_request('check', params)
        response_dict = json.loads(response.body)

        # ------------------------------------------------------------------- --

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        self.assertIn('value', result)
        value = result.get('value')

        # ------------------------------------------------------------------- --

        self.assertTrue(value)


# --------------------------------------------------------------------------- --

    def execute_correct_serial_challenge(self, content_type, use_tan=False):

        challenge_url = self.trigger_challenge_by_serial(content_type)

        # ------------------------------------------------------------------- --

        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        # ------------------------------------------------------------------- --

        # check if the content type is right

        returned_content_type = challenge['content_type']
        self.assertEqual(returned_content_type, content_type)

        # ------------------------------------------------------------------- --

        # prepare params for validate

        pass_ = tan if use_tan else sig

        params = {'transactionid': challenge['transaction_id'],
                  'pass': pass_}

        # again, we ignore the callback definitions

        response = self.make_validate_request('check_t', params)
        response_dict = json.loads(response.body)

        self.assertIn('status', response_dict.get('result', {}))

        status = response_dict.get('result', {}).get('status')
        self.assertEqual(status, True)

        # ------------------------------------------------------------------- --

        value = response_dict.get('result', {}).get('value')

        self.assertIn('value', value)
        self.assertIn('failcount', value)

        value_value = value.get('value')

        self.assertTrue(value_value)

# --------------------------------------------------------------------------- --

    def test_offline_info(self):
        """ QRTOKEN: Checking if offline info is transmitted on validation """

        user_token_id = self.execute_correct_pairing()
        token = self.tokens[user_token_id]
        serial = token['serial']

        # ------------------------------------------------------------------- --

        self.setPinPolicy(action='otppin=1, ')
        self.assign_token_to_user(serial=serial, user_login='molière')

        # ------------------------------------------------------------------- --

        params = {'user': 'molière', 'pass': 'molière',
                  'data': '2000 dollars to that nigerian prince'}
        response = self.make_validate_request('check', params)
        response_dict = json.loads(response.body)

        self.assertIn('detail', response_dict)
        detail = response_dict.get('detail')

        # ------------------------------------------------------------------- --

        self.assertIn('transactionid', detail)
        self.assertIn('message', detail)

        challenge_url = detail.get('message')

        self.assertTrue(challenge_url.startswith('lseqr://'))

        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        # ------------------------------------------------------------------- --

        transaction_id = challenge["transaction_id"]

        params = {'user': 'molière',
                  'transactionid': transaction_id,
                  'pass': sig,
                  'use_offline': True}

        response = self.make_validate_request('check', params)
        response_dict = json.loads(response.body)

        # ------------------------------------------------------------------- --

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        self.assertIn('value', result)
        value = result.get('value')

        self.assertTrue(value)

        # even if we provided the use_offline parameter, the data
        # should not be returned because the policy was not set

        self.assertNotIn('detail', response_dict)

        # ------------------------------------------------------------------- --

        # now we set the policy and do it again

        self.setOfflinePolicy()

        # ------------------------------------------------------------------- --

        params = {'user': 'molière', 'pass': 'molière',
                  'data': '2000 dollars to that nigerian prince'}
        response = self.make_validate_request('check', params)
        response_dict = json.loads(response.body)

        self.assertIn('detail', response_dict)
        detail = response_dict.get('detail')

        # ------------------------------------------------------------------- --

        self.assertIn('transactionid', detail)
        self.assertIn('message', detail)

        challenge_url = detail.get('message')

        self.assertTrue(challenge_url.startswith('lseqr://'))

        challenge, sig, tan = self.decrypt_and_verify_challenge(challenge_url)

        # ------------------------------------------------------------------- --

        transaction_id = challenge["transaction_id"]

        params = {'user': 'molière',
                  'transactionid': transaction_id,
                  'pass': sig,
                  'use_offline': True}

        response = self.make_validate_request('check', params)
        response_dict = json.loads(response.body)

        # ------------------------------------------------------------------- --

        self.assertIn('result', response_dict)
        result = response_dict.get('result')

        self.assertIn('value', result)
        value = result.get('value')

        # ------------------------------------------------------------------- --

        self.assertTrue(value)

        self.assertIn('detail', response_dict)
        detail = response_dict.get('detail')

        self.assertIn('offline', detail)
        offline = detail.get('offline')

        self.assertIn('type', offline)
        self.assertIn('serial', offline)
        self.assertIn('offline_info', offline)

        token_type = offline.get('type')
        serial = offline.get('serial')

        self.assertEqual(token_type, 'qr')
        self.assertEqual(serial, token['serial'])

        offline_info = offline.get('offline_info')
        self.assertIn('user_token_id', offline_info)
        self.assertIn('public_key', offline_info)

        received_user_token_id = offline_info.get('user_token_id')
        self.assertEqual(user_token_id, received_user_token_id)

        public_key = offline_info.get('public_key')
        self.assertEqual(public_key, b64encode(self.public_key))

    # ----------------------------------------------------------------------- --

    def test_unpairing(self):

        """ QRTOKEN: Test if unpairing works with serial + policy check """

        pairing_url, pin = self.enroll_qrtoken()

        # execute the first step of the pairing

        challenge_url = self.pair_until_challenge(pairing_url, pin)

        # execute the second step

        user_token_id = self.verify_pairing(challenge_url)

        # -------------------------------------------------------------------- -

        # unpair the token with serial without setting unpair policy

        serial = self.tokens[user_token_id]['serial']

        params = {'serial': serial}

        response = self.make_admin_request('unpair', params)
        response_dict = json.loads(response.body)

        # call should succeed, because with no policy anything goes

        self.assertTrue(response_dict.get('result', {}).get('value', False))

        # -------------------------------------------------------------------- -

        # unpair again now with deactivated policy

        self.setUnassignPolicy()  # just a dummy to activate the
                                  # policy engine altogether

        response = self.make_admin_request('unpair', params)
        response_dict = json.loads(response.body)

        # call should fail, because policy engine is activated (unassign
        # dummy policy is active), but admin-unpair is not activated

        self.assertFalse(response_dict.get('result', {}).get('value', True))

        # -------------------------------------------------------------------- -

        # activate policy

        self.setUnpairPolicy(active=True)

        response = self.make_admin_request('unpair', params)
        response_dict = json.loads(response.body)

        # call should succeed now

        self.assertTrue(response_dict.get('result', {}).get('value', True))

        # -------------------------------------------------------------------- -

        # do a second pairing
        # execute the first step of the pairing

        challenge_url = self.pair_until_challenge(pairing_url, pin)

        # execute the second step

        self.verify_pairing(challenge_url)

# --------------------------------------------------------------------------- --

    def test_unpairing_with_user(self):

        """ QRTOKEN: Test if unpairing works with user """

        pairing_url, pin = self.enroll_qrtoken()

        # execute the first step of the pairing

        challenge_url = self.pair_until_challenge(pairing_url, pin)

        # execute the second step

        user_token_id = self.verify_pairing(challenge_url)

        # -------------------------------------------------------------------- -

        # assign token to user

        serial = self.tokens[user_token_id]['serial']

        self.assign_token_to_user(serial=serial, user_login='molière')

        # -------------------------------------------------------------------- -

        # unpair the token with user

        params = {'user': 'molière'}

        response = self.make_admin_request('unpair', params)
        response_dict = json.loads(response.body)

        # call should succeed

        self.assertTrue(response_dict.get('result', {}).get('value', False))

        # -------------------------------------------------------------------- -

        # unpair the token with nonexistant user

        params = {'user': 'iprobablydontexist'}

        response = self.make_admin_request('unpair', params)
        response_dict = json.loads(response.body)

        # call should fail, because user is not found

        self.assertFalse(response_dict.get('result', {}).get('value', True))

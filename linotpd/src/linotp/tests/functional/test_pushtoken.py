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

import os
import json
import struct
import mock
from tempfile import NamedTemporaryFile
from collections import defaultdict
from linotp.tests import TestController
from linotp.lib.crypto import dsa_to_dh_public
from linotp.lib.crypto import dsa_to_dh_secret
from linotp.lib.crypto import encode_base64_urlsafe
from linotp.lib.crypto import decode_base64_urlsafe
from linotp.lib.util import int_from_bytes
from pysodium import crypto_scalarmult_curve25519 as calc_dh
from pysodium import crypto_scalarmult_curve25519_base as calc_dh_base
from pysodium import crypto_sign_keypair as gen_dsa_keypair
from pysodium import crypto_sign_detached
from pysodium import crypto_sign_verify_detached
import linotp.provider.pushprovider.default_push_provider as default_provider

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Util import Counter

FLAG_PAIR_PK = 1 << 0
FLAG_PAIR_SERIAL = 1 << 1
FLAG_PAIR_CBURL = 1 << 2
FLAG_PAIR_CBSMS = 1 << 3
FLAG_PAIR_DIGITS = 1 << 4
FLAG_PAIR_HMAC = 1 << 5
PAIRING_URL_VERSION = 2
PAIR_RESPONSE_VERSION = 1

TYPE_PUSHTOKEN = 4
CHALLENGE_URL_VERSION = 1

CONTENT_TYPE_SIGNREQ = 0
CONTENT_TYPE_PAIRING = 1
CONTENT_TYPE_LOGIN = 2


def u64_to_transaction_id(u64_int):
    # HACK! counterpart to transaction_id_to_u64 in
    # lib.tokens.qrtokenclass
    rest = u64_int % 100
    if rest == 0:
        return str(u64_int / 100)
    else:
        before = u64_int // 100
        return '%s.%s' % (str(before), str(rest))

# --------------------------------------------------------------------------- --


class TestPushToken(TestController):

    def setUp(self):

        self.delete_all_policies()
        self.delete_all_token()
        self.delete_all_realms()
        self.delete_all_resolvers()
        super(TestPushToken, self).setUp()
        self.create_common_resolvers()
        self.create_common_realms()
        self.create_dummy_cb_policies()

        # ------------------------------------------------------------------- --

        self.gda = 'DEADBEEF'
        self.tokens = defaultdict(dict)

        # ------------------------------------------------------------------- --

        pk, sk = gen_dsa_keypair()
        self.secret_key = sk
        self.public_key = pk

        # ------------------------------------------------------------------ --

        # we need a dummy file to sneak past the file existence check
        # in the initial provider configuration

        self.dummy_temp_cert = NamedTemporaryFile()

        # ------------------------------------------------------------------ --

        # make dummy provider config
        p_config = {"push_url": "https://pushproxy.keyidentity.com",
                    "access_certificate": self.dummy_temp_cert.name,
                    "server_certificate": ""}

        params = {'name': 'dummy_provider',
                  'class': 'DefaultPushProvider',
                  'config': json.dumps(p_config),
                  'timeout': '120',
                  'type': 'push'}

        self.make_system_request('setProvider', params=params)

        # ------------------------------------------------------------------ --

        params = {'name': 'dummy_push_policy',
                  'scope': 'authentication',
                  'action': 'push_provider=dummy_provider',
                  'user': '*',
                  'realm': '*',
                  'client': '',
                  'time': ''}

        self.create_policy(params=params)

# --------------------------------------------------------------------------- --

    def tearDown(self):

        self.delete_all_policies()
        self.delete_all_realms()
        self.delete_all_resolvers()
        self.delete_all_token()
        super(TestPushToken, self).tearDown()

        # ------------------------------------------------------------------- --

        # delete dummy provider config

        params = {'name': 'dummy_provider_config',
                  'type': 'push'}

        self.make_system_request('delProvider', params=params)

        # ------------------------------------------------------------------- --

        # delete temp file

        self.dummy_temp_cert.close()

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

    def create_dummy_cb_policies(self):

        """ sets some dummy callback policies. callback policies get ignored
        by the tests, but are nonetheless necessary for the backend """

        # ------------------------------------------------------------------- --

        # set pairing callback policies

        params = {'name': 'dummy1',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'pushtoken_pairing_callback_url=foo',
                  'user': '*'}

        self.setPolicy(params)

        # ------------------------------------------------------------------- --

        # set challenge callback policies

        params = {'name': 'dummy2',
                  'scope': 'authentication',
                  'realm': '*',
                  'action': 'pushtoken_challenge_callback_url=foo',
                  'user': '*'}

        self.setPolicy(params)

# --------------------------------------------------------------------------- --

    def enroll_pushtoken(self, user=None, pin='1234'):

        """
        enrolls a pushtoken

        :param user: the user to which the token should be assigned
        :param pin: the pin the token should have after enrollment
            (default is 1234)

        :returns pairing url
        """

        # initialize an unfinished token on the server

        params = {'type': 'push', 'pin': pin}

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

        return pairing_url

# --------------------------------------------------------------------------- --

    def execute_correct_pairing(self, user=None, pin='1234'):

        """
        enroll token and pair it

        :param user: the user the token should be assigned to
            (default: None)
        :param pin: the pin the token should have (default '1234')

        :return user_token_id (key for self.tokens)
        """

        # ------------------------------------------------------------------- --

        # enroll token

        pairing_url = self.enroll_pushtoken(user=user, pin=pin)

        # ------------------------------------------------------------------- --

        # execute the first step of the pairing

        challenge_url = self.pair_until_challenge(pairing_url, pin)

        # ------------------------------------------------------------------- --

        # parse, descrypt and verify the challenge url

        challenge, sig = self.decrypt_and_verify_challenge(challenge_url)

        # ------------------------------------------------------------------- --

        # check if the content type is right (we are doing pairing
        # right now, so type must be CONTENT_TYPE_PAIRING)

        content_type = challenge['content_type']
        self.assertEqual(content_type, CONTENT_TYPE_PAIRING)

        # ------------------------------------------------------------------- --

        # prepare params for validate

        params = {'transactionid': challenge['transaction_id'],
                  'pass': sig}

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

        user_token_id = challenge['user_token_id']

        return user_token_id

# --------------------------------------------------------------------------- --

    def pair_until_challenge(self, pairing_url, pin='1234'):

        """
        Executes a pairing for an existing token until the last
        step in which the challenge response is sent.

        :param pairing_url: the pairing url provided by the token

        :param pin: the pin of the token (default: '1234')

        :returns the response dictionary received by the server. if all goes
            right it will include the challenge url
        """

        # save data extracted from pairing url to the 'user database'

        user_token_id = self.create_user_token_by_pairing_url(pairing_url, pin)

        # ------------------------------------------------------------------- --

        # create the pairing response

        pairing_response = self.create_pairing_response_by_serial(user_token_id)

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

        challenge_url = self.trigger_challenge(user_token_id, data='')

        return challenge_url

# --------------------------------------------------------------------------- --

    def create_user_token_by_pairing_url(self, pairing_url, pin='1234'):

        """
        parses the pairing url and saves the extracted data in
        the fake token database of this test class.

        :param pairing_url: the pairing url received from the server
        :param pin: the pin of the token (default: '1234')

        :returns: user_token_id of newly created token
        """

        # extract metadata and the public key

        data_encoded = pairing_url[len('lseqr://pair/'):]
        data = decode_base64_urlsafe(data_encoded)
        version, token_type, flags = struct.unpack('<bbI', data[0:6])
        partition = struct.unpack('<I', data[6:10])[0]

        server_public_key = data[10:10 + 32]

        # validate protocol versions and type id

        self.assertEqual(token_type, TYPE_PUSHTOKEN)
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
            raise NotImplementedError('Callback URL is mandatory for PushToken')

        # ------------------------------------------------------------------- --

        # save token data for later use

        user_token_id = len(self.tokens)
        self.tokens[user_token_id] = {'serial': token_serial,
                                      'server_public_key': server_public_key,
                                      'partition': partition,
                                      'callback_url': callback_url,
                                      'pin': pin}

        # ------------------------------------------------------------------- --

        return user_token_id


# --------------------------------------------------------------------------- --

    def decrypt_and_verify_challenge(self, challenge_url):

        """
        Decrypts the data packed in the challenge url, verifies
        its content, returns the parsed data as a dictionary,
        calculates and returns the signature.

        The calling method must then send the signature
        back to the server. (The reason for this control flow
        is that the challenge data must be checked in different
        scenarios, e.g. when we have a pairing the data must be
        checked by the method that simulates the pairing)

        :param challenge_url: the challenge url as sent by the server

        :returns: (challenge, signature)

            challenge has the keys

                * content_type - one of the three values CONTENT_TYPE_SIGNREQ,
                    CONTENT_TYPE_PAIRING or CONTENT_TYPE_LOGIN)
                    (all defined in this module)
                * transaction_id - used to identify the challenge
                    on the server
                * callback_url (optional) - the url to which the challenge
                    response should be set
                * user_token_id - used to identify the token in the
                    user database for which this challenge was created

            depending on the content type additional keys are present

                * for CONTENT_TYPE_PAIRING: serial
                * for CONTENT_TYPE_SIGNREQ: message
                * for CONTENT_TYPE_LOGIN: login, host

            signature is the generated user signature used to
            respond to the challenge
        """

        challenge_data_encoded = challenge_url[len('lseqr://chal/'):]
        challenge_data = decode_base64_urlsafe(challenge_data_encoded)

        # ------------------------------------------------------------------- --

        # parse and verify header information in the
        # encrypted challenge data

        header = challenge_data[0:5]
        version, user_token_id = struct.unpack('<bI', header)
        self.assertEqual(version, CHALLENGE_URL_VERSION)

        # ------------------------------------------------------------------- --

        # get token from client token database

        token = self.tokens[user_token_id]
        server_public_key = token['server_public_key']

        # ------------------------------------------------------------------- --

        # prepare decryption by seperating R from
        # ciphertext and server signature

        R = challenge_data[5:5 + 32]
        ciphertext = challenge_data[5 + 32:-64]
        server_signature = challenge_data[-64:]

        # check signature

        data = challenge_data[0:-64]
        crypto_sign_verify_detached(server_signature, data, server_public_key)

        # ------------------------------------------------------------------- --

        # key derivation

        secret_key_dh = dsa_to_dh_secret(self.secret_key)
        ss = calc_dh(secret_key_dh, R)
        U = SHA256.new(ss).digest()

        sk = U[0:16]
        nonce = U[16:32]

        # ------------------------------------------------------------------ --

        # decrypt and verify challenge

        nonce_as_int = int_from_bytes(nonce, byteorder='big')
        ctr = Counter.new(128, initial_value=nonce_as_int)
        cipher = AES.new(sk, AES.MODE_CTR, counter=ctr)
        plaintext = cipher.decrypt(ciphertext)

        # ------------------------------------------------------------------ --

        # parse/check plaintext header

        # 1 - for content type
        # 8 - for transaction id
        # 8 - for time stamp
        offset = 1 + 8 + 8

        pt_header = plaintext[0:offset]
        (content_type,
         transaction_id,
         _time_stamp) = struct.unpack('<bQQ', pt_header)

        transaction_id = u64_to_transaction_id(transaction_id)

        # ------------------------------------------------------------------ --

        # prepare the parsed challenge data

        challenge = {}
        challenge['content_type'] = content_type

        # ------------------------------------------------------------------ --

        # retrieve plaintext data depending on content_type

        if content_type == CONTENT_TYPE_PAIRING:

            serial, callback_url, __ = plaintext[offset:].split('\x00')
            challenge['serial'] = serial

        elif content_type == CONTENT_TYPE_SIGNREQ:

            message, callback_url, __ = plaintext[offset:].split('\x00')
            challenge['message'] = message

        elif content_type == CONTENT_TYPE_LOGIN:

            login, host, callback_url, __ = plaintext[offset:].split('\x00')
            challenge['login'] = login
            challenge['host'] = host

        # ------------------------------------------------------------------- --

        # prepare the parsed challenge data

        challenge['callback_url'] = callback_url
        challenge['transaction_id'] = transaction_id
        challenge['user_token_id'] = user_token_id

        # calculate signature

        sig_base = server_signature + plaintext
        sig = crypto_sign_detached(sig_base, self.secret_key)
        encoded_sig = encode_base64_urlsafe(sig)

        return challenge, encoded_sig

# --------------------------------------------------------------------------- --

    def test_correct_pairing(self):
        """ PushToken: Check if pairing works correctly """
        self.execute_correct_pairing()

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

        # ------------------------------------------------------------------- --

        # assemble header and plaintext

        header = struct.pack('<bI', PAIR_RESPONSE_VERSION, partition)

        pairing_response = b''
        pairing_response += struct.pack('<bI', TYPE_PUSHTOKEN, user_token_id)

        pairing_response += self.public_key

        pairing_response += token_serial.encode('utf8') + b'\x00\x00'
        pairing_response += self.gda + b'\x00'

        signature = crypto_sign_detached(pairing_response, self.secret_key)
        pairing_response += signature

        # ------------------------------------------------------------------- --

        # create public diffie hellman component
        # (used to decrypt and verify the reponse)

        r = os.urandom(32)
        R = calc_dh_base(r)

        # ------------------------------------------------------------------- --

        # derive encryption key and nonce

        server_public_key_dh = dsa_to_dh_public(server_public_key)
        ss = calc_dh(r, server_public_key_dh)
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

    def send_pairing_response(self, pairing_response):

        """ sends a pairing response to /validate/pair """

        params = {'pairing_response': pairing_response}

        # we use the standard calback url in here
        # in a real client we would use the callback
        # defined in the pairing url (and saved in
        # the 'token database' of the user)

        response = self.make_validate_request('pair', params)
        response_dict = json.loads(response.body)

        return response_dict

# --------------------------------------------------------------------------- --

    def trigger_challenge(self, user_token_id, content_type=None, data=None):

        serial = self.tokens[user_token_id]['serial']
        pin = self.tokens[user_token_id]['pin']

        params = {'serial': serial,
                  'pass': pin}

        if content_type is not None:
            params['content_type'] = content_type

        if data is not None:
            params['data'] = data

        # ------------------------------------------------------------------- --

        # we mock the interface of the push provider (namely the method
        # push_notification) to get the generated challenge_url passed
        # to it (which would normaly be sent over the PNP)

        with mock.patch.object(default_provider.DefaultPushProvider,
                               'push_notification',
                               autospec=True) as mock_push_notification:

            mock_push_notification.return_value = (True, None)
            response = self.make_validate_request('check_s', params)
            challenge_url = mock_push_notification.call_args[0][1]

            response_dict = json.loads(response.body)
            self.assertIn('result', response_dict)

            result = response_dict.get('result')
            self.assertIn('status', result)
            self.assertIn('value', result)

            status = result.get('status')
            value = result.get('value')

            self.assertTrue(status)
            self.assertFalse(value)

        # ------------------------------------------------------------------- --

        return challenge_url

# --------------------------------------------------------------------------- --

    def test_signreq(self):

        """ PushToken: Check if signing transactions works correctly """

        user_token_id = self.execute_correct_pairing()
        challenge_url = self.trigger_challenge(user_token_id, data='Yes, I '
            'want to know why doctors hate this guy. Take these 6000 $ with '
            'all my sincere benevolence and send me the black magic diet pill '
            'they don\'t want me to know about',
            content_type=CONTENT_TYPE_SIGNREQ)

        challenge, sig = self.decrypt_and_verify_challenge(challenge_url)

        # ------------------------------------------------------------------- --

        # check if the content type is right

        content_type = challenge['content_type']
        self.assertEqual(content_type, CONTENT_TYPE_SIGNREQ)

        # ------------------------------------------------------------------- --

        # prepare params for validate

        params = {'transactionid': challenge['transaction_id'],
                  'pass': sig}

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

    def test_failed_signreq(self):

        """ PushToken: Check if signing transactions fails correctly """

        user_token_id = self.execute_correct_pairing()
        challenge_url = self.trigger_challenge(user_token_id, data='Yes, I '
            'want to know why doctors hate this guy. Take these 6000 $ with '
            'all my sincere benevolence and send me the black magic diet pill '
            'they don\'t want me to know about',
            content_type=CONTENT_TYPE_SIGNREQ)

        challenge, __ = self.decrypt_and_verify_challenge(challenge_url)
        wrong_sig = encode_base64_urlsafe('DEADBEEF' * 32)

        # ------------------------------------------------------------------- --

        # check if the content type is right

        content_type = challenge['content_type']
        self.assertEqual(content_type, CONTENT_TYPE_SIGNREQ)

        # ------------------------------------------------------------------- --

        # prepare params for validate

        params = {'transactionid': challenge['transaction_id'],
                  'pass': wrong_sig}

        # again, we ignore the callback definitions

        response = self.make_validate_request('check_t', params)
        response_dict = json.loads(response.body)

        self.assertIn('status', response_dict.get('result', {}))
        status = response_dict.get('result', {}).get('status')
        value = response_dict.get('result', {}).get('value')
        self.assertTrue(status)

        value = response_dict.get('result', {}).get('value')

        self.assertIn('value', value)
        self.assertIn('failcount', value)
        value_value = value.get('value')
        failcount = value.get('failcount')
        self.assertFalse(value_value)
        self.assertGreater(failcount, 0)


# --------------------------------------------------------------------------- --

    def test_repairing(self):

        """ PushToken: Check if repairing works correctly """

        user_token_id = self.execute_correct_pairing()

        # temporarily switch the gda

        tmp_gda = self.gda
        self.gda = '7777'

        # ------------------------------------------------------------------- --

        # send repairing pairing response

        pairing_response = self.create_pairing_response_by_serial(user_token_id)

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

        # reset the gda

        self.gda = tmp_gda

# --------------------------------------------------------------------------- --

    def test_repairing_fail_sig(self):

        """ PushToken: Check if repairing fails correctly (wrong sig) """

        user_token_id = self.execute_correct_pairing()

        # temporarily switch the secret key (used for signature)

        tmp_secret_key = self.secret_key
        self.secret_key = '7' * 32

        # ------------------------------------------------------------------- --

        # send repairing pairing response

        pairing_response = self.create_pairing_response_by_serial(user_token_id)

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
        self.assertFalse(status)

        # ------------------------------------------------------------------- --

        # reset the secret key

        self.secret_key = tmp_secret_key

# --------------------------------------------------------------------------- --

    def test_repairing_fail_pubkey(self):

        """ PushToken: Check if repairing fails correctly (wrong pubkey) """

        user_token_id = self.execute_correct_pairing()

        # temporarily switch the keypair (used for signature)

        tmp_secret_key = self.secret_key
        tmp_public_key = self.public_key

        pk, sk = gen_dsa_keypair()
        self.secret_key = sk
        self.public_key = pk

        # ------------------------------------------------------------------- --

        # send repairing pairing response

        pairing_response = self.create_pairing_response_by_serial(user_token_id)

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
        self.assertFalse(status)

        # ------------------------------------------------------------------- --

        # reset the secret key

        self.secret_key = tmp_secret_key
        self.public_key = tmp_public_key

# --------------------------------------------------------------------------- --

    def test_login(self):

        """ PushToken: Check if signing logins works correctly """

        user_token_id = self.execute_correct_pairing()
        challenge_url = self.trigger_challenge(user_token_id, data='root@foo',
                                               content_type=CONTENT_TYPE_LOGIN)

        challenge, sig = self.decrypt_and_verify_challenge(challenge_url)

        # ------------------------------------------------------------------- --

        # check if the content type is right

        content_type = challenge['content_type']
        self.assertEqual(content_type, CONTENT_TYPE_LOGIN)

        # ------------------------------------------------------------------- --

        # prepare params for validate

        params = {'transactionid': challenge['transaction_id'],
                  'pass': sig}

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

    def test_unsupported_content_type(self):

        """ PushToken: Check for unsupported content types """

        user_token_id = self.execute_correct_pairing()

        serial = self.tokens[user_token_id]['serial']
        pin = self.tokens[user_token_id]['pin']

        params = {'serial': serial,
                  'pass': pin,
                  'data': 'wohoooo',
                  'content_type': 99999999999}

        response = self.make_validate_request('check_s', params)
        response_dict = json.loads(response.body)
        self.assertIn('result', response_dict)

        result = response_dict.get('result')
        self.assertIn('status', result)
        self.assertIn('value', result)

        status = result.get('status')
        value = result.get('value')

        self.assertFalse(status)
        self.assertFalse(value)

# --------------------------------------------------------------------------- --

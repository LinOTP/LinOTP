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

import logging
import struct
import zlib
from os import urandom
from base64 import b64decode, b64encode
from pysodium import crypto_scalarmult_curve25519 as calc_dh
from pysodium import crypto_scalarmult_curve25519_base as calc_dh_base
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from linotp.lib.challenges import Challenges
from linotp.lib.tokenclass import TokenClass
from linotp.lib.tokenclass import StatefulTokenMixin
from linotp.lib.crypt import zerome
from linotp.lib.crypt import extract_tan
from linotp.lib.crypt import encode_base64_urlsafe
from linotp.lib.crypt import decode_base64_urlsafe
from linotp.lib.config import getFromConfig
from linotp.lib.error import ValidateError
from linotp.lib.error import InvalidFunctionParameter
from linotp.lib.crypt import get_qrtan_secret_key
from linotp.lib.crypt import get_qrtan_public_key
from linotp.lib.qrtan import decrypt_pairing_response
from linotp.lib.pairing import generate_pairing_url
from hmac import compare_digest


log = logging.getLogger(__name__)

FLAG_COMP = 0
FLAG_CBURL = 1
FLAG_CBSMS = 2
FLAG_SRVSIG = 3

CHALLENGE_HAS_COMPRESSION = 1
CHALLENGE_HAS_URL = 2
CHALLENGE_HAS_SMS_NUMBER = 4
CHALLENGE_HAS_SIGNATURE = 8

CONTENT_TYPE_FREE = 0
CONTENT_TYPE_PAIRING = 1
CONTENT_TYPE_AUTH = 2

QRTAN_VERSION       = 0

def transaction_id_to_u64(transaction_id):
    """
    converts a transaction_id to u64 format (used in the challenge-url format)
    transaction_ids come in 2 formats:

    - Normal Transaction - 49384
    - Subtransaction - 213123.39

    where the 2 places behind the point start with 01.

    The function converts the strings by "multiplying" it with
    100, so we well get 4938400 and 21312339
    """

    # HACK! remove when transaction id handling is
    # refactored.

    if '.' in transaction_id:
        before, _, after = transaction_id.partition('.')
        encoded = before + after
    else:
        encoded = transaction_id + '00'

    return int(encoded)


class QrTanTokenClass(TokenClass, StatefulTokenMixin):

    """

    """

    def __init__ (self, token_model_object):
        TokenClass.__init__(self, token_model_object)
        self.setType(u'qrtan')
        self.mode = ['challenge']

# ------------------------------------------------------------------------------

    def isActive (self):

        # overwritten, because QrTanTokenClass can receive validate
        # requests in 2 different states: pairing_finished (active
        # flag is 1) and pairing_challenge_sent (active flag is 0)

        is_completely_finished = TokenClass.isActive(self)
        return is_completely_finished or \
               self.current_state == 'pairing_challenge_sent'

# ------------------------------------------------------------------------------

    def is_challenge_request(self, passw, user, options=None):

        """
        check, if the request would start a challenge

        :param passw: password, which might be pin or pin+otp
        :param options: dictionary of additional request parameters

        :return: returns true or false
        """

        if not passw and \
           ('data' in options or 'challenge' in options):
            return True
        else:
            return TokenClass.is_challenge_request(self, passw,
                                                        user, options)

        return False

# ------------------------------------------------------------------------------

# type identifier interface

    @classmethod
    def getClassType(cls):
        return "qrtan"

    @classmethod
    def getClassPrefix(cls):
        return "QRTAN"

# ------------------------------------------------------------------------------

    def splitPinPass(self, passw):

        # we split differently here, because we support pins, but no otp
        # so an incoming request with passw but without transaction_id
        # is a request with a pin

        return (passw, '')

# ------------------------------------------------------------------------------

    @classmethod
    def get_helper_params_pre(cls, params):

        helper_params = {}

        if 'pairing_response' in params:

            # client sent back response to pairing url
            # decrypt it and check its values

            enc_response = params.get('pairing_response')
            response = decrypt_pairing_response(enc_response)

            if not response.serial:
                raise ValidateError('Pairing responses with no serial attached '
                                    'are currently not implemented.')

            helper_params['serial'] = response.serial
            helper_params['user_public_key'] = response.user_public_key
            helper_params['user_token_id'] = response.user_token_id
            helper_params['user'] = response.user_login

        return helper_params

# ------------------------------------------------------------------------------

    def create_challenge_url(self, transaction_id, content_type, message,
                             callback_url, callback_sms_number,
                             use_compression=False):

        """
        creates a challenge url (looking like lseqr://chal/<base64string>)
        from a challenge dictionary as provided by Challanges.create_challenge
        in lib.challenge

        the version identifier of the challenge url is currently hardcoded
        to 0.
        """

        serial = self.getSerial()

        if content_type is None:
            content_type = CONTENT_TYPE_FREE

        # ----------------------------------------------------------------------

        # sanity/format checks

        if content_type not in [CONTENT_TYPE_PAIRING,
            CONTENT_TYPE_AUTH, CONTENT_TYPE_FREE]:
            raise InvalidFunctionParameter('content_type', 'content_type must '
                                           'be CONTENT_TYPE_PAIRING, '
                                           'CONTENT_TYPE_AUTH or '
                                           'CONTENT_TYPE_FREE.')

        if content_type == CONTENT_TYPE_PAIRING and \
           message != serial:
            raise InvalidFunctionParameter('message', 'message must be equal '
                                           'to serial in pairing mode')


        if content_type == CONTENT_TYPE_AUTH:
            if '@' not in message:
                raise InvalidFunctionParameter('message', 'For content type '
                                               'auth, message must have format '
                                               '<login>@<server>')

        # ----------------------------------------------------------------------

        #  after the lseqr://chal/ prefix the following data is encoded
        #  in urlsafe base64:

        #            ---------------------------------------------------
        #  fields   | version | user token id |  R  | ciphertext | MAC |
        #            ---------------------------------------------------
        #           |          header         |     |    EAX enc data  |
        #            ---------------------------------------------------
        #  size     |    1    |       4       |  32 |      ?     | 16  |
        #            ---------------------------------------------------
        #

        r = urandom(32)
        R = calc_dh_base(r)

        user_token_id = self.getFromTokenInfo('user_token_id')
        data_header = struct.pack('<bI', QRTAN_VERSION, user_token_id)

        # the user public key is saved as base64 in
        # the token info since the byte format is
        # incompatible with the json backend.

        b64_user_public_key = self.getFromTokenInfo('user_public_key')
        user_public_key = b64decode(b64_user_public_key)

        ss = calc_dh(r, user_public_key)
        U1 = SHA256.new(ss).digest()
        U2 = SHA256.new(U1).digest()
        zerome(ss)

        skA = U1[0:16]
        skB = U2[0:16]
        nonce = U2[16:32]
        zerome(U1)
        zerome(U2)


        # ----------------------------------------------------------------------

        # create plaintext section

        # ----------------------------------------------------------------------

        # create the bitmap for flags

        flags = 0

        if use_compression:
            flags |= CHALLENGE_HAS_COMPRESSION

        #FIXME: sizecheck for message, callback url, sms number
        #wiki specs are utf-8 byte length (without \0)

        if callback_url is not None:
            flags |= CHALLENGE_HAS_URL

        if callback_sms_number is not None:
            flags |= CHALLENGE_HAS_SMS_NUMBER

        if (content_type == CONTENT_TYPE_PAIRING):
            flags |= CHALLENGE_HAS_SIGNATURE

        #-----------------------------------------------------------------------

        # generate plaintext header

        #            ----------------------------------------------
        #  fields   | content_type  | flags | transaction_id | ... |
        #            ----------------------------------------------
        #  size     |       1       |   1   |        8       |  ?  |
        #            ----------------------------------------------

        transaction_id = transaction_id_to_u64(transaction_id)
        pt_header = struct.pack('<bbQ', content_type, flags, transaction_id)
        plaintext = pt_header

        #-----------------------------------------------------------------------

        # create data package

        #            -------------------------------
        #  fields   | header  | message | NUL | ... |
        #            -------------------------------
        #  size     |   10    |    ?    |  1  |  ?  |
        #            -------------------------------

        data_package = b''
        utf8_message = message.encode('utf8')

        # enforce max sizes specified by protocol

        if content_type == CONTENT_TYPE_FREE and len(utf8_message) > 511:
            raise InvalidFunctionParameter('message', 'max string length '
                                           '(encoded as utf8) is 511 for '
                                           'content type FREE')

        elif content_type == CONTENT_TYPE_PAIRING and len(utf8_message) > 63:
            raise InvalidFunctionParameter('message', 'max string length '
                                           '(encoded as utf8) is 511 for '
                                           'content type PAIRING')

        elif content_type == CONTENT_TYPE_AUTH and len(utf8_message) > 511:
            raise InvalidFunctionParameter('message', 'max string length '
                                           '(encoded as utf8) is 511 for '
                                           'content type AUTH')

        data_package += utf8_message + b'\x00'

        # ----------------------------------------------------------------------

        # depending on function parameters add callback url
        # and/or callback sms number

        #            -----------------------------------------------------
        #  fields   | ... | callback url | NUL | callback sms | NUL | ... |
        #            -----------------------------------------------------
        #  size     |  ?  |       ?      |  1  |       ?      |  1  |  ?  |
        #            -----------------------------------------------------

        # ----------------------------------------------------------------------

        if callback_url is not None:

            utf8_callback_url = callback_url.encode('utf8')

            # enforce max url length as specified in protocol

            if len(utf8_callback_url) > 511:
                raise InvalidFunctionParameter('callback_url', 'max string '
                                               'length (encoded as utf8) is '
                                               '511')

            data_package += utf8_callback_url + b'\x00'

        # ----------------------------------------------------------------------

        if callback_sms_number is not None:

            utf8_callback_sms_number = callback_sms_number.encode('utf8')

            if len(utf8_callback_sms_number) > 31:
                raise InvalidFunctionParameter('callback_sms_number',
                                               'max string length (encoded '
                                               'as utf8) is 31')

            data_package += utf8_callback_sms_number + b'\x00'

        # ----------------------------------------------------------------------

        if use_compression:
            maybe_compressed_data_package = zlib.compress(data_package, 9)
        else:
            maybe_compressed_data_package = data_package

        # ----------------------------------------------------------------------

        # when content type is pairing the protocol specifies that
        # the server must send a hmac based signature with the
        # response

        if flags & CHALLENGE_HAS_SIGNATURE:

            hmac_message = nonce + pt_header + maybe_compressed_data_package

            sig = HMAC.new(self.server_hmac_secret, hmac_message,
                           digestmod=SHA256).digest()

            plaintext += sig

        # ----------------------------------------------------------------------

        plaintext += maybe_compressed_data_package

        # ----------------------------------------------------------------------

        user_message = nonce + pt_header + data_package
        user_sig = HMAC.new(skB, user_message, digestmod=SHA256).digest()

        # the user sig will be given as urlsafe base64 in the
        # challenge response. for this reasons (and because we
        # need to serialize it into json) we convert the user_sig
        # into this format.

        user_sig = encode_base64_urlsafe(user_sig)

        # ----------------------------------------------------------------------



        cipher = AES.new(skA, AES.MODE_EAX, nonce)
        cipher.update(data_header)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        raw_data = data_header + R + ciphertext + tag
        url = 'lseqr://chal/' + encode_base64_urlsafe(raw_data)

        return url, user_sig

# ------------------------------------------------------------------------------

    def update(self, params):

        param_keys = set(params.keys())
        init_rollout_state_keys = set(['type', 'hashlib', 'serial',
                                       'key_size', 'user.login',
                                       'user.realm', 'session'])

        # ----------------------------------------------------------------------

        if param_keys.issubset(init_rollout_state_keys):

            # if param keys are in {'type', 'hashlib'} the token is
            # initialized for the first time. this is e.g. done on the
            # manage web ui. since the token doesn't exist in the database
            # yet, its rollout state must be None (that is: they data for
            # the rollout state doesn't exist yet)

            self.ensure_state(None)

            # ------------------------------------------------------------------

            # collect data used for generating the pairing url

            serial = params.get('serial')
            hash_algorithm = params.get('hashlib')
            pub_key = get_qrtan_public_key()

            # TODO: these values should be fetched from
            # policies or config

            cb_url = '/admin/init'
            cb_sms_number = None
            otp_pin_length = None

            # ------------------------------------------------------------------

            pairing_url = generate_pairing_url('qrtan',
                                          server_public_key=pub_key,
                                          serial=serial,
                                          callback_url=cb_url,
                                          callback_sms_number=cb_sms_number,
                                          otp_pin_length=otp_pin_length,
                                          hash_algorithm=hash_algorithm)

            # ------------------------------------------------------------------

            self.addToInfo('pairing_url', pairing_url)

            # we set the the active state of the token to False, because
            # it should not be allowed to use it for validation before the
            # pairing process is done

            self.token.LinOtpIsactive = False

            # ------------------------------------------------------------------

            self.change_state('pairing_url_sent')

        # ----------------------------------------------------------------------

        elif 'pairing_response' in params:

            # if a pairing response is in the parameters, we guess,
            # that the request refers to a token in the state
            # 'pairing_url_sent'

            self.ensure_state('pairing_url_sent')

            # ------------------------------------------------------------------

            # adding the user's public key to the token info
            # as well as the user_token_id, which is used to
            # identify the token on the user's side

            self.addToTokenInfo('user_token_id', params['user_token_id'])

            # user public key arrives in the bytes format.
            # we must convert to a string in order to be
            # able to dump it as json in the db

            b64_user_public_key = b64encode(params['user_public_key'])
            self.addToTokenInfo('user_public_key', b64_user_public_key)

            # ------------------------------------------------------------------

            # create challenge through the challenge factory

            # add the content type and the challenge data to the params
            # (needed in the createChallenge method)

            params['content_type'] = CONTENT_TYPE_PAIRING
            params['data'] = self.getSerial()

            self.change_state('pairing_response_received')

            success, challenge_dict = Challenges.create_challenge(self, params)

            if not success:
                raise Exception('Unable to create challenge from '
                                'pairing response %s' %
                                params['pairing_response'])

            challenge_url = challenge_dict['message']

            # ------------------------------------------------------------------

            self.addToInfo('pairing_challenge_url', challenge_url)

            # ------------------------------------------------------------------

            self.change_state('pairing_challenge_sent')


# ------------------------------------------------------------------------------

    def getInitDetail(self, params, user=None):

        response_detail = {}

        param_keys = set(params.keys())
        init_rollout_state_keys = set(['type', 'hashlib', 'serial',
                                       'key_size', 'user.login',
                                       'user.realm', 'session'])

        # ----------------------------------------------------------------------

        if param_keys.issubset(init_rollout_state_keys):

            # if we are at the first rollout step, the update method has
            # generated a pairing_url and saved it in the token info

            info = self.getInfo()
            pairing_url = info.get('pairing_url')
            response_detail['pairing_url'] = pairing_url

        # ----------------------------------------------------------------------

        elif 'pairing_response' in params:

            # if we are in the second step we expect the update method
            # to have generated a challenge_url, that can be used by
            # the client to complete the pairing

            info = self.getInfo()
            challenge_url = info.get('pairing_challenge_url')
            response_detail['challenge_url'] = challenge_url

        # ----------------------------------------------------------------------

        return response_detail

# ------------------------------------------------------------------------------

    def checkOtp(self, passwd, counter, window, options=None):

        valid_states = ['pairing_challenge_sent',
                        'pairing_complete']

        self.ensure_state_is_in(valid_states)

        # ----------------------------------------------------------------------

        filtered_challenges = []
        serial = self.getSerial()

        if options is None:
            options = {}

        max_fail = int(getFromConfig('QrTanMaxChallengeRequests', '3'))

        # ----------------------------------------------------------------------

        # TODO: from which point is checkOtp called, when there
        # is no challenge response in the request?

        if 'transactionid' in options:

            # ------------------------------------------------------------------

            # fetch all challenges that match the transaction id or serial

            transaction_id = options.get('transaction_id')

            challenges = Challenges.lookup_challenges(serial, transaction_id)

            # ------------------------------------------------------------------

            # filter into filtered_challenges

            for challenge in challenges:

                (received_tan, tan_is_valid) = challenge.getTanStatus()
                fail_counter = challenge.getTanCount()

                # if we iterate over matching challenges (that is: challenges
                # with the correct transaction id) we either find a fresh
                # challenge, that didn't receive a TAN at all (first case)
                # or a challenge, that already received a number of wrong
                # TANs but still has tries left (second case).

                if not received_tan:
                    filtered_challenges.append(challenge)
                elif not tan_is_valid and fail_counter <= max_fail:
                    filtered_challenges.append(challenge)

            # ------------------------------------------------------------------

        if not filtered_challenges:
            return -1

        for challenge in filtered_challenges:

            data = challenge.getData()
            correct_passwd = data['user_sig']

            # compare values with python's native constant
            # time comparison

            if compare_digest(correct_passwd, passwd):

                if self.current_state == 'pairing_challenge_sent':
                    self.change_state('pairing_complete')
                    self.enable(True)

                return 1

            else:

                # maybe we got a tan instead of a signature

                correct_passwd_as_bytes = decode_base64_urlsafe(correct_passwd)
                tan_length = 8 # TODO fetch from policy
                correct_tan = extract_tan(correct_passwd_as_bytes, tan_length)

                # TODO PYLONS-HACK pylons silently converts integers in
                # incoming json to unicode. since extract_tan returns
                # an integer, we have to convert it here
                correct_tan = unicode(correct_tan)

                if compare_digest(correct_tan, passwd):
                    return 1

        return -1 # TODO: ??? semantics of this ret val?


# ------------------------------------------------------------------------------

    def createChallenge(self, transaction_id, options):

        """
        """

        valid_states = ['pairing_response_received', 'pairing_complete']
        self.ensure_state_is_in(valid_states)

        content_type = options.get('content_type')
        message = options.get('data')

        # ----------------------------------------------------------------------

        # TODO: get from policy

        callback_url = None
        callback_sms_number = None
        compression = False

        # ----------------------------------------------------------------------

        challenge_url, user_sig = self.create_challenge_url(transaction_id,
                                                            content_type,
                                                            message,
                                                            callback_url,
                                                            callback_sms_number,
                                                            compression)

        data = {'message': message, 'user_sig': user_sig}

        return (True, challenge_url, data, {})

    @property
    def server_hmac_secret(self):

        """ the server hmac secret for this specific token """

        server_secret_key = get_qrtan_secret_key()

        # user public key is saved base64 encoded

        b64_user_public_key = self.getFromTokenInfo('user_public_key')
        user_public_key = b64decode(b64_user_public_key)

        hmac_secret = calc_dh(server_secret_key, user_public_key)
        zerome(server_secret_key)

        return hmac_secret

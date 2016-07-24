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
from base64 import b64decode
from pysodium import crypto_scalarmult_curve25519 as calc_dh
from pysodium import crypto_scalarmult_curve25519_base as calc_dh_base
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC
from Cryptodome.Hash import SHA256
from linotp.lib.policy import getPolicy
from linotp.lib.policy import getPolicyActionValue
from linotp.lib.policy import get_pairing_certificate_id
from linotp.lib.challenges import Challenges
from linotp.lib.reply import create_img
from linotp.lib.tokenclass import TokenClass
from linotp.lib.tokenclass import StatefulTokenMixin
from linotp.lib.token import get_token_owner

from linotp.lib.crypt import zerome
from linotp.lib.crypt import extract_tan
from linotp.lib.crypt import encode_base64_urlsafe
from linotp.lib.crypt import decode_base64_urlsafe
from linotp.lib.config import getFromConfig
from linotp.lib.error import InvalidFunctionParameter
from linotp.lib.error import ParameterError
from linotp.lib.crypt import get_qrtoken_dh_secret_key
from linotp.lib.crypt import get_qrtoken_public_key
from linotp.lib.pairing import generate_pairing_url
from hmac import compare_digest

from linotp.lib.context import request_context as context


log = logging.getLogger(__name__)

FLAG_COMP = 0
FLAG_CBURL = 1
FLAG_CBSMS = 2
FLAG_SRVSIG = 3

CHALLENGE_HAS_COMPRESSION = 1
CHALLENGE_HAS_URL = 2
CHALLENGE_HAS_SMS_NUMBER = 4
CHALLENGE_HAS_SIGNATURE = 8
CHALLENGE_SHOULD_RESET_URL = 16

CONTENT_TYPE_FREE = 0
CONTENT_TYPE_PAIRING = 1
CONTENT_TYPE_AUTH = 2

QRTOKEN_VERSION = 1


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


def get_single_auth_policy(policy_name, user=None, realms=None):
    """
    Retrieves a policy value and checks if the value is consistent
    across realms.

    :param policy_name: the name of the policy, e.g:
        * qrtoken_pairing_callback_url
        * qrtoken_pairing_callback_sms
        * qrtoken_challenge_response_url
        * qrtoken_challenge_response_sms

    :param realms: the realms that his policy should be effective in
    """

    action_values = []
    login = None
    ret = None

    if user and user.login and user.realm:
        realms = [user.realm]
        login = user.login

    if realms is None or len(realms) == 0:
        realms = ['/:no realm:/']

    params = {"scope": "authentication",
              'action': policy_name}

    for realm in realms:
        params['realm'] = realm
        if login:
            params['user'] = login

        policy = getPolicy(params)
        action_value = getPolicyActionValue(policy, policy_name,
                                            is_string=True)
        if action_value:
            action_values.append(action_value)

    if len(action_values) > 1:
        for value in action_values:
            if value != action_values[0]:
                raise Exception('conflicting policy values %r found for '
                                'realm set: %r' % (action_values, realms))
    if action_values:
        ret = action_values[0]

    return ret


class QrTokenClass(TokenClass, StatefulTokenMixin):

    """

    """

    def __init__(self, token_model_object):
        TokenClass.__init__(self, token_model_object)
        self.setType(u'qr')
        self.mode = ['challenge']
        self.supports_offline_mode = True

# ------------------------------------------------------------------------------

    def isActive(self):

        # overwritten, because QrTokenClass can receive validate
        # requests in 2 different states: pairing_finished (active
        # flag is 1) and pairing_challenge_sent (active flag is 0)

        is_completely_finished = TokenClass.isActive(self)
        return is_completely_finished or \
            self.current_state == 'pairing_response_received' or \
            self.current_state == 'pairing_challenge_sent'

# ------------------------------------------------------------------------------

# type identifier interface

    @classmethod
    def getClassType(cls):
        return "qr"

    @classmethod
    def getClassPrefix(cls):
        # OATH standard compliant prefix: XXYY XX= vendor, YY - token type
        return "LSQR"

# ------------------------------------------------------------------------------

    # info interface definition

    @classmethod
    def getClassInfo(cls, key=None, ret='all'):

        _ = context['translate']

        info = {'type': 'qr', 'title': _('QRToken')}

        info['description'] = 'Challenge-Response-Token - Curve 25519 based'

        # ----------------------------------------------------------------------

        info['policy'] = {}

        auth_policies = {}

        for policy_name in ['qrtoken_pairing_callback_url',
                            'qrtoken_pairing_callback_sms',
                            'qrtoken_challenge_callback_url',
                            'qrtoken_challenge_callback_sms']:

            auth_policies[policy_name] = {'type': 'str'}

        info['policy']['authentication'] = auth_policies

        info['policy']['selfservice'] = {'activate_QRToken':
                                         {'type': 'bool',
                                          'description': _('activate your '
                                                           'QRToken')}
                                         }

        # ----------------------------------------------------------------------

        # wire the templates

        init_dict = {}
        init_dict['title'] = {'html': 'qrtoken.mako', 'scope': 'enroll.title'}
        init_dict['page'] = {'html': 'qrtoken.mako', 'scope': 'enroll'}
        info['init'] = init_dict

        config_dict = {}
        config_dict['title'] = {
            'html': 'qrtoken.mako', 'scope': 'config.title'}
        config_dict['page'] = {'html': 'qrtoken.mako', 'scope': 'config'}
        info['config'] = config_dict

        ss_enroll = {}
        ss_enroll['title'] = {'html': 'qrtoken.mako',
                              'scope': 'selfservice.title.enroll'}
        ss_enroll['page'] = {'html': 'qrtoken.mako',
                             'scope': 'selfservice.enroll'}

        ss_activate = {}
        ss_activate['title'] = {'html': 'qrtoken.mako',
                                'scope': 'selfservice.title.activate'}
        ss_activate['page'] = {'html': 'qrtoken.mako',
                               'scope': 'selfservice.activate'}

        selfservice_dict = {}
        selfservice_dict['enroll'] = ss_enroll
        selfservice_dict['activate_QRToken'] = ss_activate

        info['selfservice'] = selfservice_dict

        # ----------------------------------------------------------------------

        if key is not None:
            return info.get(key)

        return info

# ------------------------------------------------------------------------------

    def splitPinPass(self, passw):

        # we split differently here, because we support pins, but no otp
        # so an incoming request with passw but without transaction_id
        # is a request with a pin

        return (passw, '')

# ------------------------------------------------------------------------------

    def create_challenge_url(self, transaction_id, content_type, message,
                             callback_url, callback_sms_number,
                             use_compression=False, reset_url=False):
        """
        creates a challenge url (looking like lseqr://chal/<base64string>)
        from a challenge dictionary as provided by Challanges.create_challenge
        in lib.challenge

        the version identifier of the challenge url is currently hardcoded
        to 1.
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
        data_header = struct.pack('<bI', QRTOKEN_VERSION, user_token_id)

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

        # FIXME: sizecheck for message, callback url, sms number
        # wiki specs are utf-8 byte length (without \0)

        if callback_url is not None:
            flags |= CHALLENGE_HAS_URL

        if callback_sms_number is not None:
            flags |= CHALLENGE_HAS_SMS_NUMBER

        if (content_type == CONTENT_TYPE_PAIRING):
            flags |= CHALLENGE_HAS_SIGNATURE

        if reset_url:
            flags |= CHALLENGE_SHOULD_RESET_URL
            flags |= CHALLENGE_HAS_SIGNATURE

        #----------------------------------------------------------------------

        # generate plaintext header

        #            ----------------------------------------------
        #  fields   | content_type  | flags | transaction_id | ... |
        #            ----------------------------------------------
        #  size     |       1       |   1   |        8       |  ?  |
        #            ----------------------------------------------

        transaction_id = transaction_id_to_u64(transaction_id)
        pt_header = struct.pack('<bbQ', content_type, flags, transaction_id)
        plaintext = pt_header

        #----------------------------------------------------------------------

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
            raise ParameterError('message (encoded as utf8) can only be 511 '
                                 'characters long')

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

        sig = ''

        if flags & CHALLENGE_HAS_SIGNATURE:

            hmac_message = nonce + pt_header + maybe_compressed_data_package

            sig = HMAC.new(self.server_hmac_secret, hmac_message,
                           digestmod=SHA256).digest()

            plaintext += sig

        # ----------------------------------------------------------------------

        plaintext += maybe_compressed_data_package

        # ----------------------------------------------------------------------

        user_message = nonce + pt_header + sig + data_package
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
        init_rollout_state_keys = {'type', 'hashlib', 'serial', '::scope::',
                                   'key_size', 'user.login', 'description',
                                   'user.realm', 'session', 'otplen', 'resConf',
                                   'user', 'realm', 'qr', 'pin'}

        # ----------------------------------------------------------------------

        if not param_keys.issubset(init_rollout_state_keys):

            # make sure the call aborts, if request
            # type wasn't recognized

            raise Exception('Unknown request type for token type qr')

        # if param keys are in {'type', 'hashlib'} the token is
        # initialized for the first time. this is e.g. done on the
        # manage web ui. since the token doesn't exist in the database
        # yet, its rollout state must be None (that is: they data for
        # the rollout state doesn't exist yet)

        self.ensure_state(None)

        # ------------------------------------------------------------------

        # we check if callback policies are set. this must be done here
        # because the token gets saved directly after the update method
        # in the TokenHandler

        _ = context['translate']

        owner = get_token_owner(self)
        if owner and owner.login and owner.realm:
            realms = [owner.realm]
        else:
            realms = self.getRealms()

        pairing_policies = ['qrtoken_pairing_callback_url',
                            'qrtoken_pairing_callback_sms']

        cb_url = get_single_auth_policy(pairing_policies[0],
                                        user=owner, realms=realms)
        cb_sms = get_single_auth_policy(pairing_policies[1],
                                        user=owner, realms=realms)


        if not cb_url and not cb_sms:
            raise Exception(_('Policy %s must have a value') %
                            _(" or ").join(pairing_policies))

        challenge_policies = ['qrtoken_challenge_callback_url',
                              'qrtoken_challenge_callback_sms']

        cb_url = get_single_auth_policy(challenge_policies[0],
                                        user=owner, realms=realms)
        cb_sms = get_single_auth_policy(challenge_policies[1],
                                        user=owner, realms=realms)

        if not cb_url and not cb_sms:
            raise Exception(_('Policy %s must have a value') %
                            _(" or ").join(pairing_policies))

        # ------------------------------------------------------------------

        # we set the the active state of the token to False, because
        # it should not be allowed to use it for validation before the
        # pairing process is done

        self.token.LinOtpIsactive = False

        # ------------------------------------------------------------------

        if 'otplen' not in params:
            params['otplen'] = getFromConfig("QRTokenOtpLen", 8)

        # -------------------------------------------------------------- --

        TokenClass.update(self, params, reset_failcount=True)

# ------------------------------------------------------------------------------

    def getInitDetail(self, params, user=None):

        _ = context['translate']
        response_detail = {}

        param_keys = set(params.keys())
        init_rollout_state_keys = {'type', 'hashlib', 'serial', '::scope::',
                                   'key_size', 'user.login', 'description',
                                   'user.realm', 'session', 'otplen', 'pin',
                                   'resConf', 'user', 'realm', 'qr'}

        # ----------------------------------------------------------------------

        if param_keys.issubset(init_rollout_state_keys):

            # collect data used for generating the pairing url

            serial = self.getSerial()
            # for qrtoken hashlib is ignored
            hash_algorithm = None
            pub_key = get_qrtoken_public_key()
            otp_pin_length = int(self.getOtpLen())

            owner = get_token_owner(self)
            if owner and owner.login and owner.realm:
                realms = [owner.realm]
                user = owner
            else:
                realms = self.getRealms()

            pairing_policies = ['qrtoken_pairing_callback_url',
                                'qrtoken_pairing_callback_sms']

            # it is guaranteed, that either cb_url or cb_sms has a value
            # because we checked it in the update method

            cb_url = get_single_auth_policy(pairing_policies[0],
                                            user=owner, realms=realms)
            cb_sms = get_single_auth_policy(pairing_policies[1],
                                            user=owner, realms=realms)

            cert_id = get_pairing_certificate_id(realms=realms, user=user)

            # ------------------------------------------------------------------

            pairing_url = generate_pairing_url('qrtoken',
                                               server_public_key=pub_key,
                                               serial=serial,
                                               callback_url=cb_url,
                                               callback_sms_number=cb_sms,
                                               otp_pin_length=otp_pin_length,
                                               hash_algorithm=hash_algorithm,
                                               cert_id=cert_id)

            # ------------------------------------------------------------------

            self.addToInfo('pairing_url', pairing_url)
            response_detail['pairing_url'] = pairing_url

            # create response tabs
            response_detail['lse_qr_url'] = {
                'description': _('QRToken Pairing Url'),
                'img': create_img(pairing_url, width=250),
                'order': 0,
                'value': pairing_url}
            response_detail['lse_qr_cert'] = {
                'description': _('QRToken Certificate'),
                'img': create_img(pairing_url, width=250),
                'order': 1,
                'value': pairing_url}

            response_detail['serial'] = self.getSerial()

        # ------------------------------------------------------------------ --

        else:

            # make sure the call aborts, if request
            # type wasn't recognized

            raise Exception('Unknown request type for token type qr')

        # ----------------------------------------------------------------------

        self.change_state('pairing_url_sent')

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

        max_fail = int(getFromConfig('QRMaxChallenges', '3'))

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

                return 1

            else:

                # maybe we got a tan instead of a signature

                correct_passwd_as_bytes = decode_base64_urlsafe(correct_passwd)
                tan_length = 8  # TODO fetch from policy
                correct_tan = extract_tan(correct_passwd_as_bytes, tan_length)

                # TODO PYLONS-HACK pylons silently converts integers in
                # incoming json to unicode. since extract_tan returns
                # an integer, we have to convert it here
                correct_tan = unicode(correct_tan)

                if compare_digest(correct_tan, passwd):
                    return 1

        return -1  # TODO: ??? semantics of this ret val?

# ------------------------------------------------------------------------------

    def statusValidationSuccess(self):

        if self.current_state == 'pairing_challenge_sent':
            self.change_state('pairing_complete')
            self.enable(True)

# ------------------------------------------------------------------------------

    def createChallenge(self, transaction_id, options):
        """
        """
        _ = context['translate']

        valid_states = ['pairing_response_received', 'pairing_complete']
        self.ensure_state_is_in(valid_states)

        if self.current_state == 'pairing_response_received':
            content_type = CONTENT_TYPE_PAIRING
            reset_url = True
        else:
            content_type = options.get('content_type')
            reset_url = False

        message = options.get('data')

        # ----------------------------------------------------------------------

        owner = get_token_owner(self)
        if owner and owner.login and owner.realm:
            realms = [owner.realm]
        else:
            realms = self.getRealms()

        callback_policies = ['qrtoken_challenge_callback_url',
                             'qrtoken_challenge_callback_sms']
        callback_url = get_single_auth_policy(callback_policies[0],
                                              user=owner, realms=realms)
        callback_sms = get_single_auth_policy(callback_policies[1],
                                              user=owner, realms=realms)

        if not callback_url and not callback_sms:
            raise Exception(_('Policy %s must have a value') %
                            _(" or ").join(callback_policies))

        # TODO: get from policy/config
        compression = False

        # ----------------------------------------------------------------------

        challenge_url, user_sig = self.create_challenge_url(transaction_id,
                                                            content_type,
                                                            message,
                                                            callback_url,
                                                            callback_sms,
                                                            compression,
                                                            reset_url)

        data = {'message': message, 'user_sig': user_sig}

        if self.current_state == 'pairing_response_received':
            self.change_state('pairing_challenge_sent')

        return (True, challenge_url, data, {})

    # --------------------------------------------------------------------------

    def getQRImageData(self, response_detail):

        url = None
        hparam = {}

        if response_detail is not None:
            if 'pairing_url' in response_detail:
                url = response_detail.get('pairing_url')
                hparam['alt'] = url

        return url, hparam

    # --------------------------------------------------------------------------

    def getOfflineInfo(self):

        public_key = self.getFromTokenInfo('user_public_key')
        user_token_id = self.getFromTokenInfo('user_token_id')

        return {'public_key': public_key,
                'user_token_id': user_token_id}

    # --------------------------------------------------------------------------

    @property
    def server_hmac_secret(self):
        """ the server hmac secret for this specific token """

        server_secret_key = get_qrtoken_dh_secret_key()

        # user public key is saved base64 encoded

        b64_user_public_key = self.getFromTokenInfo('user_public_key')
        user_public_key = b64decode(b64_user_public_key)

        hmac_secret = calc_dh(server_secret_key, user_public_key)
        zerome(server_secret_key)

        return hmac_secret

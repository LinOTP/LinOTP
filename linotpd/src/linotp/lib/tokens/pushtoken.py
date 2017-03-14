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
import time

from os import urandom
from linotp.lib.tokenclass import TokenClass
from linotp.lib.tokenclass import StatefulTokenMixin
from linotp.lib.challenges import transaction_id_to_u64
from linotp.lib.challenges import Challenges
from linotp.lib.error import InvalidFunctionParameter
from linotp.lib.policy import get_partition
from linotp.lib.crypto import zerome
from linotp.lib.crypto import get_secret_key
from linotp.lib.crypto import encode_base64_urlsafe
from linotp.lib.crypto import decode_base64_urlsafe
from linotp.lib.crypto import dsa_to_dh_public
from linotp.lib.util import int_from_bytes
from linotp.lib.token import get_token_owner
from linotp.lib.context import request_context as context
from linotp.lib.reply import create_img
from linotp.lib.pairing import generate_pairing_url
from linotp.lib.config import getFromConfig
from linotp.lib.policy import get_single_auth_policy
from linotp.provider import loadProviderFromPolicy
from pysodium import crypto_scalarmult_curve25519 as calc_dh
from pysodium import crypto_scalarmult_curve25519_base as calc_dh_base
from pysodium import crypto_sign_detached
from pysodium import crypto_sign_verify_detached as verify_sig
from base64 import b64encode
from base64 import b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Util import Counter

import logging

log = logging.getLogger(__name__)

CHALLENGE_URL_VERSION = 1

CONTENT_TYPE_SIGNREQ = 0
CONTENT_TYPE_PAIRING = 1
CONTENT_TYPE_LOGIN = 2


class PushTokenClass(TokenClass, StatefulTokenMixin):

    """

    """

# --------------------------------------------------------------------------- --

#   Overview of the different token states:
#
#   .------.                 .-------------.                       .----------.
#   | None | ---- update --> | initialized | --- getInitDetail --> | unpaired |
#   '------'                 '-------------'                       '----------'
#                            .---------------------------.             |
#     .-- createChallenge -- | pairing_response_received | <-- pair ---'
#     |                      '---------------------------'
#     |     .------------------------.                    .--------.
#     '---> | pairing_challenge_sent | ---> checkOtp ---> | active | <-----.
#           '------------------------'                    '--------'       |
#                                                             |            |
#                                                             '--- pair ---'
#                                                             createChallenge
#                                                                checkOtp

# --------------------------------------------------------------------------- --

    def __init__(self, token_model_object):
        TokenClass.__init__(self, token_model_object)
        self.setType(u'push')
        self.mode = ['challenge']
        self.supports_offline_mode = False

# --------------------------------------------------------------------------- --

    def isActive(self):

        # overwritten, because PushTokenClass can receive validate
        # requests in 3 different states: active (active flag is 1)
        # pairing_response_received and pairing_challenge_sent
        # (both with active flag 0)

        is_completely_finished = TokenClass.isActive(self)
        return is_completely_finished or \
            self.current_state == 'pairing_response_received' or \
            self.current_state == 'pairing_challenge_sent'

# --------------------------------------------------------------------------- --

    # type identifier interface

    @classmethod
    def getClassType(cls):
        return "push"

    @classmethod
    def getClassPrefix(cls):
        # OATH standard compliant prefix: XXYY XX= vendor, YY - token type
        return "KIPT"

# --------------------------------------------------------------------------- --

    # info interface definition

    @classmethod
    def getClassInfo(cls, key=None, ret='all'):

        _ = context['translate']

        info = {'type': 'push', 'title': _('PushToken')}

        info['description'] = 'Challenge-Response-Token over Push ' + \
                              'Notifications - Curve 25519 based'

        # ------------------------------------------------------------------- --

        info['policy'] = {}

        auth_policies = {}

        for policy_name in ['pushtoken_pairing_callback_url',
                            'pushtoken_challenge_callback_url']:

            auth_policies[policy_name] = {'type': 'str'}

        info['policy']['authentication'] = auth_policies

        info['policy']['selfservice'] = {'activate_PushToken':
                                         {'type': 'bool',
                                          'description': _('activate your '
                                                           'PushToken')}
                                         }

        # ------------------------------------------------------------------- --

        # wire the templates

        init_dict = {}
        init_dict['title'] = {'html': 'pushtoken.mako', 'scope': 'enroll.title'}
        init_dict['page'] = {'html': 'pushtoken.mako', 'scope': 'enroll'}
        info['init'] = init_dict

        config_dict = {}
        config_dict['title'] = {
            'html': 'pushtoken.mako', 'scope': 'config.title'}
        config_dict['page'] = {'html': 'pushtoken.mako', 'scope': 'config'}
        info['config'] = config_dict

        ss_enroll = {}
        ss_enroll['title'] = {'html': 'pushtoken.mako',
                              'scope': 'selfservice.title.enroll'}
        ss_enroll['page'] = {'html': 'pushtoken.mako',
                             'scope': 'selfservice.enroll'}

        ss_activate = {}
        ss_activate['title'] = {'html': 'pushtoken.mako',
                                'scope': 'selfservice.title.activate'}
        ss_activate['page'] = {'html': 'pushtoken.mako',
                               'scope': 'selfservice.activate'}

        selfservice_dict = {}
        selfservice_dict['enroll'] = ss_enroll
        selfservice_dict['activate_PushToken'] = ss_activate

        info['selfservice'] = selfservice_dict

        # ------------------------------------------------------------------- --

        if key is not None:
            return info.get(key)

        return info

# --------------------------------------------------------------------------- --

    def pair(self, pairing_data):

        """
        If token has state 'unpaired' it saves the data from
        the pairing response and changes the state to
        'pairing_response_received'

        If token is already in 'active' state it changes the gda
        supplied in the pairing response under the condition
        that the public key matches (re-pairing case)

        :raises TokenStateError: If token state is not 'active'
            or 'unpaired'

        :param pairing_data: A PushTokenPairingData object
        """

        user_token_id = pairing_data.user_token_id
        user_dsa_public_key = pairing_data.user_public_key
        user_login = pairing_data.user_login
        gda = pairing_data.gda

        valid_states = ['unpaired',
                        'active']

        self.ensure_state_is_in(valid_states)

        # ------------------------------------------------------------------- --

        if self.current_state == 'unpaired':

            # original pairing case: we save all the information
            # supplied by the client

            self.addToTokenInfo('user_token_id', user_token_id)
            b64_user_dsa_public_key = b64encode(user_dsa_public_key)
            self.addToTokenInfo('user_dsa_public_key', b64_user_dsa_public_key)
            self.addToTokenInfo('user_login', user_login)
            self.addToTokenInfo('gda', gda)

            self.change_state('pairing_response_received')

        # ------------------------------------------------------------------- --

        if self.current_state == 'active':

            # repairing case: we receive a spontaneous pairing response
            # which is used to change the generic device address

            # we check if the public keys match (signature check
            # was already done in decrypt_pairing_response)

            current_b64_key = self.getFromTokenInfo('user_dsa_public_key')
            current_user_dsa_public_key = b64decode(current_b64_key)

            if user_dsa_public_key != current_user_dsa_public_key:
                raise ValueError('re-pairing: public keys don\'t match')

            self.addToTokenInfo('gda', gda)

# --------------------------------------------------------------------------- --

    def createChallenge(self, transaction_id, options):

        """
        entry hook for the challenge logic. when this function is called
        a challenge with an transaction was created.

        :param transaction_id: A unique transaction id used to identity
            the challenge object

        :param options: additional options as a dictionary

        :raises TokenStateError: If token state is not 'active' or
            'pairing_response_received'

        :returns: A tuple (success, message, data, attributes)
            with success being a boolean indicating if the call
            to this method was successful, message being a string
            that is passed to the user, attributes being additional
            output data (unused in here)
        """

        valid_states = ['pairing_response_received',
                        'active']

        self.ensure_state_is_in(valid_states)

        # ------------------------------------------------------------------- --

        # inside the challenge url we sent a callback url for the client
        # which is defined by an authentication policy

        owner = get_token_owner(self)
        if owner and owner.login and owner.realm:
            realms = [owner.realm]
        else:
            realms = self.getRealms()

        callback_policy_name = 'pushtoken_challenge_callback_url'
        callback_url = get_single_auth_policy(callback_policy_name,
                                              user=owner, realms=realms)

        if not callback_url:
            raise Exception(_('Policy pushtoken_challenge_callback_url must '
                              'have a value'))

        # ------------------------------------------------------------------- --

        # load and configure provider

        # the realm logic was taken from the
        # provider loading in the smstoken class
        # TODO: refactor & centralize logic

        realm = None
        if realms:
            realm = realms[0]

        push_provider = loadProviderFromPolicy(provider_type='push',
                                               realm=realm,
                                               user=owner)

        # ------------------------------------------------------------------- --

        if self.current_state == 'pairing_response_received':

            content_type = CONTENT_TYPE_PAIRING

            message = ''
            challenge_url, sig_base = self.create_challenge_url(transaction_id,
                                                                content_type,
                                                                callback_url)

        else:

            content_type_as_str = options.get('content_type')

            try:

                # pylons silently converts all ints in json
                # to unicode :(

                content_type = int(content_type_as_str)

            except:

                raise ValueError('Unrecognized content type: %s'
                                 % content_type_as_str)

            # --------------------------------------------------------------- --

            if content_type == CONTENT_TYPE_SIGNREQ:

                message = options.get('data')
                challenge_url, sig_base = self.create_challenge_url(
                                                transaction_id, content_type,
                                                callback_url, message=message)

            # --------------------------------------------------------------- --

            elif content_type == CONTENT_TYPE_LOGIN:

                message = options.get('data')
                login, __, host = message.partition('@')

                challenge_url, sig_base = self.create_challenge_url(
                                                transaction_id, content_type,
                                                callback_url, login=login,
                                                host=host)

            else:

                raise ValueError('Unrecognized content type: %s' % content_type)

        # ------------------------------------------------------------------- --

        # send the challenge_url to the push notification proxy

        token_info = self.getTokenInfo()
        gda = token_info['gda']

        log.debug("pushing notification: %r : %r", challenge_url, gda)

        success, response = push_provider.push_notification(challenge_url, gda)

        if not success:
            raise Exception('push mechanism failed. response was %r'
                            % response)

        # ------------------------------------------------------------------- --

        # we save sig_base in the challenge data, because we need it in
        # checkOtp to verify the signature

        b64_sig_base = b64encode(sig_base)
        data = {'sig_base': b64_sig_base}

        if self.current_state == 'pairing_response_received':
            self.change_state('pairing_challenge_sent')

        # ------------------------------------------------------------------- --

        # don't pass the challenge_url as message to the user

        return (True, '', data, {})

# --------------------------------------------------------------------------- --

    def checkOtp(self, passwd, counter, window, options=None):

        """
        checks if the supplied challenge response is correct.

        :param passwd: The challenge response

        :param options: A dictionary of parameters passed by the upper
            layer (used for transaction_id in this context)

        :param counter: legacy API (unused)

        :param window: legacy API (unused)

        :raises TokenStateError: If token state is not 'active' or
            'pairing_challenge_sent'

        :returns: -1 for failure, 1 for success
        """

        valid_states = ['pairing_challenge_sent',
                        'active']

        self.ensure_state_is_in(valid_states)

        # ------------------------------------------------------------------- --

        filtered_challenges = []
        serial = self.getSerial()

        if options is None:
            options = {}

        max_fail = int(getFromConfig('PushMaxChallenges', '3'))

        # ------------------------------------------------------------------- --

        if 'transactionid' in options:

            # --------------------------------------------------------------- --

            # fetch all challenges that match the transaction id or serial

            transaction_id = options.get('transaction_id')

            challenges = Challenges.lookup_challenges(serial, transaction_id)

            # --------------------------------------------------------------- --

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

        # ------------------------------------------------------------------- --

        if not filtered_challenges:
            return -1

        for challenge in filtered_challenges:

            # client verifies the challenge by signing the challenge
            # plaintext. we retrieve the original plaintext (saved
            # in createChallenge) and check for a match

            b64_dsa_public_key = self.getFromTokenInfo('user_dsa_public_key')
            user_dsa_public_key = b64decode(b64_dsa_public_key)

            data = challenge.getData()
            sig_base = data['sig_base']

            passwd_as_bytes = decode_base64_urlsafe(passwd)
            sig_base_as_bytes = b64decode(sig_base)
            try:
                verify_sig(passwd_as_bytes,
                           sig_base_as_bytes,
                           user_dsa_public_key)
                return 1
            except ValueError:  # signature mismatch
                return -1

        return -1

# --------------------------------------------------------------------------- --

    def statusValidationSuccess(self):

        if self.current_state == 'pairing_challenge_sent':
            self.change_state('active')
            self.enable(True)

# --------------------------------------------------------------------------- --

    def update(self, params):

        """
        initialization entry hook for the enrollment process.

        :param params: parameters provided by the client

        :raises Exception: If the client supplied unrecognized
            configuration parameters for this token type

        :raises Exception: If the policy 'pushtoken_pairing_callback_url'
            was not set.

        :raises TokenStateError: If token state is not None
            (default pre-enrollment state)
        """

        param_keys = set(params.keys())
        init_rollout_state_keys = set(['type', 'serial', '::scope::',
                                       'user.login', 'description',
                                       'user.realm', 'session', 'key_size',
                                       'resConf', 'user', 'realm',
                                       'pin'])

        # ------------------------------------------------------------------- --

        if not param_keys.issubset(init_rollout_state_keys):

            # make sure the call aborts, if request
            # type wasn't recognized

            raise Exception('Unknown request type for token type pushtoken')

        # if param keys are in above set, the token is
        # initialized for the first time. this is e.g. done on the
        # manage web ui. since the token doesn't exist in the database
        # yet, its rollout state must be None (that is: the data for
        # the rollout state doesn't exist yet)

        self.ensure_state(None)

        # --------------------------------------------------------------- --

        # we check if callback policies are set. this must be done here
        # because the token gets saved directly after the update method
        # in the TokenHandler

        _ = context['translate']

        owner = get_token_owner(self)
        if owner and owner.login and owner.realm:
            realms = [owner.realm]
        else:
            realms = self.getRealms()

        cb_url = get_single_auth_policy('pushtoken_pairing_callback_url',
                                        user=owner, realms=realms)

        if not cb_url:
            raise Exception(_('Policy pushtoken_pairing_callback_url must '
                              'have a value'))

        partition = get_partition(realms, owner)
        self.addToTokenInfo('partition', partition)

        # --------------------------------------------------------------- --

        # we set the the active state of the token to False, because
        # it should not be allowed to use it for validation before the
        # pairing process is done

        self.token.LinOtpIsactive = False

        # -------------------------------------------------------------- --

        TokenClass.update(self, params, reset_failcount=True)

        # -------------------------------------------------------------- --

        self.change_state('initialized')

# --------------------------------------------------------------------------- --

    def getInitDetail(self, params, user=None):

        """
        returns initialization details in the enrollment process
        (gets called after update method). used here to pass the
        pairing url to the user

        :param params: parameters provided by the client

        :param user: (unused)

        :raises TokenStateError: If token state is not 'initialized'

        :returns: a dict consisting of a 'pairing_url' entry, containing
            the pairing url and a 'pushtoken_pairing_url' entry containing
            a data structure used in the manage frontend in the enrollment
            process
        """

        _ = context['translate']
        response_detail = {}

        self.ensure_state('initialized')

        # ------------------------------------------------------------------- --

        # collect data used for generating the pairing url

        serial = self.getSerial()

        # ------------------------------------------------------------------- --

        owner = get_token_owner(self)
        if owner and owner.login and owner.realm:
            realms = [owner.realm]
        else:
            realms = self.getRealms()

        # it is guaranteed, that cb_url has a value
        # because we checked it in the update method

        cb_url = get_single_auth_policy('pushtoken_pairing_callback_url',
                                        user=owner, realms=realms)

        # --------------------------------------------------------------- --

        partition = self.getFromTokenInfo('partition')

        # FIXME: certificate usage

        pairing_url = generate_pairing_url(token_type='push',
                                           partition=partition,
                                           serial=serial,
                                           callback_url=cb_url,
                                           use_cert=False)

        # --------------------------------------------------------------- --

        self.addToInfo('pairing_url', pairing_url)
        response_detail['pairing_url'] = pairing_url

        # --------------------------------------------------------------- --

        # add response tabs (used in the manage view on enrollment)

        response_detail['lse_qr_url'] = {
            'description': _('Pairing URL'),
            'img': create_img(pairing_url, width=250),
            'order': 0,
            'value': pairing_url}

        response_detail['serial'] = self.getSerial()

        # ------------------------------------------------------------------ --

        self.change_state('unpaired')

        return response_detail

# --------------------------------------------------------------------------- --

    def create_challenge_url(self,
                             transaction_id,
                             content_type,
                             callback_url='',
                             message=None,
                             login=None,
                             host=None):

        """
        creates a challenge url (looking like lseqr://push/<base64string>),
        returns the url and the unencrypted challenge data

        :param transaction_id: The transaction id generated by LinOTP

        :param content_type: One of the types CONTENT_TYPE_SIGNREQ,
            CONTENT_TYPE_PAIRING, CONTENT_TYPE_LOGIN

        :param callback_url: callback url (optional), default is
            empty string

        :param message: the transaction message, that should be signed
            by the client. Only for content type CONTENT_TYPE_SIGNREQ

        :param login: the login name of the user. Only for content type
            CONTENT_TYPE_LOGIN

        :param host: hostname of the user. Only for content type
            CONTENT_TYPE_LOGIN

        :returns: tuple (challenge_url, sig_base), with challenge_url being
            the push url and sig_base the message, that is used for
            the client signature
        """

        serial = self.getSerial()

        # ------------------------------------------------------------------- --

        # sanity/format checks

        if content_type not in [CONTENT_TYPE_SIGNREQ,
                                CONTENT_TYPE_PAIRING, CONTENT_TYPE_LOGIN]:
            raise InvalidFunctionParameter('content_type', 'content_type must '
                                           'be CONTENT_TYPE_SIGNREQ, '
                                           'CONTENT_TYPE_PAIRING or '
                                           'CONTENT_TYPE_LOGIN.')

        # ------------------------------------------------------------------- --

        #  after the lseqr://push/ prefix the following data is encoded
        #  in urlsafe base64:

        #            ---------------------------------------------------
        #  fields   | version | user token id |  R  | ciphertext | sign |
        #            ---------------------------------------------------
        #           |          header         |          body           |
        #            ---------------------------------------------------
        #  size     |    1    |       4       |  32 |      ?     |  64  |
        #            ---------------------------------------------------
        #

        # create header

        user_token_id = self.getFromTokenInfo('user_token_id')
        data_header = struct.pack('<bI', CHALLENGE_URL_VERSION, user_token_id)

        # ------------------------------------------------------------------- --

        # create body

        r = urandom(32)
        R = calc_dh_base(r)

        b64_user_dsa_public_key = self.getFromTokenInfo('user_dsa_public_key')
        user_dsa_public_key = b64decode(b64_user_dsa_public_key)
        user_dh_public_key = dsa_to_dh_public(user_dsa_public_key)

        ss = calc_dh(r, user_dh_public_key)
        U = SHA256.new(ss).digest()
        zerome(ss)

        sk = U[0:16]
        nonce = U[16:32]
        zerome(U)

        # ------------------------------------------------------------------- --

        # create plaintext section

        # ------------------------------------------------------------------- --

        # generate plaintext header

        #            ------------------------------------------------
        #  fields   | content_type  | transaction_id | timestamp | ..
        #            ------------------------------------------------
        #  size     |       1       |        8       |     8     |  ?
        #            -------------------------------------------------

        transaction_id = transaction_id_to_u64(transaction_id)
        plaintext = struct.pack('<bQQ', content_type, transaction_id,
                                int(time.time()))

        # ------------------------------------------------------------------- --

        utf8_callback_url = callback_url.encode('utf8')

        # enforce max url length as specified in protocol

        if len(utf8_callback_url) > 511:
            raise InvalidFunctionParameter('callback_url', 'max string '
                                           'length (encoded as utf8) is '
                                           '511')

        # ------------------------------------------------------------------- --

        # create data package depending on content type

        # ------------------------------------------------------------------- --

        if content_type == CONTENT_TYPE_PAIRING:

            #            -----------------------------------------
            #  fields   | header | serial | NUL | callback | NUL |
            #            -----------------------------------------
            #  size     |   9    |    ?   |  1  |     ?    |  1  |
            #            -----------------------------------------

            utf8_serial = serial.encode('utf8')

            if len(utf8_serial) > 63:
                raise ValueError('serial (encoded as utf8) can only be 63 '
                                 'characters long')

            plaintext += utf8_serial + b'\00' + utf8_callback_url + b'\00'

        # ------------------------------------------------------------------- --

        if content_type == CONTENT_TYPE_SIGNREQ:

            if message is None:
                raise InvalidFunctionParameter('message', 'message must be '
                                               'supplied for content type '
                                               'SIGNREQ')

            #            ------------------------------------------
            #  fields   | header | message | NUL | callback | NUL |
            #            ------------------------------------------
            #  size     |   9    |    ?    |  1  |     ?    |  1  |
            #            ------------------------------------------

            utf8_message = message.encode('utf8')

            # enforce max sizes specified by protocol

            if len(utf8_message) > 511:
                raise InvalidFunctionParameter('message', 'max string '
                                               'length (encoded as utf8) is '
                                               '511')

            plaintext += utf8_message + b'\00' + utf8_callback_url + b'\00'

        # ------------------------------------------------------------------- --

        if content_type == CONTENT_TYPE_LOGIN:

            if login is None:
                raise InvalidFunctionParameter('login', 'login must be '
                                               'supplied for content type '
                                               'LOGIN')
            if host is None:
                raise InvalidFunctionParameter('host', 'host must be '
                                               'supplied for content type '
                                               'LOGIN')

            #            -----------------------------------------------------
            #  fields   | header | login | NUL | host | NUL | callback | NUL |
            #            -----------------------------------------------------
            #  size     |   9    |   ?   |  1  |   ?  |  1  |     ?    |  1  |
            #            -----------------------------------------------------

            utf8_login = login.encode('utf8')
            utf8_host = host.encode('utf8')

            # enforce max sizes specified by protocol

            if len(utf8_login) > 127:
                raise InvalidFunctionParameter('login', 'max string '
                                               'length (encoded as utf8) is '
                                               '127')
            if len(utf8_host) > 255:
                raise InvalidFunctionParameter('host', 'max string '
                                               'length (encoded as utf8) is '
                                               '255')

            plaintext += utf8_login + b'\00'
            plaintext += utf8_host + b'\00'
            plaintext += utf8_callback_url + b'\00'

        # ------------------------------------------------------------------- --

        # encrypt inner layer

        nonce_as_int = int_from_bytes(nonce, byteorder='big')
        ctr = Counter.new(128, initial_value=nonce_as_int)
        cipher = AES.new(sk, AES.MODE_CTR, counter=ctr)
        ciphertext = cipher.encrypt(plaintext)
        unsigned_raw_data = data_header + R + ciphertext

        # ------------------------------------------------------------------- --

        # create signature

        partition = self.getFromTokenInfo('partition')
        secret_key = get_secret_key(partition)
        signature = crypto_sign_detached(unsigned_raw_data, secret_key)
        raw_data = unsigned_raw_data + signature

        url = 'lseqr://push/' + encode_base64_urlsafe(raw_data)

        return url, (signature + plaintext)

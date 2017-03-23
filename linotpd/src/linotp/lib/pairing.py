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
from collections import namedtuple
from linotp.lib.crypto import encode_base64_urlsafe
from linotp.lib.crypto import decode_base64_urlsafe
from linotp.lib.crypto import get_secret_key
from linotp.lib.crypto import get_dh_secret_key
from linotp.lib.crypto import get_public_key
from linotp.lib.error import InvalidFunctionParameter
from linotp.lib.error import ParameterError
from linotp.lib.error import ProgrammingError
from pysodium import crypto_sign_detached
from pysodium import crypto_scalarmult_curve25519 as calc_dh
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from linotp.lib.crypto import zerome
from linotp.lib.qrtoken import parse_qrtoken_pairing_data
from linotp.lib.pushtoken import parse_and_verify_pushtoken_pairing_data

"""
This module provides functions and constants for the generation of
pairing urls and the decryption of pairing responses. For the token
type specific pairing data parsing look at the appropriate token lib
(e.g. lib.qrtoken). The pairing logic is handled partly in the
validate/pair controller, partly in the token classes.
"""

# --------------------------------------------------------------------------- --
# pairing constants (used for the low-level implementation in c)
# --------------------------------------------------------------------------- --

PAIR_URL_VERSION = 2
PAIR_RESPONSE_VERSION = 1

FLAG_PAIR_PK = 1 << 0
FLAG_PAIR_SERIAL = 1 << 1
FLAG_PAIR_CBURL = 1 << 2
FLAG_PAIR_CBSMS = 1 << 3
FLAG_PAIR_DIGITS = 1 << 4
FLAG_PAIR_HMAC = 1 << 5
FLAG_PAIR_COUNTER = 1 << 6
FLAG_PAIR_TSTART = 1 << 7
FLAG_PAIR_TSTEP = 1 << 8

TYPE_QRTOKEN_ED25519 = 2
TYPE_PUSHTOKEN = 4
SUPPORTED_TOKEN_TYPES = [TYPE_QRTOKEN_ED25519, TYPE_PUSHTOKEN]

# translation tables between low level enum types and
# high level string identifiers

hash_algorithms = {'sha1': 0, 'sha256': 1, 'sha512': 2}
TOKEN_TYPES = {'qr': TYPE_QRTOKEN_ED25519, 'push': TYPE_PUSHTOKEN}
INV_TOKEN_TYPES = {v: k for k, v in TOKEN_TYPES.items()}


# --------------------------------------------------------------------------- --


def generate_pairing_url(token_type,
                         partition=None,
                         serial=None,
                         callback_url=None,
                         callback_sms_number=None,
                         otp_pin_length=None,
                         hash_algorithm=None,
                         use_cert=False):

    """
    Generates a pairing url that should be sent to the client.

    Mandatory parameters:

    :param: token_type The token type for which this url is generated
        as a string (currently supported is only 'qr')

    Optional parameters:

    :param partition: A partition id that should be used during pairing.
        Partitions identitify a subspace of tokens, that share a common
        key pair. This currently defaults to the enum id of the token
        type when set to None and is reserved for future use.

    :param serial: When a token for the client was already enrolled
        (e.g. manually in the manage interface) its serial has to be
        sent to the client. When serial is not specified the client will
        receive a so-called 'anonymous pairing url' with no token data
        inside it. The token will then be created after the server
        received a pairing response from the client.

    :param callback_url: A callback URL that should be used by the client
        to sent back the pairing reponse. Please note, that this url will
        be cached by the client and used in the challenge step, if the
        challenge doesn't provide a custom url

    :param callback_sms_number: A sms number that can be used by the client
        to send back the pairing response. Typically this is used as a
        fallback for offline pairing.
        As with the callback url please note, that the number will be
        cached by the client. If you want a different number in the
        challenge step you have to send it inside the challenge as
        specified in the challenge protocol

    :param otp_pin_length: The number of digits the otp has to consist of.

    :param hash_algorithm: A string value that signifies the hash algorithm
        used in calculating the hmac. Currently the values 'sha1', 'sha256',
        'sha512' are supported. If the parameter is left out the default
        depends on the token type. qrtoken uses sha256 as default, while
        hotp/totp uses sha1.

    :param use_cert: A boolean, if a server certificate should be used
        in the pairing url

    The function can raise several exceptions:

    :raises InvalidFunctionParameter: If the string given in token_type
        doesn't match a supported token type

    :raises InvalidFunctionParameter: If the string given in hash_algorithm
        doesn't match a supported hash algorithm

    :raises InvalidFunctionParameter: If public key has a different size
        than 32 bytes

    :raises InvalidFunctionParameter: If otp_pin_length value is not between
        1 and 127

    :return: Pairing URL string
    """

    # ----------------------------------------------------------------------- --

    # check the token type

    try:
        TOKEN_TYPE = TOKEN_TYPES[token_type]
    except KeyError:
        allowed_types = ', '.join(TOKEN_TYPES.keys())
        raise InvalidFunctionParameter('token_type',
                                       'Unsupported token type %s. Supported '
                                       'types for pairing are: %s' %
                                       (token_type, allowed_types))

    # ----------------------------------------------------------------------- --

    # initialize the flag bitmap

    flags = 0

    if not use_cert:
        flags |= FLAG_PAIR_PK
    if serial is not None:
        flags |= FLAG_PAIR_SERIAL
    if callback_url is not None:
        flags |= FLAG_PAIR_CBURL
    if callback_sms_number is not None:
        flags |= FLAG_PAIR_CBSMS
    if hash_algorithm is not None:
        flags |= FLAG_PAIR_HMAC
    if otp_pin_length is not None:
        flags |= FLAG_PAIR_DIGITS

    # ----------------------------------------------------------------------- --

    #            ------------------------------
    #  fields   | version | type | flags | ... |
    #            ------------------------------
    #  size     |    1    |  1   |   4   |  ?  |
    #            ------------------------------

    data = struct.pack('<bbI', PAIR_URL_VERSION, TOKEN_TYPE, flags)

    # ----------------------------------------------------------------------- --

    #            -----------------------
    #  fields   | ... | partition | ... |
    #            -----------------------
    #  size     |  6  |     4     |  ?  |
    #            -----------------------

    data += struct.pack('<I', partition)

    # ----------------------------------------------------------------------- --

    #            --------------------------------
    #  fields   | .... | server public key | ... |
    #            --------------------------------
    #  size     |  10  |        32         |  ?  |
    #            --------------------------------

    if flags & FLAG_PAIR_PK:

        server_public_key = get_public_key(partition)

        if len(server_public_key) != 32:
            raise InvalidFunctionParameter('server_public_key',
                                           'Public key must be 32 bytes long')

        data += server_public_key

    # ----------------------------------------------------------------------- --

    # Depending on flags additional data may be sent. If serial was provided
    # serial will be sent back. If callback url or callback sms was provided
    # the corresponding data will be added, too

    #            --------------------------------------------------------
    #  fields   | .... | serial | NUL | cb url | NUL | cb sms | NUL | ... |
    #            --------------------------------------------------------
    #  size     |  42  |   ?    |  1  |   ?    |  1  |   ?    |  1  |  ?  |
    #            --------------------------------------------------------

    if flags & FLAG_PAIR_SERIAL:
        data += serial.encode('utf8') + b'\x00'
    if flags & FLAG_PAIR_CBURL:
        data += callback_url.encode('utf8') + b'\x00'
    if flags & FLAG_PAIR_CBSMS:
        data += callback_sms_number.encode('utf8') + b'\x00'

    # ----------------------------------------------------------------------- --

    # Other optional values: allowed pin length of otp (number of digits)
    # and custom hash algorithm

    #            ---------------------------------------
    #  fields   | ... | otp pin length | hash_algorithm |
    #            ---------------------------------------
    #  size     |  ?  |       1        |       1        |
    #            ---------------------------------------

    if flags & FLAG_PAIR_DIGITS:
        if not(6 <= otp_pin_length <= 12):
            raise InvalidFunctionParameter('otp_pin_length', 'Pin length must '
                                           'be in the range 6..12')
        data += struct.pack('<b', otp_pin_length)

    if flags & FLAG_PAIR_HMAC:
        try:
            HASH_ALGO = hash_algorithms[hash_algorithm]
        except KeyError:
            allowed_values = ", ".join(hash_algorithms.keys())
            raise InvalidFunctionParameter('hash_algorithm',
                                           'Unsupported hash algorithm %s, '
                                           'allowed values are %s' %
                                           (hash_algorithm, allowed_values))
        data += struct.pack('<b', HASH_ALGO)

    # ----------------------------------------------------------------------- --

    # TODO missing token details for other protocols (hotp, hmac, etc)
    # * counter (u64le)
    # * tstart (u64le)
    # * tstep (u32le)

    # TODO: replace lseqr literal with global config value
    # or global constant

    if not (flags & FLAG_PAIR_PK):

        secret_key = get_secret_key(partition)
        server_sig = crypto_sign_detached(data, secret_key)
        data += server_sig

    return 'lseqr://pair/' + encode_base64_urlsafe(data)

# --------------------------------------------------------------------------- --

PairingResponse = namedtuple('PairingResponse', ['token_type', 'pairing_data'])

# --------------------------------------------------------------------------- --


def get_pairing_data_parser(token_type):

    """
    fetches a parser for the decrypted inner layer
    of a pairing response according to its token type.

    :param token_type: the token type obtained from the
        decrypted inner layer

    :return: parser function
    """

    if token_type == TYPE_QRTOKEN_ED25519:
        return parse_qrtoken_pairing_data

    if token_type == TYPE_PUSHTOKEN:
        return parse_and_verify_pushtoken_pairing_data

    raise ValueError('unsupported token type %d, supported types '
                     'are %s' % (token_type, SUPPORTED_TOKEN_TYPES))

# --------------------------------------------------------------------------- --


def decrypt_pairing_response(enc_pairing_response):

    """
    Parses and decrypts a pairing response into a named tuple PairingResponse
    consisting of

    * user_public_key - the user's public key
    * user_token_id   - an id for the client to uniquely identify the token.
                        this id is necessary, because the client could
                        communicate with more than one linotp, so serials
                        could overlap.
    * serial - the serial identifying the token in linotp
    * user_login - the user login name

    It is possible that either user_login or serial is None. Both
    being None is a valid response according to this function but
    will be considered an error in the calling method.

    The following parameters are needed:

    :param enc_pairing_response:
        The urlsafe-base64 encoded string received from the client

    The following exceptions can be raised:

    :raises ParameterError:
        If the pairing response has an invalid format

    :raises ValueError:
        If the pairing response has a different version
        than this implementation (currently hardcoded)

    :raises ValueError:
        If the pairing response indicates a different
        token type than QRToken (also hardcoded)

    :raises ValueError:
        If the pairing response field "partition" is not
        identical to the field "token_type"
        ("partition" is currently used for the token
        type id. It is reserved for multiple key usage
        in a future implementation.)

    :raises ValueError:
        If the MAC of the response didn't match

    :return:
        Parsed/decrypted PairingReponse
    """

    data = decode_base64_urlsafe(enc_pairing_response)

    # ----------------------------------------------------------------------- --

    #            --------------------------------------------
    #  fields   | version | partition | R  | ciphertext | MAC |
    #            --------------------------------------------
    #  size     |    1    |     4     | 32 |      ?     | 16  |
    #            --------------------------------------------

    if len(data) < 1 + 4 + 32 + 16:
        raise ParameterError('Malformed pairing response')

    # ----------------------------------------------------------------------- --

    # parse header

    header = data[0:5]
    version, partition = struct.unpack('<bI', header)

    if version != PAIR_RESPONSE_VERSION:
        raise ValueError('Unexpected pair-response version, '
                         'expected: %d, got: %d' %
                         (PAIR_RESPONSE_VERSION, version))

    # ----------------------------------------------------------------------- --

    R = data[5:32+5]
    ciphertext = data[32+5:-16]
    mac = data[-16:]

    # ----------------------------------------------------------------------- --

    # calculate the shared secret

    # - --

    secret_key = get_dh_secret_key(partition)
    ss = calc_dh(secret_key, R)

    # derive encryption key and nonce from the shared secret
    # zero the values from memory when they are not longer needed
    U = SHA256.new(ss).digest()
    zerome(ss)
    encryption_key = U[0:16]
    nonce = U[16:32]
    zerome(U)

    # decrypt response
    cipher = AES.new(encryption_key, AES.MODE_EAX, nonce)
    cipher.update(header)
    plaintext = cipher.decrypt_and_verify(ciphertext, mac)
    zerome(encryption_key)

    # ----------------------------------------------------------------------- --

    # check format boundaries for type peaking
    # (token type specific length boundaries are checked
    #  in the appropriate functions)

    plaintext_min_length = 1
    if len(data) < plaintext_min_length:
        raise ParameterError('Malformed pairing response')

    # ----------------------------------------------------------------------- --

    # get token type and parse decrypted response

    #            ----------------------
    #  fields   | token type |   ...   |
    #            ----------------------
    #  size     |     1      |    ?    |
    #            ----------------------

    token_type = struct.unpack('<b', plaintext[0])[0]

    if token_type not in SUPPORTED_TOKEN_TYPES:
        raise ValueError('unsupported token type %d, supported types '
                         'are %s' % (token_type, SUPPORTED_TOKEN_TYPES))

    # ----------------------------------------------------------------------- --

    # delegate the data parsing of the plaintext
    # to the appropriate function and return the result

    data_parser = get_pairing_data_parser(token_type)
    pairing_data = data_parser(plaintext)
    zerome(plaintext)

    # get the appropriate high level type

    try:
        token_type_as_str = INV_TOKEN_TYPES[token_type]
    except KeyError:
        raise ProgrammingError('token_type %d is in SUPPORTED_TOKEN_TYPES',
                               'however an appropriate mapping entry in '
                               'TOKEN_TYPES is missing' % token_type)

    return PairingResponse(token_type_as_str, pairing_data)

#eof######################################################################

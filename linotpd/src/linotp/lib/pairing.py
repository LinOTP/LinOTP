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

import struct
from linotp.lib.crypt import encode_base64_urlsafe
from linotp.lib.crypt import get_qrtoken_secret_key
from linotp.lib.error import InvalidFunctionParameter
from pysodium import crypto_sign_detached

"""
This module provides functions and constants for the generation of
pairing urls. For the response processing and challenge generation
please take a look into the appropriate token type lib (e.g. lib.qrtoken)
"""

# ------------------------------------------------------------------------------
# pairing constants (used for the low-level implementation in c)
# ------------------------------------------------------------------------------

PAIR_VERSION = 1

FLAG_PAIR_PK = 1 << 0
FLAG_PAIR_SERIAL = 1 << 1
FLAG_PAIR_CBURL = 1 << 2
FLAG_PAIR_CBSMS = 1 << 3
FLAG_PAIR_DIGITS = 1 << 4
FLAG_PAIR_HMAC = 1 << 5
FLAG_PAIR_COUNTER = 1 << 6
FLAG_PAIR_TSTART = 1 << 7
FLAG_PAIR_TSTEP = 1 << 8

hash_algorithms = {'sha1': 0, 'sha256': 1, 'sha512': 2}
token_types = {'qrtoken': 2}

# ------------------------------------------------------------------------------


def generate_pairing_url(token_type,
                         server_public_key,
                         serial=None,
                         callback_url=None,
                         callback_sms_number=None,
                         otp_pin_length=None,
                         hash_algorithm=None,
                         cert_id=None):
    """
    Generates a pairing url that should be sent to the client.

    Mandatory parameters:

    :param: token_type The token type for which this url is generated
        as a string (currently supported is only 'qr')

    :param: server_public_key: The servers public key as bytes (length: 32)

    Optional parameters:

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

    :param cert_id: A certificate id that should be used during pairing.
        default is None.

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

    # --------------------------------------------------------------------------

    # check the token type

    try:
        TOKEN_TYPE = token_types[token_type]
    except KeyError:
        allowed_types = ', '.join(token_types.keys())
        raise InvalidFunctionParameter('token_type',
                                       'Unsupported token type %s. Supported '
                                       'types for pairing are: %s' %
                                       (token_type, allowed_types))

    # --------------------------------------------------------------------------

    # initialize the flag bitmap

    flags = 0

    if cert_id is None:
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

    # --------------------------------------------------------------------------

    #            ------------------------------
    #  fields   | version | type | flags | ... |
    #            ------------------------------
    #  size     |    1    |  1   |   4   |  ?  |
    #            ------------------------------

    data = struct.pack('<bbI', PAIR_VERSION, TOKEN_TYPE, flags)

    # --------------------------------------------------------------------------

    #            -------------------------------
    #  fields   | ... | server public key | ... |
    #            -------------------------------
    #  size     |  6  |        32         |  ?  |
    #            -------------------------------

    if len(server_public_key) != 32:
        raise InvalidFunctionParameter('server_public_key', 'Public key must '
                                       'be 32 bytes long')

    if flags & FLAG_PAIR_PK:
        data += server_public_key

    # --------------------------------------------------------------------------

    # Depending on flags additional data may be sent. If serial was provided
    # serial will be sent back. If callback url or callback sms was provided
    # the corresponding data will be added, too

    #            --------------------------------------------------------
    #  fields   | ... | serial | NUL | cb url | NUL | cb sms | NUL | ... |
    #            --------------------------------------------------------
    #  size     | 38  |   ?    |  1  |   ?    |  1  |   ?    |  1  |  ?  |
    #            --------------------------------------------------------

    if flags & FLAG_PAIR_SERIAL:
        data += serial.encode('utf8') + b'\x00'
    if flags & FLAG_PAIR_CBURL:
        data += callback_url.encode('utf8') + b'\x00'
    if flags & FLAG_PAIR_CBSMS:
        data += callback_sms_number.encode('utf8') + b'\x00'

    # --------------------------------------------------------------------------

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

    # --------------------------------------------------------------------------

    # TODO missing token details for other protocols (hotp, hmac, etc)
    # * counter (u64le)
    # * tstart (u64le)
    # * tstep (u32le)

    # TODO: replace lseqr literal with global config value
    # or global constant

    if cert_id is not None:
        secret_key = get_qrtoken_secret_key(cert_id=cert_id)
        server_sig = crypto_sign_detached(data, secret_key)
        data += server_sig

    return 'lseqr://pair/' + encode_base64_urlsafe(data)

#eof######################################################################

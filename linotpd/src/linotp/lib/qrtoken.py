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
from collections import namedtuple

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from pysodium import crypto_scalarmult_curve25519 as calc_dh
from linotp.lib.crypt import decode_base64_urlsafe
from linotp.lib.crypt import zerome
from linotp.lib.error import ParameterError
from linotp.lib.crypt import get_qrtoken_dh_secret_key

# ------------------------------------------------------------------------------
# Pairing logic
# ------------------------------------------------------------------------------

# pairing constants
#
PAIR_VERSION        = 0

FLAG_PAIR_SERIAL    = 1 << 0
FLAG_PAIR_CBURL     = 1 << 1
FLAG_PAIR_CBSMS     = 1 << 2
FLAG_PAIR_DIGITS    = 1 << 3
FLAG_PAIR_HMAC      = 1 << 4
FLAG_PAIR_COUNTER   = 1 << 5
FLAG_PAIR_TSTART    = 1 << 6
FLAG_PAIR_TSTEP     = 1 << 7

RESPONSE_VERSION    = 0

hash_algorithms = {'sha1' : 0, 'sha256': 1, 'sha512': 2}

# QRToken constants

QRTOKEN_VERSION       = 0
TYPE_QRTOKEN          = 2

PairingResponse = namedtuple('PairingResponse',
                             ['user_public_key', 'user_token_id',
                              'serial', 'user_login'])

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
        If the MAC of the response didn't match

    :return:
        Parsed/encrpted PairingReponse
    """

    data = decode_base64_urlsafe(enc_pairing_response)

    # --------------------------------------------------------------------------

    #            -----------------------
    #  fields   | R  | ciphertext | MAC |
    #            -----------------------
    #  size     | 32 |      ?     | 16  |
    #            -----------------------

    if len(data) < 32 + 16:
        raise ParameterError('Malformed pairing response')

    R = data[0:32]
    ciphertext = data[32:-16]
    mac = data[-16:]

    # --------------------------------------------------------------------------

    # calculate the shared secret

    # ----

    secret_key = get_qrtoken_dh_secret_key()
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
    plaintext = cipher.decrypt_and_verify(ciphertext, mac)

    # --------------------------------------------------------------------------

    # parse decrypted response

    # ----

    plaintext_min_length = 1 + 1 + 4 + 32 + 1
    if len(data) < plaintext_min_length:
        raise ParameterError('Malformed pairing response')

    # Parse Pairing Reponse Header (First 6 Bytes)

    #            -------------------------------------------
    #  fields   | version  | type | user token id |   ...   |
    #            -------------------------------------------
    #  size     |    1     |  1   |       4       |    ?    |
    #            -------------------------------------------

    resp_header = plaintext[0:6]
    version, token_type, user_token_id = struct.unpack('<bbI', resp_header)

    if version != 0:
        raise ValueError('Unexpected pair-response version, '
                         'expected: %d, got: %d' % (0, version))

    if token_type != 2:
        raise ValueError('wrong token type in user response, '
                         'expected: %d, got: %d' % (2, token_type))

    # --------------------------------------------------------------------------

    # get user public key (next 32 bytes)

    #            -----------------------------
    #  fields   | ... | user public key | ... |
    #            -----------------------------
    #  size     |  6  |       32        |  ?  |
    #            -----------------------------

    user_public_key = plaintext[6:6+32]

    # --------------------------------------------------------------------------

    # get serial and/or user login

    #            ---------------------------------
    #  fields   | ... | serial | NUL | user login |
    #            ---------------------------------
    #  size     | 38  |   ?    |  1  |     ?      |
    #            ---------------------------------

    # parse token_serial and user identification

    serial_user_data = plaintext[6+32:].split(b'\x00')
    serial = serial_user_data[0].decode('utf8')
    user_login = serial_user_data[1].decode('utf8')

    return PairingResponse(user_public_key, user_token_id, serial, user_login)

#eof############################################################################

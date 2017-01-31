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
from linotp.lib.error import ParameterError

_QRTokenPairingData = namedtuple('_QRTokenPairingData',
                                 ['user_public_key', 'user_token_id',
                                  'serial', 'user_login'])


class QRTokenPairingData(_QRTokenPairingData):

    """
    holds all the information of a QRToken pairing response,
    namely user_public_key, user_token_id, serial and user_login
    """

    pass

# --------------------------------------------------------------------------- --


def parse_qrtoken_pairing_data(plaintext):

    """
    Parses the decrypted inner layer of a pairing response
    according to the QRToken Pairing data format.

    :param plaintext: The plaintext received from the decryption
        of the outer pairing response layer

    :return: QRTokenPairingData: A named tuple holding
        the parsed fields
    """

    # ----------------------------------------------------------------------- --

    # check format boundaries

    plaintext_min_length = 1 + 4 + 32 + 1 + 1
    if len(plaintext) < plaintext_min_length:
        raise ParameterError('Malformed pairing response for type QrToken')

    # ----------------------------------------------------------------------- --

    # get user token id (unique id on the client)
    # (token type was already processed in
    #  decrypt_pairing_response function)

    #            --------------------------------------
    #  fields   | token type | user token id |   ...   |
    #            --------------------------------------
    #  size     |     1      |       4       |    ?    |
    #            --------------------------------------

    user_token_id = struct.unpack('<I', plaintext[1:5])[0]

    # ----------------------------------------------------------------------- --

    # get user public key (next 32 bytes)

    #            -----------------------------
    #  fields   | ... | user public key | ... |
    #            -----------------------------
    #  size     |  5  |       32        |  ?  |
    #            -----------------------------

    user_public_key = plaintext[5:5+32]

    # ----------------------------------------------------------------------- --

    # get serial and/or user login

    #            ---------------------------------
    #  fields   | ... | serial | NUL | user login |
    #            ---------------------------------
    #  size     | 37  |   ?    |  1  |     ?      |
    #            ---------------------------------

    # parse token_serial and user identification

    serial_user_data = plaintext[5+32:].split(b'\x00')
    serial = serial_user_data[0].decode('utf8')
    user_login = serial_user_data[1].decode('utf8')

    # ----------------------------------------------------------------------- --

    # check serial / user login max length

    if len(serial) > 63:
        raise ParameterError('Malformed pairing response for type QrToken:'
                             'Serial too long')

    if len(user_login) > 255:
        raise ParameterError('Malformed pairing response for type QrToken:'
                             'User login too long')

    # ----------------------------------------------------------------------- --

    return QRTokenPairingData(user_public_key,
                              user_token_id,
                              serial,
                              user_login)

#eof############################################################################

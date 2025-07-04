#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

import struct
from collections import namedtuple

from pysodium import crypto_sign_verify_detached

from linotp.lib.error import ParameterError

_PushTokenPairingData = namedtuple(
    "_PushTokenPairingData",
    ["user_public_key", "user_token_id", "serial", "user_login", "gda"],
)


class PushTokenPairingData(_PushTokenPairingData):
    """
    holds all the information of a PushToken pairing response,
    namely user_public_key, user_token_id, serial, user_login,
    gda (generic device address)
    """


def parse_and_verify_pushtoken_pairing_data(plaintext):
    """
    Parses the decrypted inner layer of a pairing response
    according to the PushToken Pairing data format

    :param plaintext: The plaintext reveceived from the decryption
        of the outer pairing response layer

    :raises ParameterError: If plaintext has a wrong format

    :raises ValueError: If signature check failed

    :return: PushTokenPairingData
    """

    # ----------------------------------------------------------------------- --

    # check format boundaries

    plaintext_min_length = 1 + 4 + 32 + 1 + 1 + 1 + 64
    if len(plaintext) < plaintext_min_length:
        msg = "Malformed pairing response for type PushToken"
        raise ParameterError(msg)

    # ----------------------------------------------------------------------- --

    # get user token id (unique id on the client)
    # (token type was already processed in
    #  decrypt_pairing_response function)

    #            ---------------------------------------------
    #  fields   | token type | user token id |   ...   | sign |
    #            ---------------------------------------------
    #  size     |     1      |       4       |    ?    |  64  |
    #            ---------------------------------------------

    user_token_id = struct.unpack("<I", plaintext[1:5])[0]

    # ----------------------------------------------------------------------- --

    # get user public key (next 32 bytes)

    #            ------------------------------------
    #  fields   | ... | user public key | ... | sign |
    #            ------------------------------------
    #  size     |  5  |       32        |  ?  |  64  |
    #            ------------------------------------

    user_public_key = plaintext[5 : 5 + 32]

    # ----------------------------------------------------------------------- --

    # get serial, user login and gda

    #            ----------------------------------------------------------
    #  fields   | ... | serial | NUL | user login | NUL | gda | NUL | sign |
    #            ----------------------------------------------------------
    #  size     | 37  |   ?    |  1  |     ?      |  1  |  ?  |  1  |  64  |
    #            ----------------------------------------------------------

    # parse token_serial and user identification

    str_parts = plaintext[5 + 32 : -64].split(b"\x00")

    # enforce format

    if len(str_parts) != 3 + 1:
        msg = "Malformed pairing response for type PushToken"
        raise ParameterError(msg)

    serial = str_parts[0].decode("utf8")
    user_login = str_parts[1].decode("utf8")
    gda = str_parts[2].decode("utf8")

    # ----------------------------------------------------------------------- --

    # get signature and verify

    signature = plaintext[-64:]
    message = plaintext[:-64]

    try:
        crypto_sign_verify_detached(signature, message, user_public_key)
    except ValueError as exx:
        # original value error is too generic
        msg = "Invalid signature for pairing response data"
        raise ValueError(msg) from exx

    # ----------------------------------------------------------------------- --

    return PushTokenPairingData(user_public_key, user_token_id, serial, user_login, gda)

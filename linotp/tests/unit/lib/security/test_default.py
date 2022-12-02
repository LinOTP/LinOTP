# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
"""
Test for the default security provider (hsm api)
"""

import pytest
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

from linotp.lib.security.default import DefaultSecurityModule, PaddingException


def test_old_unpadding():
    # test with old padding and two aes blocks
    test_vector = [
        # one aes block len
        (b"deadbeaf", b"deadbeaf\x01\x02\x00\x00\x00\x00\x00\x00"),
        (b"adeadbeaf", b"adeadbeaf\x01\x02\x00\x00\x00\x00\x00"),
        (b"aadeadbeaf", b"aadeadbeaf\x01\x02\x00\x00\x00\x00"),
        (b"aaadeadbeaf", b"aaadeadbeaf\x01\x02\x00\x00\x00"),
        (b"aaaadeadbeaf", b"aaaadeadbeaf\x01\x02\x00\x00"),
        (b"aaaaadeadbeaf", b"aaaaadeadbeaf\x01\x02\x00"),
        # two aes block len
        (
            b"aaaaaadeadbeaf",
            b"aaaaaadeadbeaf\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaadeadbeaf",
            b"aaaaaaadeadbeaf\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaaadeadbeaf",
            b"aaaaaaaadeadbeaf\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaaaadeadbeaf",
            b"aaaaaaaaadeadbeaf\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaaaaadeadbeaf",
            b"aaaaaaaaaadeadbeaf\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaaaaaadeadbeaf",
            b"aaaaaaaaaaadeadbeaf\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaaaaaaadeadbeaf",
            b"aaaaaaaaaaaadeadbeaf\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaaaaaaaadeadbeaf",
            b"aaaaaaaaaaaaadeadbeaf\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaaaaaaaaaadeadbeaf",
            b"aaaaaaaaaaaaaaadeadbeaf\x01\x02\x00\x00\x00\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaaaaaaaaaaadeadbeaf",
            b"aaaaaaaaaaaaaaaadeadbeaf\x01\x02\x00\x00\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaaaaaaaaaaaadeadbeaf",
            b"aaaaaaaaaaaaaaaaadeadbeaf\x01\x02\x00\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaaaaaaaaaaaaadeadbeaf",
            b"aaaaaaaaaaaaaaaaaadeadbeaf\x01\x02\x00\x00\x00\x00",
        ),
        (
            b"aaaaaaaaaaaaaaaaaaadeadbeaf",
            b"aaaaaaaaaaaaaaaaaaadeadbeaf\x01\x02\x00\x00\x00",
        ),
        (
            b"aaaaaaaaaaaaaaaaaaaadeadbeaf",
            b"aaaaaaaaaaaaaaaaaaaadeadbeaf\x01\x02\x00\x00",
        ),
        (
            b"aaaaaaaaaaaaaaaaaaaaadeadbeaf",
            b"aaaaaaaaaaaaaaaaaaaaadeadbeaf\x01\x02\x00",
        ),
    ]
    for unpadded_data, padded_data in test_vector:
        unpad_data = DefaultSecurityModule.unpadd_data(padded_data)
        assert unpadded_data == unpad_data


def test_std_pad():
    # small test as we use the pkcs7 padding from the std lib

    pkcs7_padded_data = [
        (b"deadbeaf", b"deadbeaf\x08\x08\x08\x08\x08\x08\x08\x08"),
    ]
    for unpadded_data, padded_data in pkcs7_padded_data:
        unpad_data = DefaultSecurityModule.unpadd_data(padded_data)
        assert unpadded_data == unpad_data


def test_padding_from_29():  #
    test_vector = [
        (
            b"7b2022534d54505f534552564552223a226d61696c2e6c6f7564"
            + b"79692e6465222c2022534d54505f55534552223a22736d747040"
            + b"6c6f756479692e6465222c2022534d54505f50415353574f5244"
            + b"223a225465737431323321222c2022454d41494c5f46524f4d22"
            + b"3a226c696e6f7470406c6f756479692e6465222c2022454d4149"
            + b"4c5f5355424a454354223a22596f7572204f5450227d",
            b"7b2022534d54505f534552564552223a226d61696c2e6c6f7564"
            + b"79692e6465222c2022534d54505f55534552223a22736d747040"
            + b"6c6f756479692e6465222c2022534d54505f50415353574f5244"
            + b"223a225465737431323321222c2022454d41494c5f46524f4d22"
            + b"3a226c696e6f7470406c6f756479692e6465222c2022454d4149"
            + b"4c5f5355424a454354223a22596f7572204f5450227d"
            + b"\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00",
        )
    ]

    for unpadded_data, padded_data in test_vector:
        unpad_data = DefaultSecurityModule.unpadd_data(padded_data)
        assert unpadded_data == unpad_data


def test_bad_data_in_old_padding():
    """test with bad data

    we can detect 3 cases:
        - data is to short - not multiple of AES.block_size
        - data does not contain a \x01\x02
        - after the \x01\x02 not all bytes are '\x00'
    """
    test_vector = [
        # last byte is not an b"\x00"
        b"adeadbeaf\x01\x02\x00\x00\x00x",
        # too short
        b"adeadbeaf\x01\x02\x00\x00\x00\x00",
        # no \x01\x02
        b"aadeadbeaf\x01\x01\x00\x00\x00\x00",
        # after \x01\x02 not all bytes are '\x00'
        b"adeadbeaf\x01\x02\x00\x00\x01\x00\x00",
    ]

    for padded_data in test_vector:
        with pytest.raises(PaddingException) as ex:
            DefaultSecurityModule.unpadd_data(padded_data)

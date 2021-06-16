# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#
#    This file is part of LinOTP userid resolvers.
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
This module implements the encapsulation of encrypted data which
for example are used in config entries
"""

from linotp.lib.crypto.utils import decryptPassword, encryptPassword


class EncryptedData(str):
    """
    preserve encrypted data throughout the LinOTP config handling
    to support late decryption
    """

    def __init__(self, encrypted_str):
        """constructor"""
        self._encrypted_str = encrypted_str

    def __new__(cls, encrypted_str):
        return str.__new__(cls, encrypted_str)

    def get_unencrypted(self) -> str:
        """return the decrypted data"""
        return decryptPassword(self._encrypted_str).decode("utf-8")

    @staticmethod
    def from_unencrypted(value: str) -> "EncryptedData":
        """
        to create an EncrytedData obejct from a plaintext password
        for the encryption it is required to have the value encoded as utf-8

        :param value: value is a unicode string
        :return: new EncrytedData object
        """
        crypted_value = encryptPassword(value.encode("utf-8"))
        return EncryptedData(crypted_value)

    def __str__(self):
        """
        provide the string repesentation, which is the encrypted data
        """
        return self._encrypted_str

    def __repr__(self):
        """for log entries and exceptions the repr representation is used"""
        return "XXXXXX"

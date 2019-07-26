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
'''
Declare the SecretObject to encapsulate security aspects
'''

import hmac
import logging
import struct
import base64
import binascii
import os
import stat
import json
import sys
import ctypes
import linotp

from crypt import crypt as libcrypt

from pysodium import crypto_scalarmult_curve25519 as calc_dh

from Cryptodome.Cipher import AES

from linotp.lib.crypto.utils import libcrypt_password
from linotp.lib.crypto.utils import get_hashalgo_from_description
from linotp.lib.crypto.utils import hash_digest
from linotp.lib.crypto.utils import hmac_digest
from linotp.lib.crypto.utils import encryptPin
from linotp.lib.crypto.utils import decryptPin
from linotp.lib.crypto.utils import encrypt
from linotp.lib.crypto.utils import decrypt
from linotp.lib.crypto.utils import zerome
from linotp.lib.crypto.utils import geturandom
from linotp.lib.crypto.utils import get_dh_secret_key


# for the hmac algo, we have to check the python version
(python_major, python_minor, _, _, _,) = sys.version_info

log = logging.getLogger(__name__)


class SecretObj(object):
    def __init__(self, val, iv, preserve=True, hsm=None):
        self.val = val
        self.iv = iv
        self.bkey = None
        self.preserve = preserve
        self.hsm = hsm

    def getKey(self):
        log.debug('Warning: Requesting secret key as plaintext.')
        return decrypt(self.val, self.iv, hsm=self.hsm)

    def calc_dh(self, partition, data):
        """
        encapsulate the Diffi Helmann calculation

        as the server secret key is a sensitive data, we try to encapsulate
        it and care for the cleanup

        :param partition: the id of the server secret key
        :param :
        """
        server_secret_key = get_dh_secret_key(partition)
        hmac_secret = calc_dh(server_secret_key, data)

        zerome(server_secret_key)

        return hmac_secret

    def getPin(self):
        return decrypt(self.val, self.iv, hsm=self.hsm)

    def compare(self, key):
        bhOtpKey = binascii.unhexlify(key)
        enc_otp_key = encrypt(bhOtpKey, self.iv, hsm=self.hsm)
        otpKeyEnc = binascii.hexlify(enc_otp_key)

        return (otpKeyEnc == self.val)

    def compare_password(self, password):
        '''
        compare the password of the password token

        the password token contains the unix hashed (hmac256) password format
        and is using the standard libcryp password hash compare. the iv is used
        as indicator for the new password format, which is :1:

        - legacy -
        the seed for some tokens contains the encrypted password
        insetead of decrypting the password and running the comparison,
        the new otp will be encrypted as well.

        :param password: the password - for the password token this is the
                         to be compared password

        :return: boolean
        '''

        if self.iv == ':1:':

            crypted_password = libcrypt_password(password, self.val)

            # position independend string comparison

            result = True
            for tup1, tup2 in zip(crypted_password, self.val):
                result = result and (tup1 == tup2)

            return result

        # the legacy comparison: compare the ecrypted password

        enc_otp_key = encrypt(password, self.iv, hsm=self.hsm)

        return binascii.hexlify(enc_otp_key) == binascii.hexlify(self.val)

    def hmac_digest(self, data_input, hash_algo=None, bkey=None):

        b_key = bkey

        if not bkey:
            self._setupKey_()
            b_key = self.bkey

        if (python_major, python_minor) > (2, 6):
            data = data_input
        else:
            data = str(data_input)

        if not hash_algo:
            hash_algo = get_hashalgo_from_description('sha1')

        h_digest = hmac_digest(bkey=b_key, data_input=data,
                               hsm=self.hsm, hash_algo=hash_algo)

        if not bkey:
            self._clearKey_(preserve=self.preserve)

        return h_digest

    def aes_decrypt(self, data_input):
        '''
        support inplace aes decryption for the yubikey

        :param data_input: data, that should be decrypted
        :return: the decrypted data
        '''
        self._setupKey_()
        aes = AES.new(self.bkey, AES.MODE_ECB)
        msg_bin = aes.decrypt(data_input)
        self._clearKey_(preserve=self.preserve)
        return msg_bin

    @staticmethod
    def encrypt(seed, iv=None, hsm=None):
        if not iv:
            iv = geturandom(16)
        enc_seed = encrypt(seed, iv, hsm=hsm)
        return iv, enc_seed

    @staticmethod
    def decrypt(enc_seed, iv=None, hsm=None):
        dec_seed = decrypt(enc_seed, iv=iv, hsm=hsm)
        return dec_seed

    @staticmethod
    def hash_pin(pin, iv=None, hsm=None):
        if not iv:
            iv = geturandom(16)
        hashed_pin = hash_digest(pin, iv, hsm=hsm)
        return iv, hashed_pin

    @staticmethod
    def encrypt_pin(pin, iv=None, hsm=None):
        """
        returns a concatenated 'iv:crypt'
        """
        if not iv:
            iv = geturandom(16)
        enc_pin = encryptPin(pin, iv=iv, hsm=hsm)
        return enc_pin

    @staticmethod
    def decrypt_pin(pin, hsm=None):
        dec_pin = decryptPin(pin, hsm=hsm)
        return dec_pin

    def encryptPin(self):
        self._setupKey_()
        res = encryptPin(self.bkey)
        self._clearKey_(preserve=self.preserve)
        return res

    def _setupKey_(self):
        if not hasattr(self, 'bkey'):
            self.bkey = None

        if self.bkey is None:
            akey = decrypt(self.val, self.iv, hsm=self.hsm)
            self.bkey = binascii.unhexlify(akey)
            zerome(akey)
            del akey

    def _clearKey_(self, preserve=False):
        if preserve is False:

            if not hasattr(self, 'bkey'):
                self.bkey = None

            if self.bkey is not None:
                zerome(self.bkey)
                del self.bkey

    def __del__(self):
        self._clearKey_()

    def __enter__(self):
        self._clearKey_()

    def __exit__(self, type, value, traceback):
        self._clearKey_()

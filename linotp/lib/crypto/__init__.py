# -*- coding: utf-8 -*-
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
from linotp.lib.crypto.utils import compare

"""
Declare the SecretObject to encapsulate security aspects
"""

import binascii
import logging

from Cryptodome.Cipher import AES
from pysodium import crypto_scalarmult_curve25519 as calc_dh

from linotp.lib.crypto import utils

log = logging.getLogger(__name__)


class SecretObj(object):
    """
    High level interface to security operations

    This provides high level security operations without
    needing access to the secure data

    This is to be used by token implementations and
    classes that need encrypted data such as the
    database fields

    The encryption operations themselves are realised
    using a SecurityModule (such as HSM, PKCS11)

    The class implementation ensures that secret keys
    are not left around in memory after an operation
    has been carried out.

    It is possible to use this in two modes: With HSM,
    where operations are passed to the HSM, and without
    where a potentially degraded implementation is used.
    This is to provide the functionality during startup,
    before the HSM is ready.
    """

    def __init__(self, val, iv, preserve=True, hsm=None):
        self.val = val
        self.iv = iv
        self.bkey = None
        self.preserve = preserve
        self.hsm = hsm

    def getKey(self):
        log.debug("Warning: Requesting secret key as plaintext.")
        return utils.decrypt(self.val, self.iv, hsm=self.hsm)

    def calc_dh(self, partition, data):
        """
        encapsulate the Diffi Helmann calculation

        as the server secret key is a sensitive data, we try to encapsulate
        it and care for the cleanup

        :param partition: the id of the server secret key
        :param :
        """
        server_secret_key = utils.get_dh_secret_key(partition)
        hmac_secret = calc_dh(server_secret_key, data)

        utils.zerome(server_secret_key)

        return hmac_secret

    def compare(self, key):
        bhOtpKey = binascii.unhexlify(key)
        enc_otp_key = utils.encrypt(bhOtpKey, self.iv, hsm=self.hsm)
        otpKeyEnc = binascii.hexlify(enc_otp_key)

        return otpKeyEnc == self.val

    def compare_password(self, password):
        """
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
        """

        if self.iv == b":1:":
            return utils.compare_password(password, self.val.decode("utf-8"))

        # the legacy comparison: compare the ecrypted password

        enc_otp_key = utils.encrypt(password, self.iv, hsm=self.hsm)

        return compare(
            binascii.hexlify(enc_otp_key), binascii.hexlify(self.val)
        )

    def hmac_digest(self, data_input, hash_algo=None, bkey=None):
        b_key = bkey

        if not bkey:
            b_key = self._setupKey_()

        data = data_input

        if not hash_algo:
            hash_algo = utils.get_hashalgo_from_description("sha1")

        h_digest = utils.hmac_digest(
            bkey=b_key, data_input=data, hsm=self.hsm, hash_algo=hash_algo
        )

        if not bkey:
            self._clearKey_(preserve=self.preserve)

        return h_digest

    def aes_decrypt(self, data_input):
        """
        support inplace aes decryption for the yubikey

        :param data_input: data, that should be decrypted
        :return: the decrypted data
        """
        self._setupKey_()
        aes = AES.new(self.bkey, AES.MODE_ECB)
        msg_bin = aes.decrypt(data_input)
        self._clearKey_(preserve=self.preserve)
        return msg_bin

    @staticmethod
    def encrypt(seed: str, iv=None, hsm=None):
        if not iv:
            iv = utils.geturandom(16)
        enc_seed = utils.encrypt(seed, iv, hsm=hsm)
        return iv, enc_seed

    @staticmethod
    def decrypt(enc_seed, iv=None, hsm=None):
        dec_seed = utils.decrypt(enc_seed, iv=iv, hsm=hsm)
        return dec_seed

    @staticmethod
    def hash_pin(pin):
        """
        hash a given pin

        :param pin:
        :return: a concatenated 'iv:hashed_pin'
        """

        iv = utils.geturandom(16)
        hashed_pin = utils.hash_digest(pin.encode("utf-8"), iv)
        return iv, hashed_pin

    @staticmethod
    def check_hashed_pin(pin: str, hashed_pin: bytes, iv: bytes) -> bool:
        """
        check a hashed against a given pin

        :param hashed_pin: hex binary
        :param iv: hex binary iv from former decryption step
        :param pin: string
        :return: boolean
        """

        hash_pin = utils.hash_digest(pin.encode("utf-8"), iv)

        # TODO: position independend compare
        if hashed_pin == hash_pin:
            return True

        return False

    @staticmethod
    def encrypt_pin(pin: str):
        """
        encrypt a given pin

        :param pin:
        :return: a concatenated 'iv:crypt'
        """

        iv = utils.geturandom(16)
        enc_pin = utils.encryptPin(pin.encode("utf-8"), iv=iv)

        return enc_pin

    @staticmethod
    def check_encrypted_pin(pin: str, encrypted_pin: bytes, iv: bytes) -> bool:
        """
        check an encrypted against a given pin

        :param encrypted_pin: hex binary
        :param iv: hex binary iv from former decryption step
        :param pin: string
        :return: boolean
        """

        crypted_pin = utils.encryptPin(pin.encode("utf-8"), iv)

        # TODO: position independend compare
        if encrypted_pin == crypted_pin.encode("utf-8"):
            return True

        return False

    @staticmethod
    def decrypt_pin(pin, hsm=None):
        dec_pin = utils.decryptPin(pin, hsm=hsm)
        return dec_pin

    def encryptPin(self):
        self._setupKey_()
        res = utils.encryptPin(self.bkey)
        self._clearKey_(preserve=self.preserve)
        return res

    def _setupKey_(self):
        if not hasattr(self, "bkey"):
            self.bkey = None

        if self.bkey is None:
            self.bkey = binascii.unhexlify(
                self.decrypt(self.val, self.iv, hsm=self.hsm)
            )

        return self.bkey

    def _clearKey_(self, preserve=False):
        if preserve is False:
            if not hasattr(self, "bkey"):
                self.bkey = None

            if self.bkey is not None:
                utils.zerome(self.bkey)
                del self.bkey

    def __del__(self):
        self._clearKey_()

    def __enter__(self):
        self._clearKey_()

    def __exit__(self, type, value, traceback):
        self._clearKey_()

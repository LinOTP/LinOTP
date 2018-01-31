# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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
""" contains the hsm migration handler"""

from Cryptodome.Protocol.KDF import PBKDF2

import hmac
import binascii
import random  # for test id genretator using random.choice
import os
from hashlib import sha256


from Cryptodome.Cipher import AES


from linotp.model import Token as model_token
from linotp.model import Config as model_config

from linotp.lib.config import getFromConfig
from linotp.lib.config.db_api import _storeConfigDB

from linotp.lib.crypto import SecretObj
from linotp.lib.context import request_context as context

import linotp.model
Session = linotp.model.Session


class DecryptionError(Exception):
    pass


class MigrationHandler(object):
    """
    the migration handler supports the migration of encryted data
    like the token seed or pin of the encrypted config entries, that
    contain sensitive data like password
    """

    def __init__(self):
        """
        the Migration hanlder relies on a crypto handler, which
        encrypts or decryptes data.
        The setup of the cryptohandler is delayed, as at startup, might
        not all data be available
        """
        self.salt = None
        self.crypter = None
        self.hsm = context.get('hsm')

    def setup(self, passphrase, salt=None):
        """
        setup the MigtaionHandler - or more precise the cytpto handler, which
        is a MigrationHandler member.

        :param passphrase: enc + decryption key is derived from the passphrase
        :param salt: optional - if not given, a new one is generated

        :return: the salt, as binary
        """
        if salt:
            self.salt = salt

        if not self.salt:
            self.salt = os.urandom(AES.block_size)

        self.crypter = Crypter(passphrase, self.salt)
        return self.salt

    def calculate_mac(self, data):
        """
        helper method - to return a mac from given data

        :param data: the input data for the mac calculation
        :return: the mac as binary
        """
        return self.crypter.mac(data)

    def get_config_items(self):
        """
        iterator function, to return a config entry in the migration format

        it reads all config entries from the config table, which have the type
        password. The decrypted value is taken from the linotp config

        :return: dictionary with the config entry: key, type, description
                 and the value, which is a dict with the encryption relevant
                 data like: encrypted_data, iv, mac
        """

        config_entries = Session.query(model_config).\
                         filter(model_config.Type == 'password').all()
        for entry in config_entries:

            key = 'enc%s' % entry.Key
            value = getFromConfig(key)

            # calculate encryption and add mac from mac_data
            enc_value = self.crypter.encrypt(input_data=value,
                                             just_mac=key + entry.Value)

            config_item = {
                "Key": entry.Key,
                "Value": enc_value,
                "Type": entry.Type,
                "Description": entry.Description
            }

            yield config_item

    def set_config_entry(self, config_entry):
        """
        set the config entry - using the standard way, so that the new value
        will be encrypted using the new encryption key and potetialy as well an
        new iv.

        before storing the new entry, the old value in its encryted form is
        read. The


        :param config_entry: the config entry, as a dict
        :return: - nothing -
        """

        key = config_entry['Key']
        typ = config_entry['Type']
        desc = config_entry['Description']
        if desc == 'None':
            desc = None

        config_entries = Session.query(model_config).\
                         filter(model_config.Key == key).all()
        entry = config_entries[0]

        # decypt the real value
        enc_value = config_entry['Value']
        value = self.crypter.decrypt(enc_value,
                                     just_mac='enc%s' % key + entry.Value)

        _storeConfigDB(key, value, typ=typ, desc=desc)

    def get_token_data(self):
        """
        get all tokens
        """
        tokens = Session.query(model_token).all()

        for token in tokens:
            token_data = {}
            serial = token.LinOtpTokenSerialnumber
            token_data['Serial'] = serial

            if token.isPinEncrypted():
                iv, enc_pin = token.get_encrypted_pin()
                pin = SecretObj.decrypt_pin(enc_pin, hsm=self.hsm)
                just_mac = serial + token.LinOtpPinHash
                enc_value = self.crypter.encrypt(input_data=pin,
                                                 just_mac=just_mac)
                token_data['TokenPin'] = enc_value

            # the userpin is used in motp and ocra/ocra2 token
            if token.LinOtpTokenPinUser:
                key, iv = token.getUserPin()
                user_pin = SecretObj.decrypt(key, iv, hsm=self.hsm)
                just_mac = serial + token.LinOtpTokenPinUser
                enc_value = self.crypter.encrypt(input_data=user_pin,
                                                 just_mac=just_mac)
                token_data['TokenUserPin'] = enc_value

            # then we retrieve as well the original value,
            # to identify changes
            encKey = token.LinOtpKeyEnc

            key, iv = token.get_encrypted_seed()
            secObj = SecretObj(key, iv, hsm=self.hsm)
            seed = secObj.getKey()
            enc_value = self.crypter.encrypt(input_data=seed,
                                             just_mac=serial + encKey)
            token_data['TokenSeed'] = enc_value
            # next we look for tokens, where the pin is encrypted
            yield token_data

    def set_token_data(self, token_data):

        serial = token_data["Serial"]
        tokens = Session.query(model_token).\
            filter(model_token.LinOtpTokenSerialnumber == serial).all()
        token = tokens[0]

        if 'TokenPin' in token_data:

            enc_pin = token_data['TokenPin']

            token_pin = self.crypter.decrypt(
                                    enc_pin,
                                    just_mac=serial + token.LinOtpPinHash)
            # prove, we can write
            enc_pin = SecretObj.encrypt_pin(token_pin)
            iv = enc_pin.split(':')[0]
            token.set_encrypted_pin(enc_pin, binascii.unhexlify(iv))

        if 'TokenUserPin' in token_data:
            token_enc_user_pin = token_data['TokenUserPin']

            user_pin = self.crypter.decrypt(
                                token_enc_user_pin,
                                just_mac=serial + token.LinOtpTokenPinUser)

            # prove, we can write
            iv, enc_user_pin = SecretObj.encrypt(user_pin, hsm=self.hsm)
            token.setUserPin(enc_user_pin, iv)

        # we put the current crypted seed in the mac to check if
        # something changed in meantime
        encKey = token.LinOtpKeyEnc
        enc_seed = token_data['TokenSeed']
        token_seed = self.crypter.decrypt(enc_seed,
                                          just_mac=serial + encKey)

        # the encryption of the token seed is not part of the model anymore
        iv, enc_token_seed = SecretObj.encrypt(token_seed)

        token.set_encrypted_seed(enc_token_seed, iv,
                                 reset_failcount=False,
                                 reset_counter=False)


class Crypter(object):

    @staticmethod
    def hmac_sha256(secret, msg):
        hmac_obj = hmac.new(secret, msg=msg, digestmod=sha256)
        val = hmac_obj.digest()
        return val

    def mac(self, *messages):
        """
        calculate the mac independend of the type
        """
        mac_message = ""
        for message in messages:
            if type(message) == str:
                mac_message += message
            elif type(message) == unicode:
                mac_message += message.encode('utf-8')

        return Crypter.hmac_sha256(self.mac_key, mac_message)

    def __init__(self, password, salt):
        """
        derive the encryption key, the mac signing key and the iv
        from the passphrase and salt

        :param password: the inital passphrase
        :param salt: the rainbow defending salt
        :return: - nothing -
        """

        master_key = PBKDF2(password=password, salt=salt, dkLen=32,
                            count=65432, prf=Crypter.hmac_sha256)

        U1 = sha256(master_key).digest()
        U2 = sha256(U1).digest()
        self.enc_key = U1[:16]
        self.mac_key = U2[:16]

    def encrypt(self, input_data, just_mac=""):
        """
        encrypt data

        :param input_data: any data as input
        :return: dictionary with hexlified iv and crypted_data
        """
        # generate new iv
        iv = os.urandom(AES.block_size)

        # init cipher
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)

        # encrypt data
        crypted_data = cipher.encrypt(Crypter.pad(input_data))

        # mac encrypted data plus additional 'just_mac' data
        # mac = self.mac("%r%r%r" % (iv, crypted_data, just_mac))
        mac = self.mac(iv, crypted_data, just_mac)

        return {"iv": binascii.hexlify(iv),
                "crypted_data": binascii.hexlify(crypted_data),
                'mac': binascii.hexlify(mac)
                }

    def decrypt(self, encrypted_data, just_mac=""):
        """
        decrypt the stored data

        :param encrypted_data: the hexlified string with (iv:enc_data)
        :return: decrypted data
        """
        iv = binascii.unhexlify(encrypted_data["iv"])
        crypted_data = binascii.unhexlify(encrypted_data["crypted_data"])

        # compare the original mac with the new calculated one
        v_mac = self.mac(iv, crypted_data, just_mac)

        if encrypted_data["mac"] != binascii.hexlify(v_mac):
            raise DecryptionError("Data mismatch detected!")

        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)

        # return decrypt, unpadded data
        return Crypter.unpad(cipher.decrypt(crypted_data))

    @staticmethod
    def unpad(output_data):
        """
            pkcs7 unpadding:
            the last byte value is the number of bytes to subtract
        """
        padlen = ord(output_data[-1:])
        return output_data[:-padlen]

    @staticmethod
    def pad(input_data):
        """
            pkcs7 padding:
            the value of the last byte is the pad lenght
            !and zero is not allowed! we take a full block instead
        """
        padLength = AES.block_size - (len(input_data) % AES.block_size)
        return input_data + chr(padLength) * padLength


# eof #

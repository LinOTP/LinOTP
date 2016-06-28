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
"""default SecurityModules which takes the enc keys from a file"""


import logging
import binascii
import os

from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC
from Cryptodome.Hash import SHA as SHA1
from Cryptodome.Hash import SHA256



from linotp.lib.crypt import zerome
from linotp.lib.security import SecurityModule


TOKEN_KEY = 0
CONFIG_KEY = 1
VALUE_KEY = 2
DEFAULT_KEY = 2


log = logging.getLogger(__name__)


class DefaultSecurityModule(SecurityModule):

    def __init__(self, config=None):
        '''
        initialsation of the security module

        :param config:  contains the configuration definition
        :type  config:  - dict -

        :return -
        '''

        self.name = "Default"
        self.config = config
        self.crypted = False
        self.is_ready = True
        self._id = binascii.hexlify(os.urandom(3))

        if 'crypted' in config:
            crypt = config.get('crypted').lower()
            if crypt == 'true':
                self.crypted = True
                self.is_ready = False

        if not 'file' in config:
            log.error("[getSecret] no secret file defined. A parameter "
                      "linotpSecretFile is missing in your linotp.ini.")
            raise Exception("no secret file defined: linotpSecretFile!")

        self.secFile = config.get('file')
        self.secrets = {}

        return

    def isReady(self):
        '''
        provides the status, if the security module is fully initializes
        this is required especially for the runtime confi like set password ++

        :return:  status, if the module is fully operational
        :rtype:   boolean

        '''
        return self.is_ready

    def getSecret(self, id=0):
        '''
        internal function, which acceses the key in the defined slot

        :param id: slot id of the key array
        :type  id: int - slotId

        :return: key or secret
        :rtype:  binary string

        '''
        log.debug('getSecret()')
        id = int(id)

        if self.crypted:
            if id in self.secrets:
                return self.secrets.get(id)

        secret = ''
        try:
                f = open(self.secFile)
                for _i in range(0, id + 1):
                    secret = f.read(32)
                f.close()
                if not secret:
                    # secret = setupKeyFile(secFile, id+1)
                    raise Exception("No secret key defined for index: %s !\n"
                                    "Please extend your %s"" !"
                                     % (str(id), self.secFile))
        except Exception as exx:
            raise Exception("Exception: %r" % exx)

        if self.crypted:
            self.secrets[id] = secret

        return secret

    def setup_module(self, param):
        '''
        callback, which is called during the runtime to
        initialze the security module

        :param params: all parameters, which are provided by the http request
        :type  params: dict

        :return: -

        '''
        if self.crypted is False:
            return
        if not 'password' in param:
            raise Exception("missing password")

        # if we have a crypted file and a password, we take all keys
        # from the file and put them in a hash
        # #
        # After this we do not require the password anymore

        handles = ['pinHandle', 'passHandle', 'valueHandle', 'defaultHandle']
        for handle in handles:
            self.getSecret(self.config.get(handle, '0'))

        self.is_ready = True
        return

    # the real interfaces: random, encrypt, decrypt '''
    def random(self, len=32):
        '''
        security module methods: random

        :param len: length of the random byte array
        :type  len: int

        :return: random bytes
        :rtype:  byte string
        '''

        log.debug('random()')
        return os.urandom(len)

    def encrypt(self, data, iv, id=0):
        '''
        security module methods: encrypt

        :param data: the to be encrypted data
        :type  data:byte string

        :param iv: initialisation vector (salt)
        :type  iv: random bytes

        :param  id: slot of the key array
        :type   id: int - slotid

        :return: encrypted data
        :rtype:  byte string
        '''

        log.debug('encrypt()')

        if self.is_ready is False:
            raise Exception('setup of security module incomplete')

        key = self.getSecret(id)
        # convert input to ascii, so we can securely append bin data
        input = binascii.b2a_hex(data)
        input += '\x01\x02'
        padding = (16 - len(input) % 16) % 16
        input += padding * "\0"
        aes = AES.new(key, AES.MODE_CBC, iv)

        res = aes.encrypt(input)

        if self.crypted is False:
            zerome(key)
            del key
        return res

    def decrypt(self, input, iv, id=0):
        '''
        security module methods: decrypt

        :param data: the to be decrypted data
        :type  data:byte string

        :param iv: initialisation vector (salt)
        :type  iv: random bytes

        :param  id: slot of the key array
        :type   id: int

        :return: decrypted data
        :rtype:  byte string
        '''

        log.debug('decrypt()')

        if self.is_ready is False:
            raise Exception('setup of security module incomplete')

        key = self.getSecret(id)
        aes = AES.new(key, AES.MODE_CBC, iv)
        output = aes.decrypt(input)

        eof = len(output) - 1
        if eof == -1:
            raise Exception('invalid encoded secret!')

        while output[eof] == '\0':
            eof -= 1

        if output[eof-1:eof+1] != '\x01\x02':
            raise Exception('invalid encoded secret!')

        # convert output from ascii, back to bin data
        data = binascii.a2b_hex(output[:eof-1])

        if self.crypted is False:
            zerome(key)
            del key

        return data

    def decryptPassword(self, cryptPass):
        '''
        dedicated security module methods: decryptPassword
        which used one slot id to decryt a string

        :param cryptPassword: the crypted password -
                              leading iv, seperated by the ':'
        :type cryptPassword: byte string

        :return: decrypted data
        :rtype:  byte string
        '''

        return self._decryptValue(cryptPass, CONFIG_KEY)

    def decryptPin(self, cryptPin):
        '''
        dedicated security module methods: decryptPin
        which used one slot id to decryt a string

        :param cryptPin: the crypted pin - - leading iv, seperated by the ':'
        :type cryptPin: byte string

        :return: decrypted data
        :rtype:  byte string
        '''

        return self._decryptValue(cryptPin, TOKEN_KEY)

    def encryptPassword(self, password):
        '''
        dedicated security module methods: encryptPassword
        which used one slot id to encrypt a string

        :param password: the to be encrypted password
        :type password: byte string

        :return: encrypted data - leading iv, seperated by the ':'
        :rtype:  byte string
        '''
        return self._encryptValue(password, CONFIG_KEY)

    def encryptPin(self, pin, iv=None):
        '''
        dedicated security module methods: encryptPin
        which used one slot id to encrypt a string

        :param pin: the to be encrypted pin
        :type pin: byte string

        :param iv: initialisation vector (optional)
        :type iv: buffer (20 bytes random)

        :return: encrypted data - leading iv, seperated by the ':'
        :rtype:  byte string
        '''
        return self._encryptValue(pin, TOKEN_KEY, iv=iv)

    # base methods for pin and password
    def _encryptValue(self, value, keyNum, iv=None):
        '''
        _encryptValue - base method to encrypt a value
        - uses one slot id to encrypt a string
        retrurns as string with leading iv, seperated by ':'

        :param value: the to be encrypted value
        :type value: byte string

        :param  keyNum: slot of the key array
        :type   keyNum: int

        :param iv: initialisation vector (optional)
        :type iv: buffer (20 bytes random)

        :return: encrypted data with leading iv and sepeartor ':'
        :rtype:  byte string
        '''
        if not iv:
            iv = self.random(16)
        v = self.encrypt(value, iv, keyNum)

        value = binascii.hexlify(iv) + ':' + binascii.hexlify(v)
        return value

    def _decryptValue(self, cryptValue, keyNum):
        '''
        _decryptValue - base method to decrypt a value
        - used one slot id to encrypt a string with
          leading iv, seperated by ':'

        :param cryptValue: the to be encrypted value
        :type cryptValue: byte string

        :param  keyNum: slot of the key array
        :type   keyNum: int

        :return: decrypted data
        :rtype:  byte string
        '''
        # split at ":"
        pos = cryptValue.find(':')
        bIV = cryptValue[:pos]
        bData = cryptValue[pos + 1:len(cryptValue)]

        iv = binascii.unhexlify(bIV)
        data = binascii.unhexlify(bData)

        password = self.decrypt(data, iv, keyNum)

        return password

    def signMessage(self, message, method=None, slot_id=DEFAULT_KEY):
        """
        create the hex mac for the message -

        :param message: the original message
        :param method: the hash method - we use by default sha256
        :param slot_id: which key should be used

        :return: hex mac
        """

        sign_key = None

        if method is None:
            method = SHA256

        try:
            sign_key = self.getSecret(slot_id)
            hex_mac = HMAC.new(sign_key, message, method).hexdigest()
        finally:
            if sign_key:
                zerome(sign_key)
                del sign_key

        return hex_mac

    def verfiyMessageSignature(self, message, hex_mac, method=None,
                               slot_id=DEFAULT_KEY):
        """
        verify the hex mac is same for the message -
           the comparison is done in a constant time comparison

        :param message: the original message
        :param hex_mac: the to compared mac in hex
        :param method: the hash method - we use by default sha256
        :param slot_id: which key should be used

        :return: boolean
        """
        sign_key = None
        result = True

        if method is None:
            method = SHA256

        try:
            sign_key = self.getSecret(slot_id)
            hmac = HMAC.new(sign_key, message, method)
            sign_mac = HMAC.new(sign_key, message, method).hexdigest()

            res = 0
            # as we compare on hex, we have to multiply by 2
            digest_size = hmac.digest_size * 2

            for x, y in zip(hex_mac, sign_mac):
                res |= ord(x) ^ ord(y)

            if len(sign_mac) != digest_size:
                result = False

            if res:
                result = False

        except ValueError as err:
            log.error("Mac Comparison failed! %r", err)

        except Exception as exx:
            pass

        finally:
            if sign_key:
                zerome(sign_key)
                del sign_key

        return result


class ErrSecurityModule(DefaultSecurityModule):

        def setup_module(self, params):
            ret = DefaultSecurityModule.setup_module(self, params)
            self.is_ready = False
            return ret


#eof###########################################################################

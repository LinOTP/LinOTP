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
""" This module is used to access the YubiHSM for encrypting and
    decrypting the data

    linotp.ini:
    linotpActiveSecurityModule = yubihsm
    linotpSecurity.yubihsm.module = linotp.lib.security.yubihsm.YubiSecurityModule
    linotpSecurity.yubihsm.pinHandle =21
    linotpSecurity.yubihsm.valueHandle =22
    linotpSecurity.yubihsm.passwordHandle =23
    linotpSecurity.yubihsm.defaultHandle = 0x1111
    linotpSecurity.yubihsm.password = 14fda9321ae820aa34e57852a31b10d0
    linotpSecurity.yubihsm.device = /dev/ttyACM3


  You need to change the access rights of /dev/ttyACM?
  You could add the user "linotp" to the group "dialout"

"""

from linotp.lib.security import SecurityModule

import string
import binascii
import logging
import traceback
import pyhsm

from linotp.lib.security.provider import DEFAULT_KEY
from linotp.lib.security.provider import CONFIG_KEY
from linotp.lib.security.provider import TOKEN_KEY
from linotp.lib.security.provider import VALUE_KEY

from getopt import getopt, GetoptError
import sys
import getpass

log = logging.getLogger(__name__)


class YubiSecurityModule(SecurityModule):
    '''
    Class that handles all AES stuff
    '''

    def __init__(self, config=None):

        log.debug("[__init__] Initializing the Yubi Security Module with config %s" % config)

        if not config:
            config = {}

        self.name = "YubiHSM"
        self.is_ready = False
        self.debug = False
        self.password = config.get("password", "")
        self.device = config.get("device")

        if not self.device:
            raise Exception("No .device specified")

        self.hsm = pyhsm.base.YHSM(device=self.device, debug=self.debug)

        if self.password:
            self.login(self.password)

        # Accept invalid padding?
        config_entry = config.get('yubihsm.accept_invalid_padding', 'False')
        self.accept_invalid_padding = False
        if config_entry and config_entry.lower() == 'true':
            self.accept_invalid_padding = True

        self.handles = { CONFIG_KEY: config.get("configHandle", config.get("defaultHandle", None)),
                         TOKEN_KEY: config.get("tokenHandle", config.get("defaultHandle", None)),
                         VALUE_KEY: config.get("valueHandle", config.get("defaultHandle", None)),
                         DEFAULT_KEY: config.get("defaultHandle", None)
                        }


    def isReady(self):
        return self.is_ready

    def setup_module(self, params):
        '''
        used to set the password, if the password is not contained in the config file
        '''
        if not params.has_key('password'):
            log.error("[setup_module] missing password!")
            raise Exception("missing password")

        self.login(params.get("password"))

        self.is_ready = True
        return

    def pad(self, unpadded_str, block=16):
        """
        PKCS7 padding pads the missing bytes with the value of the number of the bytes.
        If 4 bytes are missing, this missing bytes are filled with \x04

        :param unpadded_str: The string to pad
        :type unpadded_str: str
        :param block: Block size
        :type block: int
        :returns: padded string
        :rtype: str
        """
        l_s = len(unpadded_str)
        missing_num = block - l_s % block
        missing_byte = chr(missing_num)
        padding = missing_byte * missing_num
        return unpadded_str + padding

    def unpad(self, padded_str, block=16):
        """
        This removes and checks the PKCS #7 padding.

        :param padded_str: The string to unpad
        :type padded_str: str
        :param block: Block size
        :type block: int
        :raises ValueError: If padded_str is not correctly padded a ValueError
            can be raised.
            This depends on the 'yubihsm.accept_invalid_padding' LinOTP config
            option. If set to False (default) ValueError is raised.  The reason
            why the data is sometimes incorrectly padded is because the pad()
            method delivered with LinOTP version < 2.7.1 didn't pad correctly
            when the data-length was a multiple of the block-length.
            Beware that in some cases (statistically about 0.4% of data-chunks
            whose length is a multiple of the block length) the incorrect
            padding can not be detected and incomplete data is returned.  One
            example for this last case is when the data ends with the byte
            0x01. This is recognized as legitimate padding and is removed
            before returning the data, thus removing a legitimate byte from the
            data and making it unusable.
            If you didn't upgrade from a LinOTP version before 2.7.1 (or don't
            use a YubiHSM) you will not be affected by this in any way.
            ValueError will of course also be raised if you data became corrupt
            for some other reason (e.g. disk failure) and can not be unpadded.
            In this case you should NOT set 'yubihsm.accept_invalid_padding' to
            True because your data will be unusable anyway.
        :returns: unpadded string or sometimes padded string when
            'yubihsm.accept_invalid_padding' is set to True. See above.
        :rtype: str
        """
        last_byte = padded_str[-1]
        count = ord(last_byte)
        if 0 < count <= block and padded_str[-count:] == last_byte * count:
            unpadded_str = padded_str[:-count]
            return unpadded_str
        elif self.accept_invalid_padding:
            log.warning("[unpad] Input 'padded_str' is not properly padded")
            return padded_str
        else:
            raise ValueError("Input 'padded_str' is not properly padded")

    def login(self, password=None, slotid=0):
        '''
        Open a session on the first token

        After this, we got a self.hSession
        '''
        log.debug("[login] login on slotid %i" % slotid)

        if password == None:
            log.debug("[login] using password from the config file.")
            password = self.password
        if password == None:
            log.info("[login] No password in config file. We have to wait for it beeing set.")

        try:
            if len(password) == 32:
                password = password.decode('hex')

            self.hsm.key_storage_unlock(password)
            log.debug("[login] key store unlocked")
            self.is_ready = True
        except pyhsm.exception.YHSM_Error as  e:
            log.exception("[login] Failed to unlock key store: %s" % e)


    def logout(self):
        '''
        closes the existing session
        '''
        # TODO
        pass


    def find_aes_keys(self, label="testAES", wanted=1):
        '''
        Find and AES key with the given label
        The number of keys to be found is restricted by "wanted"

        Returns
          - the number of keys and
          - the handle to the key
        '''
        pass

    def gettokeninfo(self, slotid=0):
        '''
        This returns a dictionary with the token info
        '''
        return self.hsm.info()


    def createAES(self, ks=32, label="new AES Key"):
        '''
        Creates a new AES key with the given label and the given length

        returns the hanlde
        '''
        pass

    def random(self, l=32):
        '''
        create a random value and return it
        l specifies the length of the random data to be created.
        '''
        log.debug("[random] creating %i random bytes" % l)
        return self.hsm.random(l)


    def decrypt(self, data, iv, id=0):
        '''
        decrypts the given data, using the IV and the key specified by the handle

        possible id's are:
            0
            1
            2
        '''
        handle = int(self.handles.get(id))
        log.debug("[decrypt] decrypting with handle %s" % str(handle))
        s = ""
        try:
            s = self.hsm.aes_ecb_decrypt(handle, data)
        except pyhsm.exception.YHSM_Error as  e:
            log.exception("[decrypt] Failed to decrypt data: %s" % e)

        s = self.unpad(s)
        return s



    def encrypt(self, data, iv, id=0):
        '''
        encrypts the given input data

        AES hat eine blocksize von 16 byte.
        Daher muss die data ein vielfaches von 16 sein und der IV im Falle von CBC auch 16 byte lang.
        '''
        handle = int(self.handles.get(id))
        log.debug("[encrypt] encrypting with handle %s" % str(handle))
        data = str(data)
        data = self.pad(data)
        encrypted_data = None

        try:
            encrypted_data = self.hsm.aes_ecb_encrypt(handle, data)
        except pyhsm.exception.YHSM_Error as  e:
            log.exception("[encrypt] Failed to encrypt data: %s" % str(e))

        return encrypted_data


    def _encryptValue(self, value, keyNum=2):
        '''
            _encryptValue - base method to encrypt a value
            - uses one slot id to encrypt a string
            retrurns as string with leading iv, seperated by ':'

            @param value: the to be encrypted value
            @param value: byte string

            @param  id: slot of the key array
            @type   id: int

            @return: encrypted data with leading iv and sepeartor ':'
            @rtype:  byte string
        '''
        iv = self.random(16)
        v = self.encrypt(value, iv , keyNum)

        value = binascii.hexlify(iv) + ':' + binascii.hexlify(v)
        return value

    def _decryptValue(self, cryptValue, keyNum=2):
        '''
            _decryptValue - base method to decrypt a value
            - used one slot id to encrypt a string with leading iv, seperated by ':'

            @param cryptValue: the to be encrypted value
            @param cryptValue: byte string

            @param  id: slot of the key array
            @type   id: int

            @return: decrypted data
            @rtype:  byte string
        '''
        ''' split at : '''
        pos = cryptValue.find(':')
        bIV = cryptValue[:pos]
        bData = cryptValue[pos + 1:len(cryptValue)]

        iv = binascii.unhexlify(bIV)
        data = binascii.unhexlify(bData)

        password = self.decrypt(data, iv, keyNum)

        return password


    def decryptPassword(self, cryptPass):
        '''
            dedicated security module methods: decryptPassword
            which used one slot id to decryt a string

            @param cryptPassword: the crypted password - leading iv, seperated by the ':'
            @param cryptPassword: byte string

            @return: decrypted data
            @rtype:  byte string
        '''

        return self._decryptValue(cryptPass, 0)

    def decryptPin(self, cryptPin):
        '''
            dedicated security module methods: decryptPin
            which used one slot id to decryt a string

            @param cryptPin: the crypted pin - - leading iv, seperated by the ':'
            @param cryptPin: byte string

            @return: decrypted data
            @rtype:  byte string
        '''

        return self._decryptValue(cryptPin, 1)


    def encryptPassword(self, password):
        '''
            dedicated security module methods: encryptPassword
            which used one slot id to encrypt a string

            @param password: the to be encrypted password
            @param password: byte string

            @return: encrypted data - leading iv, seperated by the ':'
            @rtype:  byte string
        '''
        return self._encryptValue(password, 0)

    def encryptPin(self, pin):
        '''
            dedicated security module methods: encryptPin
            which used one slot id to encrypt a string

            @param pin: the to be encrypted pin
            @param pin: byte string

            @return: encrypted data - leading iv, seperated by the ':'
            @rtype:  byte string
        '''
        return self._encryptValue(pin, 1)

def main():
    '''
    This module can be called to create an AES key.

    Parameters are:

        -p / --password=  The Password of the partition. Can be ommitted. Then you are asked
        -d / --device=    The device  (default /dev/ttyACM0)
        -n / --name=      The name of the AES key.
        -f / --find=      Find the AES key
        -h / --help
    '''
    try:
        opts, args = getopt(sys.argv[1:], "hp:s:n:f:",
                ["help", "password=", "slot=", "name=", "find="])

    except GetoptError:
        print "There is an error in your parameter syntax:"
        print main.__doc__
        sys.exit(1)

    password = None
    device = "/dev/ttyACM0"
    name = None
    listing = False
    label = "default"

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print main.__doc__
            sys.exit(0)
        if opt in ("-p", "--password"):
            password = str(arg)
        if opt in ("-s", "--slot"):
            slot = arg
        if opt in ("-n", "--name"):
            name = arg
        if opt in ("-f", "--find"):
            listing = True
            label = arg

    if not name and not listing:
        print "Parameter <name> required or list the AES keys."
        print main.__doc__
        sys.exit(1)

    if not password:
        password = getpass.getpass(prompt="Please enter password for slot %i:" % int(slot))

    y = YubiSecurityModule({ 'password' : '14fda9321ae820aa34e57852a31b10d0',
                             'device' : device,
                             '':""})

    y.login(password=password)
    if listing:
        pass

    else:
        pass


if __name__ == '__main__':
    main()

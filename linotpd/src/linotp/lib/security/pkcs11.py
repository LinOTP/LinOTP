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
""" This Security module (hsm) is used to access hardware security modules
    via PKCS11 for encrypting and decrypting the data

    linotp.ini:
    linotpActiveSecurityModule = lunasa
    linotpSecurity.lunasa.module = linotp.lib.security.pkcs11.Pkcs11SecurityModule
    linotpSecurity.lunasa.library = libCryptoki2_64.so
    linotpSecurity.lunasa.pinHandle =21
    linotpSecurity.lunasa.valueHandle =22
    linotpSecurity.lunasa.passwordHandle =23
    linotpSecurity.lunasa.defaultHandle =22
    linotpSecurity.lunasa.configLabel = config
    linotpSecurity.lunasa.tokenLabel = token
    linotpSecurity.lunasa.valueLabel = value
    linotpSecurity.lunasa.password = 6SNq-L9WL-SSW4-NGNL
    linotpSecurity.lunasa.slotid = 1
    linotpActiveSecurityModule = lunasa

"""

from linotp.lib.security import SecurityModule

from ctypes import *
import string
import binascii
import logging
import traceback

from linotp.lib.security.provider import DEFAULT_KEY
from linotp.lib.security.provider import CONFIG_KEY
from linotp.lib.security.provider import TOKEN_KEY
from linotp.lib.security.provider import VALUE_KEY

from Crypto.Cipher import AES as    AESCipher
from getopt import getopt, GetoptError
import sys
import getpass

log = logging.getLogger(__name__)

CKK_AES = int(0x0000001F)
CKA_CLASS = int(0x00000000)
CKO_DATA = int(0x00000000)
CKO_SECRET_KEY = int(0x00000004)
CKA_KEY_TYPE = int(0x00000100)
CKA_TOKEN = int(0x00000001)
CKA_LABEL = int(0x00000003)
CKA_ENCRYPT = int(0x00000104)
CKA_DECRYPT = int(0x00000105)
CKA_VALUE = int(0x00000011)
CKA_PRIVATE = int(0x00000002)

CKA_SENSITIVE = int(0x00000103)
CKA_VALUE_LEN = int(0x00000161)
CK_BBOOL = c_byte
CKK_AES = int(0x0000001F)
CK_OBJECT_HANDLE = c_ulong
CK_BYTE = c_char
CK_ULONG = c_ulong
CK_SLOT_ID = CK_ULONG
# AES

CKM_AES_KEY_GEN = int(0x00001080)
CKM_AES_ECB = int(0x00001081)
CKM_AES_CBC = int(0x00001082)
CKM_AES_MAC = int(0x00001083)
CKM_AES_MAC_GENERAL = int(0x00001084)
CKM_AES_CBC_PAD = int(0x00001085)
CKU_USER = 1
CKU_SO = 0

NULL = None

running_as_main = False

class CK_VERSION(Structure):
    _fields_ = [("major", c_byte),
                ("minor", c_byte),
                ]

class CK_TOKEN_INFO(Structure):
    _fields_ = [("label", c_wchar * 32),  # 0:31   Zeichen = 2byte
                ("manufacturerID", c_wchar * 32),  # 32:63
                ("model", c_wchar * 16),  # 64:79
                ("serialNumber", c_char * 16),  # 80:95
                ("flags", c_ulong),  # 96:97     4 byte
                ("ulMaxSessionCount", c_ulong),  # 98:99
                ("ulSessionCount", c_ulong),  # 100:101
                ("ulMaxRwSessionCount", c_ulong),  # 102:103
                ("ulRwSessionCount", c_ulong),  # 104:105
                ("ulMaxPinLen", c_ulong),  # 106:107
                ("ulMinPinLen", c_ulong),  # 108:109
                ("ulTotalPublicMemory", c_ulong),  # 110:111
                ("ulFreePublicMemory", c_ulong),  # 112:113
                ("ulTotalPrivateMemory", c_ulong),  # 114:115
                ("ulFreePrivateMemory", c_ulong),  # 116:117
                ("hardwareVersion", CK_VERSION),  # 118
                ("firmwareVersion", CK_VERSION),  # 119
                ("utcTime", c_char * 16),  # 120:135
                ]

class CK_ATTRIBUTE(Structure):
    _fields_ = [("type", c_ulong),
                ("pValue", c_void_p),
                ("ulValueLen", c_ulong),
                ]


class CK_MECHANISM(Structure):
    _fields_ = [ ("mechanism", c_ulong),
                 ("pParameter", c_void_p),
                 ("usParameterLen", c_ulong)
                ]

errormap = { 182:'Session exists',
                7:'Bad argument',
                19: 'Attribute value invalid',
                162: 'invalid PIN length',
                112: 'Mechanism invalid',
                224: 'Token not present',
                209: 'Template inconsistent',
                208: 'Template incomplete',
                163: 'PIN expired',
                160: 'CKR_PIN_INCORRECT',
                0x000000D0: 'TEMPLATE_INCOMPLETE',
                0x00000020: 'Data invalid',
                0x00000070: 'Mechanism invalid',
                0x00000071: 'mechanism param invalid',
                0x00000150: 'CKR_BUFFER_TOO_SMALL',
                0x00000160: 'CKR_SAVED_STATE_INVALID',
                0x00000021: 'CKR_DATA_LEN_RANGE',
                0x000000B3: "CKR_SESSION_HANDLE_INVALID",
				0x00000082: "CKR_OBJECT_HANDLE_INVALID",
                0x00000090: "CKR_OPERATION_ACTIVE",
                0x00000091: "CKR_OPERATION_NOT_INITIALIZED",
                0x000000A0: "CKR_PIN_INCORRECT",
                0x000000A1: "CKR_PIN_INVALID",
                0x000000A2: "CKR_PIN_LEN_RANGE"
                }

def pkcs11error(rv):
    return errormap.get(rv, rv)

def output(loglevel, text):
    if running_as_main:
        print "%s: %s" % (loglevel.upper(), text)
    else:
        if loglevel == "debug":
            log.debug(text)
        elif loglevel == "info":
            log.info(text)
        elif loglevel == "error":
            log.error(text)

class Pkcs11SecurityModule(SecurityModule):
    '''
    Class that handles all AES stuff
    '''

    def __init__(self, config=None):
        output("debug", "[__init__] Initializing the Pkcs11 Security Module")
        self.hSession = None
        self.is_ready = False
        self.name = "Pkcs11"
        if not config:
            config = {}
        self.password = config.get("password", "")
        self.connectedTokens = []
        library = config.get("library")
        self.slotid = int(config.get("slotid", 0))

        # Accept invalid padding?
        config_entry = config.get('pkcs11.accept_invalid_padding', 'False')
        self.accept_invalid_padding = False
        if config_entry and config_entry.lower() == 'true':
            self.accept_invalid_padding = True

        self.handles = { CONFIG_KEY: config.get("configHandle", None),
                         TOKEN_KEY: config.get("tokenHandle", None),
                         VALUE_KEY: config.get("valueHandle", None),
                         DEFAULT_KEY: config.get("defaultHandle", None)
                        }
        self.labels = { CONFIG_KEY: config.get("configLabel", None),
                        TOKEN_KEY: config.get("tokenLabel", None),
                        VALUE_KEY: config.get("valueLabel", None),
                        DEFAULT_KEY: config.get("defaultLabel", None)}

        if not library:
            raise Exception("No .library specified")
        self.pkcs11 = CDLL(library)

        self.initpkcs11()
        if self.password:
            output("debug", "[setup_module] logging in to slot %s" % str(self.slotid))
            self.login(slotid=self.slotid)



    def populate_handles(self):
        '''
        In a HA Group of LunaSAs the handle do not exist. They first need to be populated

        The Label overwrites the handles!
        '''
        for key in [ CONFIG_KEY, TOKEN_KEY, VALUE_KEY, DEFAULT_KEY ]:
            label = self.labels.get(key)
            if label:
                output("debug", "[populate_handles] get handle for label %s" % label)
                self.handles[key] = self.find_aes_keys(label)
                output("debug", "[populate_handles] handle set to %s" % self.handles.get(key))


    def isReady(self):
        return self.is_ready

    def setup_module(self, params):
        '''
        used to set the password, if the password is not contained in the config file
        '''
        if not params.has_key('password'):
            output("error", "[setup_module] missing password!")
            raise Exception("missing password")

        slotid = params.get("slotid", None)
        if slotid == None:
            slotid = self.slotid

        slotid = int(slotid)
        ''' finally initialise the login '''
        self.login(params.get("password"), slotid=slotid)

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
            This depends on the 'pkcs11.accept_invalid_padding' LinOTP config
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
            use a PKCS#11 HSM) you will not be affected by this in any way.
            ValueError will of course also be raised if you data became corrupt
            for some other reason (e.g. disk failure) and can not be unpadded.
            In this case you should NOT set 'pkcs11.accept_invalid_padding' to
            True because your data will be unusable anyway.
        :returns: unpadded string or sometimes padded string when
            'pkcs11.accept_invalid_padding' is set to True. See above.
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

    def initpkcs11(self):
        '''
        Initialize the PKCS11 library
        '''
        output("debug", "[initpkcs11]  Initialize the PKCS11 library %s" % self.pkcs11)

        self.pkcs11.C_Initialize(0)
        SlotID = c_ulong()
        nSlots = c_ulong()
        rv = self.pkcs11.C_GetSlotList(c_ulong(1), NULL, byref(nSlots))
        if rv:
            # TODO: a second call of C_GetSlotList could fetch the list of the slots
            output("error", "[initpkcs11] Failed to C_GetSlotList (%s): %s" % (str(rv), pkcs11error(rv)))
            raise Exception("etng::initpkcs11 - Failed to C_GetSlotList (%s)" % rv)
        else:
            output("debug", "[initpkcs11] number of connected tokens: %s. slotid: %s" % (nSlots.value, SlotID.value))

        if nSlots.value == 0:
            output("error", "[initpkcs11] No slots connected!")
            raise Exception("initpkcs11 - No slot connected (%s)" % nSlots.value)

        if nSlots.value > 1:
            output("info", "[initpkcs11] More than one slot connected: %s" % nSlots.value)
            #raise Exception( "initpkcs11 - There is more than one slot connected (%s)" % nSlots.value )


    def login(self, password=None, slotid=0):
        '''
        Open a session on the first token

        After this, we got a self.hSession
        '''
        output("debug", "[login] login on slotid %i" % slotid)

        if password == None:
            output("debug", "[login] using password from the config file.")
            password = self.password
        if password == None:
            output("info", "[login] No password in config file. We have to wait for it beeing set.")

        prototype = CFUNCTYPE (c_int, CK_SLOT_ID, c_int, POINTER(c_ulong), POINTER(c_ulong), POINTER(c_ulong))
        paramflags = (1, "SlotID", 0), (1, "Flags", 6), (1, "App", NULL), (1, "Notify", NULL), (2, "SessionHandle")
        opensession = prototype(("C_OpenSession", self.pkcs11), paramflags)

        self.hSession = opensession(SlotID=CK_SLOT_ID(slotid))

        output("debug", "[login] got this session: %s" % self.hSession)
        password = str(password)

        rv = self.pkcs11.C_Login(self.hSession, CKU_USER, password, len(password))
        if rv:
            output("error", "[login] Failed to login to token (%s): %s" % (str(rv), pkcs11error(rv)))
            raise Exception("etng::logintoken - Failed to C_Login (%s)" % rv)
        else:
            output("debug", "[login] login successful")
            self.is_ready = True

        self.populate_handles()

    def logout(self):
        '''
        closes the existing session
        '''
        rv = self.pkcs11.C_CloseSession(self.hSession)
        if rv:
            output("error", "[logout] Failed to close session (%s): %s" % (str(rv), pkcs11error(rv)))
            raise Exception("[logout] Failed to C_CloseSession (%s): %s" % (str(rv), pkcs11error(rv)))
        else:
            output("debug", "[logout] logout successful")


    def find_aes_keys(self, label="testAES", wanted=1):
        '''
        Find and AES key with the given label
        The number of keys to be found is restricted by "wanted"

        Returns
          - the number of keys and
          - the handle to the key
        '''
        ret_handle = 0

        klass = c_ulong(CKO_SECRET_KEY)
        keytype = c_ulong(CKK_AES)
        ck_true = c_ubyte(1)
        ck_false = c_ubyte(0)

        size = 8
        CK_TEMPLATE = CK_ATTRIBUTE * size

        template = CK_TEMPLATE(
                        CK_ATTRIBUTE(CKA_CLASS, addressof(klass), sizeof(klass)),
                        CK_ATTRIBUTE(CKA_KEY_TYPE, addressof(keytype), sizeof(keytype)),
                        CK_ATTRIBUTE(CKA_LABEL, cast(label, c_void_p), len(label)),
                        CK_ATTRIBUTE(CKA_PRIVATE, cast(addressof(ck_false), c_void_p), sizeof(ck_false)),
                        CK_ATTRIBUTE(CKA_TOKEN, cast(addressof(ck_true), c_void_p), sizeof(ck_true)),
                        CK_ATTRIBUTE(CKA_SENSITIVE, cast(addressof(ck_true), c_void_p), sizeof(ck_true)),
                        CK_ATTRIBUTE(CKA_ENCRYPT, cast(addressof(ck_true), c_void_p), sizeof(ck_true)),
                        CK_ATTRIBUTE(CKA_DECRYPT, cast(addressof(ck_true), c_void_p), sizeof(ck_true))
                        )

        template_len = c_ulong(size)

        rv = self.pkcs11.C_FindObjectsInit(self.hSession,
                                           template,
                                           template_len)
        if rv:
            raise Exception("Failed to C_FindObjectsInit (%s): %s" % (rv, pkcs11error(rv)))

        keys = []
        hKey = CK_OBJECT_HANDLE()
        ulKeyCount = c_ulong(1)

        while ulKeyCount.value > 0:

            rv = self.pkcs11.C_FindObjects(self.hSession,
                                           byref(hKey),
                                           wanted,
                                           byref(ulKeyCount));
            if rv:
                output("error", "[find_aes_keys] Failed to C_FindObjects (%s): %s" % (rv, pkcs11error(rv)))
                raise Exception("Failed to C_FindObjects (%s): %s" % (rv, pkcs11error(rv)))

            if ulKeyCount.value > 0:
                keys.append(hKey.value)
                ret_handle = int(hKey.value)

            output("debug", "[find_aes_keys] searching keys: %i: %s" % (ulKeyCount.value, hKey.value))

        rv = self.pkcs11.C_FindObjectsFinal(self.hSession);

        if rv:
            output("debug", "[find_aes_keys] Failed to C_FindObjectsFinal (%s): %s" % (rv, pkcs11error(rv)))
            raise Exception("Failed to C_FindObjectsFinal (%s): %s" % (rv, pkcs11error(rv)))

        return ret_handle

    def gettokeninfo(self, slotid=0):
        '''
        This returns a dictionary with the token info
        '''
        output("debug", "[gettokeninfo] for slot %s" % slotid)
        ti = CK_TOKEN_INFO()
        rv = self.pkcs11.C_GetTokenInfo(c_ulong(slotid), byref(ti))

        if rv:
            output("error", "[gettokeninfo] Failed to get token info (%s): %s" % (rv, pkcs11error(rv)))
            raise Exception("Failed to get token info (%s): %s" % (rv, pkcs11error(rv)))
        else:
            output("debug", "[gettokeninfo] %s" % str(ti))
        return ti

    def createAES(self, ks=32, label="new AES Key"):
        '''
        Creates a new AES key with the given label and the given length

        returns the handle
        '''
        rv = 0
        mechanism = CK_MECHANISM(CKM_AES_KEY_GEN, NULL, 0)

        keysize = c_ulong(ks)
        klass = c_ulong(CKO_SECRET_KEY)
        keytype = c_ulong(CKK_AES)
        ck_true = c_ubyte(1)
        ck_false = c_ubyte(0)
        objHandle = CK_OBJECT_HANDLE()

        size = 9
        CK_TEMPLATE = CK_ATTRIBUTE * size

        template = CK_TEMPLATE(
                        CK_ATTRIBUTE(CKA_CLASS, addressof(klass), sizeof(klass)),
                        CK_ATTRIBUTE(CKA_KEY_TYPE, addressof(keytype), sizeof(keytype)),
                        CK_ATTRIBUTE(CKA_LABEL, cast(label, c_void_p), len(label)),
                        CK_ATTRIBUTE(CKA_VALUE_LEN, addressof(keysize), sizeof(keysize)),
                        CK_ATTRIBUTE(CKA_PRIVATE, cast(addressof(ck_false), c_void_p), sizeof(ck_false)),
                        CK_ATTRIBUTE(CKA_TOKEN, cast(addressof(ck_true), c_void_p), sizeof(ck_true)),
                        CK_ATTRIBUTE(CKA_SENSITIVE, cast(addressof(ck_true), c_void_p), sizeof(ck_true)),
                        CK_ATTRIBUTE(CKA_ENCRYPT, cast(addressof(ck_true), c_void_p), sizeof(ck_true)),
                        CK_ATTRIBUTE(CKA_DECRYPT, cast(addressof(ck_true), c_void_p), sizeof(ck_true))
                        )

        template_len = c_ulong(size)

        rv = self.pkcs11.C_GenerateKey(self.hSession,
                                         byref(mechanism),
                                         template,
                                         template_len,
                                         byref(objHandle))

        if rv:
            output("error", "[createAES] Failed to C_GenerateKey (%s): %s" % (rv, pkcs11error(rv)))
            raise Exception("createAES - Failed to C_GenerateKey (%s): %s" % (rv, pkcs11error(rv)))
        else:
            output("debug", "[createAES] created key successfully: %s" % str(objHandle))

        return objHandle

    def random(self, l=32):
        '''
        create a random value and return it
        l specifies the length of the random data to be created.
        '''
        output("debug", "[random] creating %i random bytes" % l)
        key = "0" * l
        rv = self.pkcs11.C_GenerateRandom(self.hSession, key, len(key))
        if rv:
            output("error", "C_GenerateRandom failed (%s): %s" % (rv, pkcs11error(rv)))
            raise Exception("C_GenerateRandom failed (%s): %s" % (rv, pkcs11error(rv)))
        return key


    def decrypt(self, data, iv, id=0):
        '''
        decrypts the given data, using the IV and the key specified by the handle

        possible id's are:
            0
            1
            2
        '''
        handle = int(self.handles.get(id))
        output("debug", "[decrypt] decrypting with handle %s" % str(handle))
        clear = create_string_buffer(len(data))
        len_clear = c_ulong(len(clear))
        if len(iv) != 16:
            output("error", "[decrypt] Doeing aes requires an IV (block size) of 16 bytes. %i given" % len(iv))
            raise Exception("aes.decrypt: Doeing aes requires an IV (block size) of 16 bytes. %i given" % len(iv))
        mechanism = CK_MECHANISM(CKM_AES_CBC, cast(c_char_p(iv), c_void_p) , len(iv))

        rv = self.pkcs11.C_DecryptInit(self.hSession,
                                       byref(mechanism),
                                       CK_OBJECT_HANDLE(handle))
        if rv:
            output("error", "[decrypt] C_DecryptInit failed (%s): %s" % (rv, pkcs11error(rv)))
            raise Exception("C_DecryptInit failed (%s): %s" % (rv, pkcs11error(rv)))


        rv = self.pkcs11.C_Decrypt(self.hSession,
                                   data,
                                   c_ulong(len(data)),
                                   byref(clear),
                                   byref(len_clear))
        if rv:
            output("error", "[decrypt] C_Decrypt failed (%s): %s" % (rv, pkcs11error(rv)))
            raise Exception("C_Decrypt failed (%s): %s" % (rv, pkcs11error(rv)))

        s = string.join(clear, "")[:len_clear.value]
        s = self.unpad(s)
        return s



    def encrypt(self, data, iv, id=0):
        '''
        encrypts the given input data

        AES hat eine blocksize von 16 byte.
        Daher muss die data ein vielfaches von 16 sein und der IV im Falle von CBC auch 16 byte lang.
        '''
        handle = int(self.handles.get(id))
        handle = CK_OBJECT_HANDLE(handle)
        output("debug", "[encrypt] encrypting with handle %s" % str(handle))
        data = self.pad(data)

        encrypted_data = create_string_buffer(len(data))
        len_encrypted_data = c_ulong(len(encrypted_data))
        if len(iv) != 16:
            output("error", "[encrypt] Doing aes requires an IV (block size) of 16 bytes. %i given" % len(iv))
            raise Exception("PKCS11.decrypt: Doeing aes requires an IV (block size) of 16 bytes. %i given" % len(iv))

        '''
        Note:   AES_CBC hat ein 16 byte IV.
                AES_ECB hat keinen IV.
        '''
        mechanism = CK_MECHANISM(CKM_AES_CBC, cast(c_char_p(iv), c_void_p) , len(iv))

        rv = self.pkcs11.C_EncryptInit(self.hSession,
                                       byref(mechanism),
                                       handle)

        if rv:
            output("error", "[encrypt] C_EncryptInit (slot=%s, handle=%s) failed (%s): %s" % (self.slotid, handle,
                                                                                                 rv, pkcs11error(rv)))
            raise Exception("C_EncryptInit failed (%s): %s" % (rv, pkcs11error(rv)))

        data_buffer = create_string_buffer(data)
        rv = self.pkcs11.C_Encrypt(self.hSession,
                                   data_buffer,
                                   c_ulong(len(data)),
                                   byref(encrypted_data),
                                   byref(len_encrypted_data))
        if rv:
            output("error", "[encrypt] C_Encrypt (slot=%s, handle=%s) failed (%s): %s" % (self.slotid, handle,
                                                                                                 rv, pkcs11error(rv)))
            ''' no handle? '''
            self.find_aes_keys("config")
            #raise Exception("C_Encrypt failed (%s): %s" % (rv, pkcs11error(rv)))

        return encrypted_data

    def decrypt_soft(self, data, iv, key):
        '''
        Decrypt in CPU
        '''
        aes = AESCipher.new(key, AESCipher.MODE_CBC, iv)
        decrypted_data = aes.decrypt(data)
        return self.unpad(decrypted_data)


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

        -p / --password=  The Passwort of the partition. Can be ommitted. Then you are asked
        -s / --slot=      The Slot number (default 0)
        -n / --name=      The name of the AES key.
        -f / --find=      Find the AES key
        -h / --help
        -e / --encrypt=   Encrypt this data (also need slot and handle)
        -l / --label=   Specify the label of the object for encryption
    '''
    try:
        opts, args = getopt(sys.argv[1:], "hp:s:n:f:e:l:",
                ["help", "password=", "slot=", "name=", "find=", "encrypt=", "label="])

    except GetoptError:
        print "There is an error in your parameter syntax:"
        print main.__doc__
        sys.exit(1)

    password = None
    slot = 0
    name = None
    listing = False
    label = "default"
    encrypt = None
    l_handle = None

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
        if opt in ("-l", "--label"):
            l_handle = arg
        if opt in ("-e", "--encrypt"):
            encrypt = arg

    if not name and not listing and not encrypt:
        print "Parameter <name> required or list the AES keys."
        print main.__doc__
        sys.exit(1)

    if not password:
        password = getpass.getpass(prompt="Please enter password for slot %i:" % int(slot))

    config = { 'password' : password,
                'slotid' : int(slot),
                'library' : 'libCryptoki2_64.so' }
    if l_handle:
        config['defaultLabel'] = l_handle

    P11 = Pkcs11SecurityModule(config)

    if listing:
        keys = P11.find_aes_keys(label=label, wanted=100)
        print "Found these AES keys: %s" % keys
    elif encrypt:
        print "Encrypting data %s with label %s from slot %s." % (encrypt, str(l_handle), str(slot))
        #i_handle = P11.find_aes_keys(label=str(l_handle))
        #print "Found handle %s" % str(i_handle)
        #P11.handles = { DEFAULT_KEY : i_handle }
        iv = P11.random(16)
        crypttext = P11.encrypt(encrypt, iv, DEFAULT_KEY)
        print "Encrypted Text : ", binascii.hexlify(crypttext)
        plaintext = P11.decrypt(crypttext, iv, DEFAULT_KEY)
        print "Decrypted Text >>%s<< " % plaintext
    else:
        handle = P11.createAES(ks=32, label=name)
        print "Created AES key with handle %s" % str(handle)

    P11.logout()

if __name__ == '__main__':
    running_as_main = True
    main()

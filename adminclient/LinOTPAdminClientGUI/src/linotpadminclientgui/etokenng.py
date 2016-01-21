#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP admin clients.
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
""" This is the module for providing the functions
                to enroll the Aladdin eToken NG OTP
"""

from ctypes import *
import binascii
import random
import platform
import logging
import logging.handlers

CKF_RW_SESSION = 0x00000002
CKF_SERIAL_SESSION = 0x00000004
CK_SAPI_OTP_HMAC_SHA1_DEC6 = 0x00000001
CKA_SAPI_OTP_MECHANISM = int(0x80001301)
CKA_SAPI_OTP_VALUE = int(0x80001304)
CKA_SAPI_OTP_NEXT_ALLOWED = int(0x80001306)
CKA_SAPI_OTP_DURATION = int(0x80001303)
CKR_MECHANISM_INVALID = int(0x00000070)

# AES
CKK_AES = int(0x0000001F)
CKA_CLASS = int(0x00000000)
CKO_DATA = int(0x00000000)
CKO_SECRET_KEY = int(0x00000004)
CKA_KEY_TYPE = int(0x00000100)
CKA_TOKEN = int(0x00000001)
CKA_LABEL = int(0x00000003)
CKA_ENCRYPT = int(0x00000104)
CKA_VALUE = int(0x00000011)
CKA_PRIVATE = int(0x00000002)

CKU_USER		 = 1
CKU_SO			 = 0


NULL = None


import locale
import gettext
locale.setlocale(locale.LC_ALL, '')
APP_NAME = "LinOTP2"
LOCALE_DIR = "locale"

_ = gettext.gettext
gettext.bindtextdomain(APP_NAME, LOCALE_DIR)
gettext.textdomain(APP_NAME)

#typedef CK_ULONG          CK_FLAGS;

#typedef struct CK_VERSION {
#  CK_BYTE       major;  /* integer portion of version number */
#  CK_BYTE       minor;  /* 1/100ths portion of version number */
#} CK_VERSION;
class CK_VERSION(Structure):
    _fields_ = [("major", c_byte),
                ("minor", c_byte),
                ]

#/* CK_TOKEN_INFO provides information about a token */
#typedef struct CK_TOKEN_INFO {
#  /* label, manufacturerID, and model have been changed from
#   * CK_CHAR to CK_UTF8CHAR for v2.10 */
#  CK_UTF8CHAR   label[32];           /* blank padded */
#  CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
#  CK_UTF8CHAR   model[16];           /* blank padded */
#  CK_CHAR       serialNumber[16];    /* blank padded */
#  CK_FLAGS      flags;               /* see below */
#
#  /* ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount,
#   * ulRwSessionCount, ulMaxPinLen, and ulMinPinLen have all been
#   * changed from CK_USHORT to CK_ULONG for v2.0 */
#  CK_ULONG      ulMaxSessionCount;     /* max open sessions */
#  CK_ULONG      ulSessionCount;        /* sess. now open */
#  CK_ULONG      ulMaxRwSessionCount;   /* max R/W sessions */
#  CK_ULONG      ulRwSessionCount;      /* R/W sess. now open */
#  CK_ULONG      ulMaxPinLen;           /* in bytes */
#  CK_ULONG      ulMinPinLen;           /* in bytes */
#  CK_ULONG      ulTotalPublicMemory;   /* in bytes */
#  CK_ULONG      ulFreePublicMemory;    /* in bytes */
#  CK_ULONG      ulTotalPrivateMemory;  /* in bytes */
#  CK_ULONG      ulFreePrivateMemory;   /* in bytes */
#
#  /* hardwareVersion, firmwareVersion, and time are new for
#   * v2.0 */
#  CK_VERSION    hardwareVersion;       /* version of hardware */
#  CK_VERSION    firmwareVersion;       /* version of firmware */
#  CK_CHAR       utcTime[16];           /* time */
#} CK_TOKEN_INFO;
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

#  C Definition
#
#/* CK_ATTRIBUTE is a structure that includes the type, length
# * and value of an attribute */
#typedef struct CK_ATTRIBUTE {
#  CK_ATTRIBUTE_TYPE type;
#  CK_VOID_PTR       pValue;##
#
#  /* ulValueLen went from CK_USHORT to CK_ULONG for v2.0 */
#  CK_ULONG          ulValueLen;  /* in bytes */
#} CK_ATTRIBUTE;

class etngError(Exception):

    def __init__(self, id=10, description="etngError"):
        self.id = id
        self.description = description
    def getId(self):
        return self.id
    def getDescription(self):
        return self.description

    def __str__(self):
        ## here we lookup the error id - to translate
        return repr("ERR" + str(self.id) + ": " + self.description)

# CKR_ errors in pkcs11t.h
class etng(object):
    ##### error map
  errormap = { 182:_('Session exists'),
                7:_('Bad argument'),
                19: _('Attribute value invalid'),
                162: _('invalid PIN length'),
                112: _('Mechanism invalid'),
                224: _('Token not present'),
                209: _('Template inconsistent'),
                208: _('Template incomplete'),
                163: _('PIN expired'),
                160: _('Unknown initializazion key')
                }

  def __init__(self, param):
    self.debug = False
    self.key = "123456789012345678901234"
    self.pw = ""
    self.npw = ""
    self.sopw = ""
    self.password = ""
    self.fpw = ""
    self.connectedTokens = []
    self.label = "newToken"
    self.displayDuration = 9
    self.randomUserPIN = True
    self.randomSOPIN = True

    # check params
    if 'label' in param:
        self.label = param['label']
    if 'debug' in param:
        self.debug = param['debug']
    if 'displayDuration' in param:
        self.displayDuration = param['displayDuration']
    if 'RetryCounter' not in param:
        self.retryCounter = 10
    else:
        self.retryCounter = param['RetryCounter']
    if 'sopin' in param:
        self.sopw = param['sopin']
    if 'userpin' in param:
        self.pw = param['userpin']
        self.password = param['userpin']
        self.npw = param['userpin']
    if 'randomUserPIN' in param:
        self.randomUserPIN = param['randomUserPIN'] == 'True'
    if 'randomSOPIN' in param:
        self.randomSOPIN = param['randomSOPIN'] == 'True'
    if 'logging' in param:
        self.logging = True
        self.handler = logging.handlers.RotatingFileHandler(
            param['logging']['LOG_FILENAME'],
            maxBytes=param['logging']['LOG_SIZE'],
            backupCount=param['logging']['LOG_COUNT'])
        self.formatter = logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s]:%(message)s")
        self.handler.setFormatter(self.formatter)
        self.log = logging.getLogger("LinOTP etng")
        self.log.setLevel(param['logging']['LOG_LEVEL'])
        self.log.addHandler(self.handler)
    else:
        self.logging = False


    if self.logging: self.log.info("[init] setting label to %s and RetryCounter to %s" % (self.label, self.retryCounter))
    if self.debug: print "label: ", self.label
    if self.debug: print "RetryCounter: ", self.retryCounter

    self.tdata = { 'hmac':'', 'password':'', 'serial':'', 'error':'', 'sopassword':''}

    system = platform.system()
    if system == "Linux":
        self.etpkcs11 = CDLL("libeTPkcs11.so")
        self.etoken = self.etpkcs11
        self.etsapi = CDLL("libeTSapi.so")
    elif system == "Windows":
        self.etpkcs11 = CDLL("eTPkcs11")
        self.etoken = CDLL("etoken")
        self.etsapi = CDLL("eTSapi")
    else:
        raise etngError(2020, _("etng::__init__ - Unknown system platform (%s)") % system)
    self.hSession = c_ulong()

  def pkcs11error(self, rv):
    if rv in self.errormap:
        return self.errormap[rv]
    else:
        return rv

  def initpkcs11(self):
    self.etpkcs11.C_Initialize(0)
    self.connectedTokens = []
    # Get the number of connected Tokens
    prototype = CFUNCTYPE (c_int, c_int, POINTER(c_ulong), POINTER(c_ulong))
    paramflags = (1, "tokenPresent", 1), (2, "SlotID"), (2, "nSlots")
    getslotlist = prototype(("C_GetSlotList", self.etpkcs11) , paramflags)

    (SlotID, nSlots) = getslotlist()
    if self.logging: self.log.info("[initpkcs11] number of slots: %d, slotid: %d" % (nSlots, SlotID))
    if self.debug: print "Number of connected tokens: " , nSlots
    if self.debug: print "SlotID: " , SlotID

    if nSlots > 1:
        raise etngError(2020, _("etng::initpkcs11 - There are more than one tokens connected (%s)") % nSlots)

    if nSlots == 0:
        self.tdata['error'] = "No token connected"

  def createpasswd(self):
    pw = ""
    i = 0
    l = 10
    passwdchars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!/()=?+-.,;:_<>*"
    while i < l:
        pw += passwdchars[ int(random.uniform(0, len(passwdchars) - 1))]
        i = i + 1
    return pw

  def inittoken(self):
    self.fpw = "1234567890"
    # we set a random user password
    if self.randomSOPIN:
        self.sopw = self.createpasswd()
    if self.randomUserPIN:
        self.password = self.createpasswd()
    self.npw = self.password

    # Start Initializing with SO PIN
    if self.logging: self.log.info ("[inittoken] token label: %s" % self.label)
    if self.logging: self.log.debug("[inittoken] sopw: %s" % self.sopw)
    if self.debug: print "label: ", self.label
    if self.debug: print "sopw:", self.sopw
    if self.debug: print "session:", self.hSession
    rv = self.etoken.ETC_InitTokenInit(0, self.sopw, len(self.sopw), 5, self.label, pointer(self.hSession))
    if rv:
        if self.logging: self.log.error("[inittoken] Failed to init token: %d" % rv)
        if self.debug: print "Failed to init token init: " , rv
        rv = self.pkcs11error(rv)
        raise etngError(2001, _("etng::inittoken - Failed to init token (%s)") % rv)
    else:
        if self.logging: self.log.info("[inittoken] init token succesful")
        if self.debug: print "session:", self.hSession
        if self.debug: print "init token init succesful"

    if self.logging: self.log.debug("[inittoken] npw: %s" % self.npw)
    if self.debug: print "npw  : ", self.npw

    rv = self.etoken.ETC_InitPIN (self.hSession, self.npw, len(self.npw), int(self.retryCounter), True)
    if rv:
        if self.logging: self.log.error("[inittoken] Failed User C_InitPin")
        if self.debug: print "Failed User C_InitPin"
        rv = self.pkcs11error(rv)
        raise etngError(2002, _("etng::inittoken - Failed to ETC_InitPIN (%s)") % rv)
    else:
        if self.logging: self.log.info("[inittoken] C_InitPIN successful")
        if self.debug: print "init token init User PIN succesful"

    rv = self.etoken.ETC_InitTokenFinal(self.hSession)
    if rv:
        if self.logging: self.log.error("[inittoken] Failed finalize InitTokenInit")
        if self.debug: print "Failed to finalize InitTokenInit"
        raise etngError(2003, _("etng::inittoken - Failed to ETC_InitTokenFinal (%s)") % rv)
    else:
        if self.logging: self.log.info("[inittoken] finalize InitTokenInit successful")
        if self.debug: print "init token init successfully finalized"

    # End of Initializing with SO PIN
    # This closes the initialization session

  def logintoken(self):
    # Open a session on fist token
    prototype = CFUNCTYPE (c_int, c_int, c_int, POINTER(c_ulong), POINTER(c_ulong), POINTER(c_ulong))
    paramflags = (1, "SlotID", 0), (1, "Flags", 6), (1, "App", NULL), (1, "Notify", NULL), (2, "SessionHandle")
    opensession = prototype(("C_OpenSession", self.etpkcs11), paramflags)
    self.hSession = opensession(SlotID=0)

    self.pw = self.password

    #print self.password
    #print self.pw
    #print len(self.pw)

    rv = self.etpkcs11.C_Login(self.hSession, CKU_USER, self.pw, len(self.pw))
    if rv:
        if self.logging: self.log.error("[logintoken] C_Login failed")
        if self.debug: print "Failed to login to token: " , rv
        raise etngError(2004, _("etng::logintoken - Failed to C_Login (%s)") % rv)
    else:
        if self.logging: self.log.info("[logintoken] C_Login successful")
        if self.debug: print "Login succesful"

  def deleteOTP(self):
    # Deleting existing OTP appliacion
    if self.logging: self.log.info("[deleteOTP] Deleting possible existing OTP application on the token")
    if self.debug: print "Deleting possible existing OTP application on the token"
    self.etsapi.SAPI_OTP_Destroy(self.hSession)

    # Creating random hmac key
    #Java Card OTP MinKeySize = 20
    #Java Card OTP MaxKeySize = 24
    #CardOS OTP MinKeySize = 20
    #CardOS OTP MaxKeySize = 32
    # TODO: zur Zeit 24 byte

    #self.key = "12345678901234567890"

    if self.logging: self.log.info("[deleteOTP] I will create a new HMAC key with this keysize: %d" % len(self.key))
    if self.debug: print "Sizeof key: ", len(self.key)

    rv = self.etpkcs11.C_GenerateRandom(self.hSession, self.key, c_ulong(len(self.key)))
    if rv:
        if self.logging: self.log.error("[deleteOTP] C_GenerateRandom failed %d" % rv)
        if self.debug: print "C_GenerateRandom failed:", rv
        raise etngError(2005, _("etng::deleteOTP - Failed to C_GenerateRandom (%s)") % rv)
    else:
        if self.logging: self.log.info("[deleteOTP] C_GenerateRandom successful")
        if self.logging: self.log.debug("[deleteOTP] New HMAC-Key: %s" % binascii.hexlify(self.key))
        if self.debug: print "created random ", len(self.key), " byte HMAC key:", binascii.hexlify(self.key)


  def createAESKey(self):
    if self.logging: self.log.info("[createOTP] About to create new OTP object ")
    if self.debug: print "Create new OTP object"

    #keyClass = c_ulong(CKO_SECRET_KEY)
    dClass = c_ulong(CKO_SECRET_KEY)
    keyType = c_ulong(CKK_AES)
    ck_true = c_ubyte(True)
    label = "my AES key"
    value = "1234567890123456"
    c_label = c_char_p(label)
    c_value = c_char_p(value)

    tC1 = CK_ATTRIBUTE(c_ulong(CKA_CLASS),
        cast(byref(dClass), c_void_p), sizeof(dClass))
    tC2 = CK_ATTRIBUTE(c_ulong(CKA_KEY_TYPE),
        cast(byref(keyType), c_void_p), sizeof(keyType))
    tC3 = CK_ATTRIBUTE(c_ulong(CKA_TOKEN),
        cast(byref(ck_true), c_void_p), sizeof(ck_true))
    tC4 = CK_ATTRIBUTE(c_ulong(CKA_LABEL),
        cast(c_label, c_void_p), len(label))
    tC5 = CK_ATTRIBUTE(c_ulong(CKA_ENCRYPT),
        cast(byref(ck_true), c_void_p), sizeof(ck_true))
    tC6 = CK_ATTRIBUTE(c_ulong(CKA_VALUE),
        cast(c_value, c_void_p), len(value))
    #tC7 = CK_ATTRIBUTE( c_ulong(CKA_PRIVATE),
    #    cast( byref( ck_true), c_void_p), sizeof( ck_true))

    arrayCK_ATTRIBUTES = CK_ATTRIBUTE * 6

    hObject = c_ulong()

    #tCreate = arrayCK_ATTRIBUTES( tC1, tC2, tC3, tC4, tC5, tC6)

    tCreate = (tC1, tC2, tC3, tC4, tC5, tC6)

    rv = self.etpkcs11.C_CreateObject(self.hSession, tCreate, len(tCreate), pointer(hObject))

    if rv:
        rv = self.pkcs11error(rv)
        if self.logging: self.log.error("[createAES] SAPI_OTP_Create failed: %d " % rv)
        if self.debug: print "Error creating AES object: ", rv
        raise etngError(2006, _("etng::createAES - Failed to etpkcs11.C_CreateObject (%s).") % rv)
    else:
        if self.logging: self.log.info("[createAES] C_CreateObject successful")
        if self.debug: print "AES object created successfully"


  def createOTP(self):
    # Creating new OTP object
    if self.logging: self.log.info("[createOTP] About to create new OTP object ")
    if self.debug: print "Create new OTP object"

    p_c_key = c_char_p(self.key)
    p_key = cast(p_c_key, c_void_p)

#    rv = self.mysapi.my_OTP_Create( self.hSession, p_key, c_ulong(20), self.displayDuration)
#CK_RV my_OTP_Create(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen, CK_ULONG dduration)
#{
#  CK_ULONG mech = CK_SAPI_OTP_HMAC_SHA1_DEC6;
#  CK_BBOOL ck_false = FALSE;
#  CK_ATTRIBUTE tCreate[]= {
#	{CKA_SAPI_OTP_MECHANISM,    &mech,        sizeof(CK_ULONG)},
#  	{CKA_SAPI_OTP_VALUE,        RandomData,   ulRandomLen    },
#	{CKA_SAPI_OTP_DURATION,	    &dduration,		sizeof(CK_ULONG)},
#  CKA_SAPI_OTP_NEXT_ALLOWED, &ck_false,     sizeof(CK_BBOOL)},
# };
# return SAPI_OTP_Create(hSession, tCreate, sizeof(tCreate)/sizeof(CK_ATTRIBUTE));
#
#    print "new stuff"
    ck_mech = c_ulong(CK_SAPI_OTP_HMAC_SHA1_DEC6)
    ck_false = c_ubyte(False)
    ck_duration = c_ulong(int(self.displayDuration))
    tCreate1 = CK_ATTRIBUTE(c_ulong(CKA_SAPI_OTP_MECHANISM), cast(byref(ck_mech), c_void_p), sizeof(ck_mech))
    tCreate2 = CK_ATTRIBUTE(c_ulong(CKA_SAPI_OTP_VALUE), p_key, len(self.key))
    tCreate3 = CK_ATTRIBUTE(c_ulong(CKA_SAPI_OTP_NEXT_ALLOWED), cast(byref(ck_false), c_void_p), sizeof(ck_false))
    tCreate4 = CK_ATTRIBUTE(c_ulong(CKA_SAPI_OTP_DURATION), cast(byref(ck_duration), c_void_p), sizeof(ck_duration))
    arrayCK_ATTRIBUTES = CK_ATTRIBUTE * 4
    tCreate = arrayCK_ATTRIBUTES(tCreate1, tCreate2, tCreate3, tCreate4)
#    print len(tCreate)
#    print  "done 1"
    rv = self.etsapi.SAPI_OTP_Create(self.hSession, tCreate, len(tCreate))
#    print "done 2"

    if rv:
        rv = self.pkcs11error(rv)
        if self.logging: self.log.error("[createOTP] SAPI_OTP_Create failed: %d " % rv)
        if self.debug: print "Error creating OTP object: ", rv
        raise etngError(2006, _("etng::createOTP - Failed to etsapi.SAPI_OTP_Create (%s). Maybe the token was initialized previously without HMAC support?") % rv)
    else:
        if self.logging: self.log.info("[createOTP] SAPI_OTP_Create successful")
        if self.debug: print "OTP object created successfully"

  def finalize(self):
    # In fact we do not neet the CK_TOKEN_INFO Structure at the moment.
    tokeninfo = CK_TOKEN_INFO()
    tInfo = ''
    # Build up a 400 Byte mem alloc ;-)
    # The Structure is 400 bytes
    for i in range(40):
        tInfo += '0123456789'
    p_c_tokeninfo = c_char_p(tInfo)
    p_tokeninfo = cast(p_c_tokeninfo, c_void_p)
    rv = self.etpkcs11.C_GetTokenInfo(0, p_tokeninfo)
    if rv:
        if self.logging: self.log.error("[finalize] Error getting TokenInfo: %d" % rv)
        if self.debug: print "Error getting TokenInfo: ", rv
        raise etngError(2007, _("etng::Finalize - Failed to C_GetTokenInfo (%s)") % rv)
    else:
        if self.logging: self.log.info("[finalize] getting TokenInfo successful ")
        if self.debug: print "Got Token info successfully"

    # FIXME: We should make this more robust and use the structure
    tiLabel = self.unpad(tInfo[0:31])
    tiManufacturer = self.unpad(tInfo[32:63])
    tiModel = self.unpad(tInfo[64:79])
    tiSerial = self.unpad(tInfo[80:95])
    serial = tiSerial
    #print sizeof(c_ulong)
    #print "HW: ", tInfo[118]
    #print "FW: ", tInfo[119]

    rv = self.etpkcs11.C_Finalize(0)
    if rv:
        if self.logging: self.log.error("[finalize] Error finalizing Token %d" % rv)
        if self.debug: print "Error finalizing Token: ", rv
        raise etngError(2007, _("etng::Finalize - Failed to finalize token (%s)") % rv)
    else:
        if self.logging: self.log.info("[finalize] Token finalized successful ")
        if self.debug: print "Token finalized successfully"

    if self.logging: self.log.debug("[finalize] Token was created with the data HMAC-key (" +
                    binascii.hexlify(self.key) +
                    "), Serial (" + serial +
                    "), PIN (" + self.password +
                    "), SO PIN (" + self.sopw + "). YOU ASKED FOR IT! ;-)")
    if self.debug: print "Your data:"
    if self.debug: print " HMAC-key  : ", binascii.hexlify(self.key)
    if self.debug: print " Serial    : ", serial
    if self.debug: print " eToken PIN: ", self.password
    if self.debug: print " SO PIN    : ", self.sopw

    self.tdata = { 'hmac' : binascii.hexlify(self.key), 'serial':serial, 'userpin':self.password, 'sopin':self.sopw }
    return self.tdata

  def unpad(self, inValue):
    outValue = ""
    for i in range(len(inValue)):
        if inValue[i] == " ":
            break
        else:
            outValue += inValue[i]
    return outValue



##### plain function
def initetng(param={ 'label': 'newToken'}):
    debug = True
    if not 'label' in param:
        param['label'] = 'newToken'
    if not 'retrycounter' in param:
        param['RetryCounter'] = 15

    if 'debug' in param:
        debug = param['debug']


    enroller = etng(param)

    print _("initialize pkcs11 interface") if debug else '',
    enroller.initpkcs11()
    print _("initialize token")  if debug else '',
    enroller.inittoken()
    print _("login to token") if debug else '',
    enroller.logintoken()
    print _("delete old OTP application") if debug else '',
    enroller.deleteOTP()
    print _("create new OTP application") if debug else '',
    enroller.createOTP()
    print _("Creating AES key") if debug else '',
    #enroller.createAESKey()
    #print _("finalizing token") if debug else '',
    tdata = enroller.finalize()

    return tdata

if __name__ == "__main__":


    initetng({'userpin':'test123!', 'label':'eTokenNG', 'randomUserPIN':False, 'debug' : True })

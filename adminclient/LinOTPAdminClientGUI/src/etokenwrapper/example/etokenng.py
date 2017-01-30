#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
#    Support: www.keyidentity.com
#
"""
example of communicating with the eTokenNG
"""
from ctypes import *
from array import array
import getpass
import binascii
import sys
if sys.version_info[0:2] >= (2, 6):
    import json
else:
    import simplejson
import commands

CKF_RW_SESSION = 0x00000002
CKF_SERIAL_SESSION = 0x00000004
CK_SAPI_OTP_HMAC_SHA1_DEC6 = int(0x00000001)
CKA_SAPI_OTP_MECHANISM = int(0x80001301)
CKA_SAPI_OTP_VALUE = int(0x80001304)
CKA_SAPI_OTP_NEXT_ALLOWED = 0x80001306
CKU_USER		 = 1
CKU_SO			 = 0

NULL = None
"""
class ck_attribute(Structure):
    _fields_ = [("type", c_ulong),
                ("pValue", c_void_p),
                ("ulValueLen", c_ulong),
		("type", c_ulong),
		("pValue", c_void_p),
                ("ulValueLen", c_ulong),
                ]

class ck_attribute1(Structure):
    _fields_ = [("type", c_ulong),
                ("pValue", c_void_p),
                ("ulValueLen", c_ulong)
                ]
"""

# Creating instances of libs eTPKCS11 and eTSAPI
etpkcs11 = CDLL("libeTPkcs11.so")
etsapi = CDLL("libeTSapi.so")
mysapi = CDLL("../liblinotpetwrapper/liblinotpetwrapper.so")
#cdll.LoadLibrary("libeTPkcs11.so")
#cdll.LoadLibrary("libeTSapi.sp")


password = commands.getoutput("pwgen -1yn 8")

hSession = c_ulong()

# Initialize PKCS11 Library.
etpkcs11.C_Initialize(0)

connectedTokens = []

# Get the number of connected Tokens
prototype = CFUNCTYPE (c_int, c_int, POINTER(c_ulong), POINTER(c_ulong))
paramflags = (1, "tokenPresent", 1), (2, "SlotID"), (2, "nSlots")
getslotlist = prototype(("C_GetSlotList", etpkcs11) , paramflags)

(SlotID, nSlots) = getslotlist()
print "Number of connected tokens: " , nSlots
print "SlotID: " , SlotID


#fpw = getpass.getpass("Please enter Format password:")
fpw = "1234567890"

print "Initializing Token..."
rv = etpkcs11.C_InitToken(0, fpw, len(fpw), "newToken")
if rv:
    print "Failed to init token: " , rv
else:
    print "init succesful"


# Open a session on fist token
prototype = CFUNCTYPE (c_int, c_int, c_int, POINTER(c_ulong), POINTER(c_ulong), POINTER(c_ulong))
paramflags = (1, "SlotID", 0), (1, "Flags", 6), (1, "App", NULL), (1, "Notify", NULL), (2, "SessionHandle")
opensession = prototype(("C_OpenSession", etpkcs11), paramflags)
hSession = opensession(SlotID=0)


# Login as SO.
rv = etpkcs11.C_Login(hSession, CKU_SO, fpw, len(fpw))
if rv:
    print "Failed to Login to token"
else:
    print "Logged in to token with format pw"

#npw = getpass.getpass("Please enter new User password:")
npw = password

rv = etpkcs11.C_InitPIN (hSession, npw, len(npw))
if rv:
    print "Failed C_IinitPin"
else:
    print "C_InitPIN successful"

rv = etpkcs11.C_Logout(hSession)
if rv:
    print "C_Logout failed"
else:
    print "C_Logout successful"

# Login to first Token
#pw = getpass.getpass("Please enter Token password:")
pw = password

rv = etpkcs11.C_Login(hSession, CKU_USER, pw, len(pw))
if rv:
    print "Failed to login to token: " , rv
else:
    print "Login succesful"

# Deleting existing OTP application
print "Deleting possible existing OTP application on the token"
etsapi.SAPI_OTP_Destroy(hSession)

# Creating random hmac key
#Java Card OTP MinKeySize = 20
#Java Card OTP MaxKeySize = 24
#CardOS OTP MinKeySize = 20
#CardOS OTP MaxKeySize = 32
# TODO: zur Zeit 24 byte

key = "123456789012345678901234"

print "Sizeof key: ", len(key)

rv = etpkcs11.C_GenerateRandom(hSession, key, c_ulong(len(key)));
if rv:
    print "C_GenerateRandom failed:", rv
else:
    print "created random ", len(key), " byte HMAC key:", binascii.hexlify(key)

# Creating new OTP object
print "Create new OTP object"

print CKA_SAPI_OTP_VALUE
print CKA_SAPI_OTP_MECHANISM, ':', CK_SAPI_OTP_HMAC_SHA1_DEC6, '-', sizeof(c_ulong)

p_c_mech = c_void_p(CK_SAPI_OTP_HMAC_SHA1_DEC6)
p_mech = cast(p_c_mech, c_void_p)
p_c_key = c_char_p(key)
p_key = cast(p_c_key, c_void_p)

#create_attrs = ck_attribute( c_ulong(CKA_SAPI_OTP_MECHANISM), p_mech, sizeof(c_ulong),
#			     c_ulong(CKA_SAPI_OTP_VALUE), p_key, c_ulong(24)
#			  )

# p_key, c_ulong(24)
rv = mysapi.my_OTP_Create(hSession, p_key, c_ulong(24))
if rv:
    print "Error creating OTP object: ", rv
else:
    print "OTP object created successfully"


#sn=create_string_buffer('\000' * 20)
#sn = create_string_buffer(20)
sn = c_char_p('1234567890123456789')
rv = mysapi.my_GetTokenSerial(0, pointer(sn));
serial = sn.value
rv = etpkcs11.C_Finalize(0)

print "Your data:"
print " HMAC-key  : ", binascii.hexlify(key)
print " Serial    : ", serial
print " eToken PIN: ", password

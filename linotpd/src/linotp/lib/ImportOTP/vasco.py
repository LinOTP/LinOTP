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
"""This parses the vasco dpx files """

import pickle
import zlib

import logging
log = logging.getLogger(__name__)

from pylons import config

from ctypes import *

vasco_dll = None
try:
    vasco_lib = config.get("linotpImport.vasco_dll")
    #/opt/vasco/Vacman_Controller-3.10.1/lib/libaal2sdk-3.10.1.so
    if None == vasco_lib:
        log.warning("Missing linotpImport.vasco_dll in config file")
    else:
        log.info("loading vasco lib %s" % vasco_lib)
        vasco_dll = CDLL(vasco_lib)
except Exception as  e:
    log.exception("cannot load vasco library: %s" % str(e))


def check_vasco(fn):
    '''
    This is a decorator:
    checks if vasco dll is defined,
    it then runs the function otherwise returns NONE
    '''
    def new(*args, **kw):
        if None == vasco_dll:
            log.error("[check_vasco] No vasco dll available!")
            return None
        else:
            return fn(*args, **kw)
    return new


class TDPXHandle(Structure):
    _fields_ = [("pHandleDpxContext", c_void_p),
                ("pHandleDpxInitKey", c_void_p)
                ]

class TKernelParams(Structure):
    _fields_ = [ ("ParmCount", c_ulong),
                 ("ITimeWindow", c_ulong),
                 ("STimeWindow", c_ulong),
                 ("DiagLevel", c_ulong),
                 ("GMTAdjust", c_ulong),
                 ("CheckChallenge", c_ulong),
                 ("IThreshold", c_ulong),
                 ("SThreshold", c_ulong),
                 ("ChkInactDays", c_ulong),
                 ("DeriveVector", c_ulong),
                 ("SyncWindow", c_ulong),
                 ("OnLineSG", c_ulong),
                 ("EventWindow", c_ulong),
                 ("HSMSlotId", c_ulong),
                 ("StorageKeyId", c_ulong),
                 ("TransportKeyId", c_ulong),
                 ("StorageDeriveKey1", c_ulong),
                 ("StorageDeriveKey2", c_ulong),
                 ("StorageDeriveKey3", c_ulong),
                 ("StorageDeriveKey4", c_ulong),
                 ]


class TDigipassBlob(Structure):
    _fields_ = [ ("Serial", c_char * 10),
                 ("AppName", c_char * 12),
                 ("DPFlags", c_byte * 2),
                 ("Blob", c_char * 224)
                ]
@check_vasco
def vasco_dpxinit(filename="demovdp.dpx", transportkey="1"*32):
    '''
    This function returns
     - error code
     - filehandle (TDPXHandle)
     - application count
     - application names
     - token counts
    '''
    c_filename = c_char_p(filename)
    c_transportkey = c_char_p(transportkey)
    # string with 97 bytes
    appl_names = "." * 97
    p_names = c_char_p(appl_names)

    fh = TDPXHandle()
    p_fh = pointer(fh)

    appl_count = c_int(0)
    p_acount = pointer(appl_count)

    token_count = c_int(0)
    p_tcount = pointer(token_count)

    res = vasco_dll.AAL2DPXInit(p_fh,
                            c_filename,
                            c_transportkey,
                            p_acount,
                            p_names,
                            p_tcount)

    return (res, fh, appl_count, appl_names, token_count)


@check_vasco
def vasco_getstatic_vector(handle, params):
    '''
    '''
    vector = "." * 113
    p_vector = c_char_p(vector)
    vector_len = c_int(112)
    p_vector_len = pointer (vector_len)
    res = vasco_dll.AAL2DPXGetStaticVector(pointer(handle),
                                           pointer(params),
                                           p_vector,
                                           p_vector_len)

    return (res, vector, vector_len)

@check_vasco
def vasco_gettoken(handle, params, select_appl):
    dpdata = TDigipassBlob()
    serial = "\0"*23
    typ = "\0"*6
    authmode = "\0"*3
    res = vasco_dll.AAL2DPXGetToken(pointer(handle),
                                    pointer(params),
                                    c_char_p(select_appl),
                                    c_char_p(serial),
                                    c_char_p(typ),
                                    c_char_p(authmode),
                                    pointer(dpdata))

    return (res, serial, typ, authmode, dpdata)


@check_vasco
def vasco_dpxclose(handle):
    res = vasco_dll.AAL2DPXClose(pointer(handle))
    return res

@check_vasco
def vasco_genpassword(data, params, challenge="\0"*16):
    password = "\0"*41
    res = vasco_dll.AAL2GenPassword(pointer(data),
                                     pointer(params),
                                     c_char_p(password),
                                     c_char_p(challenge))
    return (res, password)

@check_vasco
def vasco_verify(data, params, password, challenge="\0"*16):
    res = vasco_dll.AAL2VerifyPassword(pointer(data),
                                           pointer(params),
                                           c_char_p(password),
                                           c_char_p(challenge)
                                          )
    return (res, data)


@check_vasco
def vasco_settokenproperty(data, params, prop, value):
    '''
    can be used to do not use a static PIN
    pin_supported (6) : enable=1, disable=2
    '''
    res = vasco_dll.AAL2SetTokenProperty(pointer(data),
                                        pointer(params),
                                        c_ulong(prop),
                                        c_ulong(value))
    return (res, data)

@check_vasco
def vasco_gettokenproperty(data, params, prop):
    '''
    This function returns token properties.

    PIN_LEN: property = 10
    '''
    value = 0
    res = vasco_dll.AAL2GetTokenProperty(pointer(data),
                                          pointer(params),
                                          c_ulong(prop),
                                          pointer(c_ulong(value)))
    return (res, value)

@check_vasco
def compress(datablob):
    '''
    Compresses the data to be stored in the token database.
    The data object is pickled and compressed.

    :param datablob: Vasco Data Blob
    :return: compressed data to be stored in Token database
    '''
    return zlib.compress(pickle.dumps(datablob))

@check_vasco
def decompress(tokendata):
    '''
    De-compresses the data when loaded from the token database.
    The data object is pickled and compressed.

    :param tokendata: The encrypted OTP Key from the database
    :return: The Vasco data blob
    '''
    return pickle.loads(zlib.decompress(tokendata))

@check_vasco
def parseVASCOdata(filename="Demo_GO6.DPX", arg_otplen=6):
    '''
    This parses a DPX file and returns the dictionary with the Token Dictionary.
    TOKENS[serial] = { hmac_key, type, otplen,
    '''
    TOKENS = {}

    kp = TKernelParams()
    kp.ParmCount = 19;
    kp.ITimeWindow = 100;
    kp.STimeWindow = 24;
    kp.DiagLevel = 0;
    kp.GMTAdjust = 0;
    kp.CheckChallenge = 0;
    '''
    This is the failcounter! The failcounter needs to be reset manually
    When we set the failcounter=0 then we can rule the failcounter in LinOTP
    '''
    kp.IThreshold = 0;
    kp.SThreshold = 1;
    kp.ChkInactDays = 0;
    kp.DeriveVector = 0;
    kp.SyncWindow = 2;
    kp.OnLineSG = 1;
    kp.EventWindow = 100;
    kp.HSMSlotId = 0;


    (res, fh, appl_count, appl_names, tokens) = vasco_dpxinit(filename=filename)
    log.debug("[parseVASCOdata] found %s tokens." % tokens)

    (res, vec, vec_len) = vasco_getstatic_vector(fh, kp)
    log.debug("[parseVASCOdata] getstaticvector: %d" % res)

    # start getting tokens
    res = 100
    data = TDigipassBlob()

    while 100 == res:
        (res, serial, typ, auth, data) = vasco_gettoken(fh, kp, appl_names)
        if 107 == res:
            log.debug("[parseVASCOdata] SUCCESSfully reached the end of the file")
        if 100 == res:
            # remove the need for an otppin
            (res, data) = vasco_settokenproperty(data, kp, 6, 2)

            # TODO: Each token could have another OTP-length. At the moment we take the parameter
            otplen = arg_otplen

            #if type[:5] in ["DPGO6"] and auth[:2] in ["RO"]:
            if auth[:2] in ["RO"]:
                # yes, we support DPGO6
                # and we support the response only (no signature and challenge)
                otpkey = compress(data)
                TOKENS["vc" + serial[:10]] = { 'type' : "vasco",
                                    'hmac_key' : otpkey,
                                    'tokeninfo' : { "application" : serial.strip("\0"),
                                                    "type" : typ.strip("\0"),
                                                    "auth" : auth.strip("\0"),
                                                    #"data_Serial" : data.Serial,
                                                    #"data_AppName" : data.AppName,
                                                    #"data_DPFlags" : data.DPFlags
                                                   },
                                    'otplen' : otplen
                                   }
            else:
                # We have not tested other tokens, so we do not import them!
                log.warning("[parseVASCOdata] the tokentype %s, auth %s is not tested! The Token %s is not imported!" % (typ, auth, serial[:10]))

    res = vasco_dpxclose(fh)

    return TOKENS


@check_vasco
def vasco_otp_check(data, otp):
    kp = TKernelParams()
    kp.ParmCount = 19;
    kp.ITimeWindow = 100;
    kp.STimeWindow = 24;
    kp.DiagLevel = 0;
    kp.GMTAdjust = 0;
    kp.CheckChallenge = 0;
    '''
    This is the failcounter! The failcounter needs to be reset manually
    When we set the failcounter=0 then we can rule the failcounter in LinOTP
    '''
    kp.IThreshold = 0;
    kp.SThreshold = 1;
    kp.ChkInactDays = 0;
    kp.DeriveVector = 0;
    kp.SyncWindow = 2;
    kp.OnLineSG = 1;
    kp.EventWindow = 100;
    kp.HSMSlotId = 0;

    return vasco_verify(data, kp, otp)

@check_vasco
def test():
    tokens = parseVASCOdata("Demo_GO6.DPX")

    for t in tokens.keys():
        print t
        print tokens[t]
        data = pickle.loads(tokens[t]['hmac_key'])
        pw = "000000"
        while "X" != pw:
                print "=========== Verify Password ============"
                pw = raw_input("Enter OTP:")
                (res, data) = vasco_otp_check(data, pw)

                print res




test()

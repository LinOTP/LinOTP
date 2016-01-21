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
"""
Parsing of pskc files:
    http://tools.ietf.org/search/rfc6030
"""
import xml.etree.cElementTree as etree
import re, binascii, base64
import hmac
import hashlib

sha = hashlib.sha1
md5 = hashlib.md5
sha256 = hashlib.sha256

import logging
log = logging.getLogger(__name__)

import linotp.lib.pbkdf2 as pbkdf2

from linotp.lib.ImportOTP  import getTagName, ImportException

def checkSerial(serial):
    return re.match("[a-zA-Z0-9]{4}[a-fA-F0-9]{8}$", serial)

def getEncMethod(elem):
    algo = elem.get("Algorithm")
    m = re.search("\#(.*)$", algo)
    if m:
        algo = m.group(1)
    if "aes128-cbc" != algo:
        log.error("The algorithm %s is not supported" % algo)
        raise ImportException("The algorithm %s is not supported" % algo)
    return algo

def getMacMethod(elem):
    meth = elem.get("Algorithm")
    m = re.search("\#(.*)$", meth)
    if m:
        meth = m.group(1)
    if "hmac-sha1" != meth:
        log.error("The method %s is not supported" % meth)
        raise ImportException("The method %s is not supported" % meth)
    return meth


def aes_decrypt(transport_b64, key_hex, serial=""):
    import Crypto.Cipher.AES as AES

    def hack(data, serial=""):
        bsize = 16
        a = ord(data[-1])
        # safety check if padding is bigger than blocksize
        #TODO: Fix: padding has to be elaborated with
        #                                  backward compatibility in mind
        if (a > bsize):
            return data

        padding = data[len(data) - a:]
        if not (chr(a) * a == padding):
            # it seems not to be padded
            return data

        if a == bsize:
            # padding equals blocksize. This is not common!
            log.warning("[aes_decrypt] the key of token %s is a multiple of blocksize but is padded. This is not compliant to the specification but we import it anyway." % serial)
        return data[:-a]

    key_bin = binascii.unhexlify(key_hex)

    transport_bin = base64.b64decode(transport_b64)
    #print len( transport_bin )
    #print binascii.hexlify(transport_bin)

    iv_bin = transport_bin[0:16]
    encSecret_bin = transport_bin[16:]

    #iv_bin = base64.b64decode( transport_b64[0:16] )
    #encSecret_bin = base64.b64decode( transport_b64[16:] )

    aesObj = AES.new(key_bin, AES.MODE_CBC, iv_bin)
    result = aesObj.decrypt(encSecret_bin)

    result = hack(result, serial)

    return result


def parsePSKCdata(xml , preshared_key_hex=None, password=None,
                    do_checkserial=True,
                    do_feitian=False):
    '''
    This function parses XML data of a PSKC file, (RFC6030)
    It can read
    * AES-128-CBC encrypted (preshared_key_bin) data
    * password based encrypted data
    * plain text data

    It returns a dictionary of
        serial : { hmac_key , counter, .... }
    '''
    TAG_NAME_KEYPACKAGE = "KeyPackage"
    TAG_TOKEN_ID = "Id"
    # Feitian Fix
    if do_feitian:
        TAG_NAME_KEYPACKAGE = "Device"
        TAG_TOKEN_ID = "KeyId"
        do_checkserial = False


    TOKENS = {}
    elem_keycontainer = etree.fromstring(xml)
    ENCRYPTION_KEY_hex = preshared_key_hex

    if getTagName(elem_keycontainer).lower() != "keycontainer":
        raise ImportException("No toplevel element KeyContainer")

    tag = elem_keycontainer.tag
    match = re.match("^({.*?})Key[Cc]ontainer$", tag)
    namespace = ""
    if match:
        namespace = match.group(1)
        log.debug("Found namespace %s" % namespace)

    PSKC_VERSION = elem_keycontainer.get("Version")
    KEYNAME = None
    MACKEY_bin = None
    ENC_ALGO = None
    ENC_MODE = None

    PBE_DERIVE_ALGO = None
    PBE_SALT = None
    PBE_ITERATION_COUNT = None
    PBE_KEY_LENGTH = None

    # check for any encryption method 6.1, 6.2
    ### Do the Encryption Key
    elem_encKey = elem_keycontainer.find(namespace + "EncryptionKey")

    if elem_encKey:

        # Check for AES-128-CBC, preshared key (chapter 6.1)
        enckeyTag = getTagName(list(elem_encKey)[0])
        # This will hold the name of the preshared key
        if "KeyName" == enckeyTag:
            ENC_MODE = "AES128"
            KEYNAME = list(elem_encKey)[0].text
            log.debug("The keyname of preshared encryption is <<%s>>" % KEYNAME)
        # check for PasswordBasedEncyprion (chapter 6.2)
        elif "DerivedKey" == enckeyTag:
            ENC_MODE = "PBE"
            log.debug("We found PBE.")
            # Now we check for KeyDerivationMethod
            elem_keyderivation = list(list(elem_encKey)[0])
            for e in elem_keyderivation:
                if "KeyDerivationMethod" == getTagName(e):

                    deriv_algo = e.get("Algorithm")
                    m = re.search("\#(.*)$", deriv_algo)
                    PBE_DERIVE_ALGO = m.group(1)
                    log.debug("Algorithm of the PBE: %s" % PBE_DERIVE_ALGO)
                    if "pbkdf2" == PBE_DERIVE_ALGO:
                        for p in list(e):
                            if "PBKDF2-params" == getTagName(p):
                                for sp in list(p):
                                    spTag = getTagName(sp)
                                    if "Salt" == spTag:
                                        for salt in list(sp):
                                            if "Specified" == getTagName(salt):
                                                PBE_SALT = salt.text
                                            else:
                                                log.warning("Unknown element in element Salt: %s" % getTagName(salt))
                                    elif "IterationCount" == spTag:
                                        PBE_ITERATION_COUNT = sp.text
                                    elif "KeyLength" == spTag:
                                        PBE_KEY_LENGTH = sp.text
                    else:
                        # probably pbkdf1
                        log.error("We do not support key derivation method %s" % deriv_algo)
                        raise ImportException("We do not support key derivation method %s" % deriv_algo)
                log.debug("found the salt <<%s>>" % PBE_SALT)

            if password and len(password) > 5 and len(password) <= 64:
                log.debug("calculation encryption key from password [%s], salt: [%s] and length: [%s], count: [%s]" %
                    (password, PBE_SALT, PBE_KEY_LENGTH, PBE_ITERATION_COUNT))
                ENCRYPTION_KEY_bin = pbkdf2.pbkdf2(password.encode('ascii'), base64.b64decode(PBE_SALT),
                    int(PBE_KEY_LENGTH), int(PBE_ITERATION_COUNT))
                ENCRYPTION_KEY_hex = binascii.hexlify(ENCRYPTION_KEY_bin)
                log.debug("calculated encryption key: %s" % ENCRYPTION_KEY_hex)
            else:
                log.error("You must provide a password that is longer than 5 characters and up to 64 characters long.")
                raise ImportException("You must provide a password that is longer than 5 characters and up to 64 characters long.")


        ### Do the MAC Key
        # This will hold the MAC key
        macmethod = elem_keycontainer.find(namespace + "MACMethod")
        MAC_Method = getMacMethod(macmethod)
        elem_mackey = macmethod.find(namespace + "MACKey")


        # Find the MAC: ENC_ALGO and MAC_bin
        for e in list(elem_mackey):
            tag = getTagName(e)
            if "CipherData" == tag:
                for c in list(e):
                    cipher_tag = getTagName(c)
                    if "CipherValue" == cipher_tag:
                        cipherValue = c.text.strip()
                        log.debug("Found this MAC Key cipherValue: <<%s>>" % cipherValue)
                        MACKEY_bin = aes_decrypt(cipherValue, ENCRYPTION_KEY_hex)
                    else:
                        log.error("Found unsupported child in CipherData: %s" % cipher_tag)
                        raise ImportException("Found unsupported child in CipherData: %s" % cipher_tag)
            elif "EncryptionMethod" == tag:
                ENC_ALGO = getEncMethod(e)
            else:
                log.warning("Found unknown tag: %s" % tag)


    ## End of Encryption Key
    # There is a keypackage per key
    # Now we get the list of keypackages

    elem_KeyPackageList = elem_keycontainer.findall(namespace + TAG_NAME_KEYPACKAGE)
    if 0 == len(elem_KeyPackageList):
        raise ImportException("No element %s contained!" % TAG_NAME_KEYPACKAGE)

    # Now parsing all the keys
    for elem_package in elem_KeyPackageList:

        ### Do the keys

        elem_key = elem_package.find(namespace + "Key")

        serial = elem_key.get(TAG_TOKEN_ID)
        log.info("Processing token with serial (Key Id=%s)" % serial)

        elem_deviceInfo = elem_package.find(namespace + "DeviceInfo")
        if elem_deviceInfo:
            # Try to find the real serial number
            elem_serial = elem_deviceInfo.find(namespace + "SerialNo")
            serial = elem_serial.text
            log.info("Processing token with the real SerialNo %s" % serial)

        algorithm = elem_key.get("Algorithm")
        if algorithm:
            # <Key Id="12345678" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">
            algorithm = algorithm.split(":")[-1]
        else:
            # Some draft say, this would be KeyAlgorithm
            algorithm = elem_key.get("KeyAlgorithm")
            # <Key KeyAlgorithm="http://www.ietf.org/keyprov/pskc#totp"
            algorithm = algorithm.split("#")[-1]

        TOKEN_TYPE = None

        if algorithm:
            if 'hotp' == algorithm.lower():
                TOKEN_TYPE = "hmac"
            elif 'totp' == algorithm.lower():
                TOKEN_TYPE = "totp"
            elif 'ocra' == algorithm.lower():
                TOKEN_TYPE = "ocra"

        if do_checkserial and not checkSerial(serial):
            log.warning("serial %s is not a valid OATH serial" % serial)
        else:
            # Now we do the Parameters, which can hold
            # the number of the digits :
            # <pskc:AlgorithmParameters>
            #   <Suite>OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1</Suite>
            #   <pskc:ResponseFormat Length="6" Encoding="DECIMAL"/>
            # </pskc:AlgorithmParameters>
            KD_otplen = 6
            KD_hashlib = None
            KD_Suite = None
            elem_algoParam = elem_key.find(namespace + "AlgorithmParameters")
            for e in list(elem_algoParam):
                eTag = getTagName(e)
                log.debug("Evaluating element <<%s>>" % eTag)
                if "ResponseFormat" == eTag:
                    KD_otplen = int (e.get("Length"))
                    log.debug("Found length = %s" % e.get("Length"))
                elif "Suite" == eTag:
                    if TOKEN_TYPE == "ocra":
                        KD_Suite = e.text
                        log.debug("Found OCRA Suite = %s" % KD_Suite)
                    else:
                        # This can be HMAC-SHA256
                        KD_hashlib = e.text
                        if KD_hashlib.lower() == "hmac-sha256":
                            KD_hashlib = "sha256"
                        if KD_hashlib.lower() == "hmac-sha1":
                            KD_hashlib = "sha1"
                        log.debug("Found hashlib = %s" % KD_hashlib)


            # Now we do all the Key Data: <pskc:Data>
            elem_keydata = elem_key.find(namespace + "Data")
            # Parse through the data of the Key
            KD_hmac_key_b64 = None
            KD_cipher_b64 = None
            KD_mac_b64 = None
            KD_algo = None
            KD_counter = None
            KD_TimeInterval = None
            KD_TimeOffset = None
            for e in list(elem_keydata):
                eTag = getTagName(e)
                log.debug("Evaluating element <<%s>>" % eTag)
                if "Secret" == eTag:
                    for se in list(e):
                        seTag = getTagName(se)
                        if "EncryptedValue" == seTag:
                            for ev in list(se):
                                evTag = getTagName(ev)
                                if "EncryptionMethod" == evTag:
                                    KD_algo = getEncMethod(ev)
                                elif "CipherData" == evTag:
                                    for ciph in list(ev):
                                        ciphTag = getTagName(ciph)
                                        if "CipherValue" == ciphTag:
                                            KD_cipher_b64 = ciph.text.strip()


                        elif "PlainValue" == seTag:
                            KD_hmac_key_b64 = se.text.strip()
                        elif "ValueMAC" == seTag:
                            KD_mac_b64 = se.text.strip()

                elif "Counter" == eTag:
                    for se in list(e):
                        seTag = getTagName(se)
                        if "PlainValue" == seTag:
                            KD_counter = se.text
                        else:
                            log.warning("We do only support PlainValue counters")
                elif "TimeInterval" == eTag:
                    for se in list(e):
                        seTag = getTagName(se)
                        if "PlainValue" == seTag:
                            KD_TimeInterval = se.text
                            log.debug("Found TimeInterval = %s" % KD_TimeInterval)
                        else:
                            log.warning("We do only support PlainValue for TimeInterval")
                elif "Time" == eTag:
                    for se in list(e):
                        seTag = getTagName(se)
                        if "PlainValue" == seTag:
                            KD_Time = se.text
                            log.debug("Found Time offset = %s" % KD_Time)
                        else:
                            log.warning("We do only support PlainValue for Time")

                else:
                    log.warning("Unparsed Tag in Key: %s" % eTag)

            if KD_algo and KD_hmac_key_b64:
                log.warning("The key %s contained a secret with PlainValue and EncryptedValue!" % serial)
            else:
                if "aes128-cbc" == ENC_ALGO:
                    #
                    #   Verifiy the MAC Value
                    #
                    if "hmac-sha1" == MAC_Method:

                        MAC_digest_bin = hmac.new(MACKEY_bin, base64.b64decode(KD_cipher_b64), sha).digest()
                        MAC_digest_b64 = base64.b64encode(MAC_digest_bin)
                        log.debug("AES128-CBC secret cipher: %s" % KD_cipher_b64)
                        log.debug("calculated MAC value    : %s" % MAC_digest_b64)
                        log.debug("read MAC value          : %s" % KD_mac_b64)

                        # decrypt key
                        HMAC_KEY_bin = aes_decrypt(KD_cipher_b64, ENCRYPTION_KEY_hex, serial)

                        if MAC_digest_b64 == KD_mac_b64:
                            TOKENS[serial] = { 'hmac_key' : binascii.hexlify(HMAC_KEY_bin),
                                        'counter' : KD_counter, 'type' : TOKEN_TYPE,
                                        'timeStep' : KD_TimeInterval, 'otplen' : KD_otplen,
                                        'hashlib' : KD_hashlib,
                                        'ocrasuite' : KD_Suite }
                        else:
                            log.error("The MAC value for %s does not fit. The HMAC secrets could be compromised!" % serial)
                            raise ImportException("The MAC value for %s does not fit. The HMAC secrets could be compromised!" % serial)
                            #TOKENS[serial] = { 'hmac_key' : binascii.hexlify(HMAC_KEY_bin),
                            #            'counter' : KD_counter, 'type' : TOKEN_TYPE,
                            #            'timeStep' : KD_TimeInterval, 'otplen' : KD_otplen,
                            #            'hashlib' : KD_hashlib }
                    else:
                        log.warning("At the moment we only support hmac-sha1. We found %s" % MAC_Method)

                elif KD_hmac_key_b64:
                    TOKENS[serial] = { 'hmac_key' : binascii.hexlify(base64.b64decode(KD_hmac_key_b64)),
                                        'counter' : KD_counter, 'type' : TOKEN_TYPE,
                                        'timeStep' : KD_TimeInterval, 'otplen' : KD_otplen,
                                        'hashlib' : KD_hashlib,
                                        'ocrasuite' : KD_Suite  }
                else:
                    log.warning("neither a PlainValue nor an EncryptedValue was found for the secret of key %s" % serial)

    return TOKENS

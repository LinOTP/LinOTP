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
"""
Parsing of pskc files:
    http://tools.ietf.org/search/rfc6030
"""

import base64
import binascii
import hashlib
import hmac
import logging
import re
import xml.etree.ElementTree as etree

import linotp.lib.crypto.pbkdf2 as pbkdf2
from linotp.lib.ImportOTP import ImportException, getTagName

sha = hashlib.sha1
md5 = hashlib.md5
sha256 = hashlib.sha256


log = logging.getLogger(__name__)


def checkSerial(serial):
    return re.match("[a-zA-Z0-9]{4}[a-fA-F0-9]{8}$", serial)


def getEncMethod(elem):
    algo = elem.get("Algorithm")
    m = re.search(r"#(.*)$", algo)
    if m:
        algo = m.group(1)
    if algo != "aes128-cbc":
        log.error("The algorithm %s is not supported", algo)
        msg = f"The algorithm {algo} is not supported"
        raise ImportException(msg)
    return algo


def getMacMethod(elem):
    meth = elem.get("Algorithm")
    m = re.search(r"#(.*)$", meth)
    if m:
        meth = m.group(1)
    if meth != "hmac-sha1":
        log.error("The method %s is not supported", meth)
        msg = f"The method {meth} is not supported"
        raise ImportException(msg)
    return meth


def aes_decrypt(transport_b64, key_hex, serial=""):
    import Cryptodome.Cipher.AES as AES

    def hack(data, serial=""):
        bsize = 16
        a = data[-1]
        # safety check if padding is bigger than blocksize
        # TODO: Fix: padding has to be elaborated with
        #                                  backward compatibility in mind
        if a > bsize:
            return data

        padding = data[len(data) - a :]
        if bytes([a]) * a != padding:
            # it seems not to be padded
            return data

        if a == bsize:
            # padding equals blocksize. This is not common!
            log.warning(
                "[aes_decrypt] the key of token %s is a multiple "
                "of blocksize but is padded. This is not compliant "
                "to the specification but we import it anyway.",
                serial,
            )
        return data[:-a]

    key_bin = binascii.unhexlify(key_hex)

    transport_bin = base64.b64decode(transport_b64)
    # print len( transport_bin )
    # print binascii.hexlify(transport_bin)

    iv_bin = transport_bin[0:16]
    encSecret_bin = transport_bin[16:]

    # iv_bin = base64.b64decode( transport_b64[0:16] )
    # encSecret_bin = base64.b64decode( transport_b64[16:] )

    aesObj = AES.new(key_bin, AES.MODE_CBC, iv_bin)
    result = aesObj.decrypt(encSecret_bin)

    result = hack(result, serial)

    return result


def parsePSKCdata(
    xml,
    preshared_key_hex=None,
    password=None,
    do_checkserial=True,
    do_feitian=False,
):
    """
    This function parses XML data of a PSKC file, (RFC6030)
    It can read
    * AES-128-CBC encrypted (preshared_key_bin) data
    * password based encrypted data
    * plain text data

    It returns a dictionary of
        serial : { hmac_key , counter, .... }
    """
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
        msg = "No toplevel element KeyContainer"
        raise ImportException(msg)

    tag = elem_keycontainer.tag
    match = re.match("^({.*?})Key[Cc]ontainer$", tag)
    namespace = ""
    if match:
        namespace = match.group(1)
        log.debug("Found namespace %s", namespace)

    KEYNAME = None
    MACKEY_bin = None
    ENC_ALGO = None

    PBE_DERIVE_ALGO = None
    PBE_SALT = None
    PBE_ITERATION_COUNT = None
    PBE_KEY_LENGTH = None

    # check for any encryption method 6.1, 6.2
    # Do the Encryption Key
    elem_encKey = elem_keycontainer.find(namespace + "EncryptionKey")

    if elem_encKey:
        # Check for AES-128-CBC, preshared key (chapter 6.1)
        enckeyTag = getTagName(next(iter(elem_encKey)))
        # This will hold the name of the preshared key
        if enckeyTag == "KeyName":
            KEYNAME = next(iter(elem_encKey)).text
            log.debug("The keyname of preshared encryption is <<%r>>", KEYNAME)
        # check for PasswordBasedEncyprion (chapter 6.2)
        elif enckeyTag == "DerivedKey":
            log.debug("We found PBE.")
            # Now we check for KeyDerivationMethod
            elem_keyderivation = list(next(iter(elem_encKey)))
            for e in elem_keyderivation:
                if getTagName(e) == "KeyDerivationMethod":
                    deriv_algo = e.get("Algorithm")
                    m = re.search(r"#(.*)$", deriv_algo)
                    PBE_DERIVE_ALGO = m.group(1)
                    log.debug("Algorithm of the PBE: %r", PBE_DERIVE_ALGO)
                    if PBE_DERIVE_ALGO == "pbkdf2":
                        for p in list(e):
                            if getTagName(p) == "PBKDF2-params":
                                for sp in list(p):
                                    spTag = getTagName(sp)
                                    if spTag == "Salt":
                                        for salt in list(sp):
                                            if getTagName(salt) == "Specified":
                                                PBE_SALT = salt.text
                                            else:
                                                log.warning(
                                                    "Unknown element in element Salt: %r",
                                                    getTagName(salt),
                                                )
                                    elif spTag == "IterationCount":
                                        PBE_ITERATION_COUNT = sp.text
                                    elif spTag == "KeyLength":
                                        PBE_KEY_LENGTH = sp.text
                    else:
                        # probably pbkdf1
                        log.error(
                            "We do not support key derivation method %r",
                            deriv_algo,
                        )
                        msg = f"We do not support key derivation method {deriv_algo}"
                        raise ImportException(msg)
                log.debug("found the salt <<%r>>", PBE_SALT)

            if password and len(password) > 5 and len(password) <= 64:
                log.debug(
                    "calculation encryption key from password [%s], salt: [%s] and "
                    "length: [%s], count: [%s]",
                    password,
                    PBE_SALT,
                    PBE_KEY_LENGTH,
                    PBE_ITERATION_COUNT,
                )
                ENCRYPTION_KEY_bin = pbkdf2.pbkdf2(
                    password.encode("ascii"),
                    base64.b64decode(PBE_SALT),
                    int(PBE_KEY_LENGTH),
                    int(PBE_ITERATION_COUNT),
                )
                ENCRYPTION_KEY_hex = binascii.hexlify(ENCRYPTION_KEY_bin)
                log.debug("calculated encryption key: %r", ENCRYPTION_KEY_hex)
            else:
                log.error(
                    "You must provide a password that is longer than 5 characters and up to 64 characters long."
                )
                msg = "You must provide a password that is longer than 5 characters and up to 64 characters long."
                raise ImportException(msg)

        # Do the MAC Key
        # This will hold the MAC key
        macmethod = elem_keycontainer.find(namespace + "MACMethod")
        MAC_Method = getMacMethod(macmethod)
        elem_mackey = macmethod.find(namespace + "MACKey")

        # Find the MAC: ENC_ALGO and MAC_bin
        for e in list(elem_mackey):
            tag = getTagName(e)
            if tag == "CipherData":
                for c in list(e):
                    cipher_tag = getTagName(c)
                    if cipher_tag == "CipherValue":
                        cipherValue = c.text.strip()
                        log.debug(
                            "Found this MAC Key cipherValue: <<%r>>",
                            cipherValue,
                        )
                        MACKEY_bin = aes_decrypt(cipherValue, ENCRYPTION_KEY_hex)
                    else:
                        log.error(
                            "Found unsupported child in CipherData: %r",
                            cipher_tag,
                        )
                        msg = f"Found unsupported child in CipherData: {cipher_tag!r}"
                        raise ImportException(msg)
            elif tag == "EncryptionMethod":
                ENC_ALGO = getEncMethod(e)
            else:
                log.warning("Found unknown tag: %r", tag)

    # End of Encryption Key
    # There is a keypackage per key
    # Now we get the list of keypackages

    elem_KeyPackageList = elem_keycontainer.findall(namespace + TAG_NAME_KEYPACKAGE)
    if len(elem_KeyPackageList) == 0:
        msg = f"No element {TAG_NAME_KEYPACKAGE} contained!"
        raise ImportException(msg)

    # Now parsing all the keys
    for elem_package in elem_KeyPackageList:
        # Do the keys

        elem_key = elem_package.find(namespace + "Key")

        serial = elem_key.get(TAG_TOKEN_ID)
        log.info("Processing token with serial (Key Id=%r)", serial)

        elem_deviceInfo = elem_package.find(namespace + "DeviceInfo")
        if elem_deviceInfo:
            # Try to find the real serial number
            elem_serial = elem_deviceInfo.find(namespace + "SerialNo")
            serial = elem_serial.text
            log.info("Processing token with the real SerialNo %r", serial)

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
            if algorithm.lower() == "hotp":
                TOKEN_TYPE = "hmac"
            elif algorithm.lower() == "totp":
                TOKEN_TYPE = "totp"
            elif algorithm.lower() == "ocra":
                TOKEN_TYPE = "ocra2"

        if do_checkserial and not checkSerial(serial):
            log.warning("serial %r is not a valid OATH serial", serial)
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
                log.debug("Evaluating element <<%r>>", eTag)
                if eTag == "ResponseFormat":
                    KD_otplen = int(e.get("Length"))
                    log.debug("Found length = %r", e.get("Length"))
                elif eTag == "Suite":
                    if TOKEN_TYPE == "ocra2":
                        KD_Suite = e.text
                        log.debug("Found OCRA Suite = %r", KD_Suite)
                    else:
                        # This can be HMAC-SHA256
                        KD_hashlib = e.text
                        if KD_hashlib.lower() == "hmac-sha256":
                            KD_hashlib = "sha256"
                        if KD_hashlib.lower() == "hmac-sha1":
                            KD_hashlib = "sha1"
                        log.debug("Found hashlib = %r", KD_hashlib)

            # Now we do all the Key Data: <pskc:Data>
            elem_keydata = elem_key.find(namespace + "Data")
            # Parse through the data of the Key
            KD_hmac_key_b64 = None
            KD_cipher_b64 = None
            KD_mac_b64 = None
            KD_algo = None
            KD_counter = None
            KD_TimeInterval = None
            for e in list(elem_keydata):
                eTag = getTagName(e)
                log.debug("Evaluating element <<%r>>", eTag)
                if eTag == "Secret":
                    for se in list(e):
                        seTag = getTagName(se)
                        if seTag == "EncryptedValue":
                            for ev in list(se):
                                evTag = getTagName(ev)
                                if evTag == "EncryptionMethod":
                                    KD_algo = getEncMethod(ev)
                                elif evTag == "CipherData":
                                    for ciph in list(ev):
                                        ciphTag = getTagName(ciph)
                                        if ciphTag == "CipherValue":
                                            KD_cipher_b64 = ciph.text.strip()

                        elif seTag == "PlainValue":
                            KD_hmac_key_b64 = se.text.strip()
                        elif seTag == "ValueMAC":
                            KD_mac_b64 = se.text.strip()

                elif eTag == "Counter":
                    for se in list(e):
                        seTag = getTagName(se)
                        if seTag == "PlainValue":
                            KD_counter = se.text
                        else:
                            log.warning("We do only support PlainValue counters")
                elif eTag == "TimeInterval":
                    for se in list(e):
                        seTag = getTagName(se)
                        if seTag == "PlainValue":
                            KD_TimeInterval = se.text
                            log.debug("Found TimeInterval = %r", KD_TimeInterval)
                        else:
                            log.warning(
                                "We do only support PlainValue for TimeInterval"
                            )
                elif eTag == "Time":
                    for se in list(e):
                        seTag = getTagName(se)
                        if seTag == "PlainValue":
                            KD_Time = se.text
                            log.debug("Found Time offset = %s", KD_Time)
                        else:
                            log.warning("We do only support PlainValue for Time")

                else:
                    log.warning("Unparsed Tag in Key: %r", eTag)

            if KD_algo and KD_hmac_key_b64:
                log.warning(
                    "The key %s contained a secret with PlainValuei "
                    "and EncryptedValue!",
                    serial,
                )
            else:
                if ENC_ALGO == "aes128-cbc":
                    #
                    #   Verifiy the MAC Value
                    #
                    if MAC_Method == "hmac-sha1":
                        MAC_digest_bin = hmac.new(
                            MACKEY_bin, base64.b64decode(KD_cipher_b64), sha
                        ).digest()
                        MAC_digest_b64 = base64.b64encode(MAC_digest_bin).decode()
                        log.debug("AES128-CBC secret cipher: %r", KD_cipher_b64)
                        log.debug("calculated MAC value    : %r", MAC_digest_b64)
                        log.debug("read MAC value          : %r", KD_mac_b64)

                        # decrypt key
                        HMAC_KEY_bin = aes_decrypt(
                            KD_cipher_b64, ENCRYPTION_KEY_hex, serial
                        )

                        if MAC_digest_b64 == KD_mac_b64:
                            TOKENS[serial] = {
                                "hmac_key": HMAC_KEY_bin.hex(),
                                "counter": KD_counter,
                                "type": TOKEN_TYPE,
                                "timeStep": KD_TimeInterval,
                                "otplen": KD_otplen,
                                "hashlib": KD_hashlib,
                                "ocrasuite": KD_Suite,
                            }
                        else:
                            log.error(
                                "The MAC value for %s does not fit. The HMAC "
                                "secrets could be compromised!",
                                serial,
                            )
                            msg = (
                                f"The MAC value for {serial} does not fit. The HMAC "
                                "secrets could be compromised!"
                            )
                            raise ImportException(msg)
                            # TOKENS[serial] = { 'hmac_key' : binascii.hexlify(HMAC_KEY_bin),
                            #            'counter' : KD_counter, 'type' : TOKEN_TYPE,
                            #            'timeStep' : KD_TimeInterval, 'otplen' : KD_otplen,
                            #            'hashlib' : KD_hashlib }
                    else:
                        log.warning(
                            "At the moment we only support hmac-sha1. We found %r",
                            MAC_Method,
                        )

                elif KD_hmac_key_b64:
                    TOKENS[serial] = {
                        "hmac_key": base64.b64decode(KD_hmac_key_b64).hex(),
                        "counter": KD_counter,
                        "type": TOKEN_TYPE,
                        "timeStep": KD_TimeInterval,
                        "otplen": KD_otplen,
                        "hashlib": KD_hashlib,
                        "ocrasuite": KD_Suite,
                    }
                else:
                    log.warning(
                        "neither a PlainValue nor an EncryptedValue was "
                        "found for the secret of key %s",
                        serial,
                    )

    return TOKENS

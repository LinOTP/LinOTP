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
""" methods to handle support files """

import os

from pylons.i18n.translation import _

import base64
import binascii
import M2Crypto

from linotp.lib.config import refreshConfig
from linotp.lib.config import getFromConfig
from linotp.lib.config import storeConfig
from linotp.lib.config import removeFromConfig

from linotp.lib.token import getTokenNumResolver


import logging
log = logging.getLogger(__name__)

__all__ = ["parseSupportLicense", "getSupportLicenseInfo", "readLicenseInfo",
           "setSupportLicense", "isSupportLicenseValid",
           "removeSupportLicenseInfo"]

PUB_KEY_DIRS = ['/etc/lseappliance/pubkeys']
PUB_KEY_EXTS = ['.pem']
PUB_KEY_LINOTP = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoqgA4ium1T+0UafBjenx
Dclj79Nj/g55iA+hH8dsP/rIMLjwe8kimikhhXqkTKz1qHQvBF00DLy3L/aGbnKk
x4//EcqdcODP6lmazWSfkuy0MNkPBki3C5h9IlSY2qTrZGlup5NcRO2KK7G5iQZS
7r0zzQlN1mFNiZmob4rLYdNkcFOz52/yBm8QV//dKvvmCNOuHJJl8zAT7R0Oe1M+
BbKBUlx/8GqnwpftJjOmH3qQUjQistt0XJvAOBk2G+jfLMknQmK+KmfzrCxkY1t7
+YrjBwJgMQhdAD/n4sjuI21BYx9iX5OpTiO+K+F0UC6IHCeqHexZObTpE8a7MB8+
7wIDAQAB
-----END PUBLIC KEY-----"""


class LicenseInfo(dict):
    """
    LicenseIfo
    special dict, which is able to return the original input strings,
    which is required to verify the License Signature
    """
    def __init__(self, *args, **kwargs):
        self.parent = super(LicenseInfo, self)
        self.parent.__init__(*args, **kwargs)
        self._list = []

    def add(self, line):
        self._list.append(line+'\n')
        key, val = line.split("=", 2)
        self[key.strip()] = val.strip()

    def info(self):
        return "".join(self._list)


class InvalidLicenseException(Exception):
    def __init__(self, message, type=None):
        super(InvalidLicenseException, self).__init__(message)
        self.type = type


def parseSupportLicense(licString):
    """
    parse the support subscription license

    :param licString: the support license as multiline string
    :return: tuple of license dict, extracted signature and the
                      license as string, which the signature could be checked
                      against
    """
    if not licString:
        error = _("Support not available, your product is unlicensed")
        log.error("[parseSupportLicense] Verification of support "
                  "license failed! %s" % (error))
        raise InvalidLicenseException(error, type='UNLICENSED')

    licInfo = LicenseInfo()
    signature = ""

    log.debug("[parseSupportLicense] license received: %r" % licString)
    licArry = licString.splitlines()

    if (licArry[0].strip() != "-----BEGIN LICENSE-----" and
            licArry[-1].strip() != "-----END LICENSE SIGNATURE-----"):
        log.error('Format error - not a valid license file! %r'
                  % licString[0:40])
        raise InvalidLicenseException('Format error - not a valid license '
                                      'file!', type='INVALID_FORMAT')

    read_license = 0
    read_signature = 0
    for line in licArry:
        l = line.strip()
        if l == "-----BEGIN LICENSE-----":
            read_license = 1
        elif l == "-----END LICENSE-----":
            read_license = 0
        elif l == "-----BEGIN LICENSE SIGNATURE-----":
            read_signature = 1
        elif l == "-----END LICENSE SIGNATURE-----":
            read_signature = 0
        else:
            if 1 == read_license:
                try:
                    licInfo.add(line)
                except Exception as exx:
                    log.debug("->parseLicense - %s: %r" % (l, exx))
            if 1 == read_signature:
                signature += l.rstrip()

    if len(signature) < 20 or len(licInfo) < 10:
        log.error('Format error - not a valid license file! %r'
                  % licString[0:40])
        raise InvalidLicenseException('Format error - not a valid '
                                      'license file!',
                                      type='INVALID_FORMAT')

    return (licInfo, base64.b64decode(signature))


def readLicenseInfo(filename):
    """
    parse the support subscription license

    :param filename: the file which contains the license
    :return: tuple of license dict, extracted signature and the
                      license as string, which the signature could be checked
                      against
    """
    with open(filename, 'r') as f:
        return parseSupportLicense(f.read())


def isSupportLicenseValid(licString=None, lic_dict=None, lic_sign=None,
                          raiseException=False):
    """
    verify the support subscription
    with respect to signature validity, expriration and volume

    :param licString: the support license
    :param raiseException: define if in case of an invalid license
                           an exception should be raised

    :return: tuple with validity and reason, if invalid
    """

    if not lic_dict or not lic_sign:
        lic_dict, lic_sign = parseSupportLicense(licString)
    return verifyLicenseInfo(lic_dict, lic_sign, raiseException=raiseException)


def setSupportLicense(licString):
    """
    set the license to be the current one

    :param licString: the license with description and signature
    :return: tuple with status (boolean) and if faild, the reason
    """
    ret = True
    msg = ''
    lic_dict, lic_sign = parseSupportLicense(licString)
    try:
        setSupportLicenseInfo(lic_dict, lic_sign)
    except Exception as exx:
        ret = False
        msg = "%s" % exx.message

    return ret, msg


def getSupportLicenseInfo():
    """
    get the current support and subscription information

    :param validate: inform program to validate or not the license info
    :return: tuple of dict with the license information and signature
             in case of an error, the dict and the signature are empty
    """
    refreshConfig()
    lic_dict = LicenseInfo()
    lic_sign = ""

    try:
        licString = getFromConfig("license", '')
        if licString:
            licBin = binascii.unhexlify(licString)
            lic_dict, lic_sign = parseSupportLicense(licBin)
    except InvalidLicenseException as exx:
        log.info('invalid license error %r' % exx)

    return lic_dict, lic_sign


def setSupportLicenseInfo(lic_dict, lic_sign):
    """
    set the license to be the current one

    :param lic_dict: the license with description
    :param lic_sign: the license signature
    :return: tuple with status (boolean) and if faild, the reason
    """

    verifyLicenseInfo(lic_dict, lic_sign, raiseException=True)

    lic_str = lic_dict.info()
    log.debug("[setSupportLicense] license %r", lic_str)

    licTemp = "-----BEGIN LICENSE-----\n"
    licTemp += lic_str
    licTemp += "-----END LICENSE-----\n"
    licTemp += "-----BEGIN LICENSE SIGNATURE-----\n"
    licTemp += base64.b64encode(lic_sign)
    licTemp += "\n-----END LICENSE SIGNATURE-----"

    storeConfig("license", binascii.hexlify(licTemp))
    log.info("[setLicense] license saved!")

    return True


def removeSupportLicenseInfo():
    removeFromConfig('license')


def verifyLicenseInfo(lic_dict, lic_sign, raiseException=False,
                      checkVolume=True):
    """
    verify the license information

    :param lic_dict: the dict with the license data
    :param lic_sign: the license signature
    :param raiseException: define if in case of an invalid license
                           an exception should be raised
    :return: tuple with validity and reason, if invalid
    """
    if not lic_dict:
        error = _("license file is empty!")
        log.error("[isSupportLicenseValid] Verification of support "
                  "license failed! %s" % (error))
        if raiseException:
            raise InvalidLicenseException(error, type='UNLICENSED')
        return False, error

    # ToDo: probably, we need to check the version number too!
    valid = verify_signature(lic_dict, lic_sign)
    if not valid:
        error = _("signature could not be verified!")
        log.error("[isSupportLicenseValid] Verification of support license"
                  " failed! %s\n %r" % (error, lic_dict.info()))
        if raiseException:
            raise InvalidLicenseException(error, type='INVALID_SIGNATURE')
        return False, error

    (valid, msg) = verify_expiration(lic_dict)
    if not valid:
        error = "%s" % msg
        log.error("[isSupportLicenseValid] Verification of support license "
                  "failed! %s\n %r" % (error, lic_dict.info()))
        if raiseException:
            raise InvalidLicenseException(error, type='EXPIRED')
        return False, error

    if checkVolume:
        valid, detail = verify_volume(lic_dict)
        if not valid:
            error = "volume exceeded:"
            try:
                error = _(error)
            except:
                pass
            error = error + detail
            log.error("[isSupportLicenseValid] Verification of support license"
                      " failed! %s\n %r" % (error, lic_dict.info()))
            if raiseException:
                raise InvalidLicenseException(error, type='INVALID_VOLUME')
            return False, error

    return True, "license OK"


def verify_signature(lic_dict, lic_sign, licStr=None):
    """
    verfiy the license signature with the m2crypto

    :param lic_dict: the dict with the license data
    :param lic_sign: the license signature

    :return: boolean
    """
    if not lic_dict:
        return False

    ret = False

    if not licStr:
        lic_str = lic_dict.info()
    else:
        lic_str = licStr

    log.debug("[verify_signature] license text: %r", lic_str)
    log.debug("[verify_signature] signature: %r",    lic_sign)

    pub_keys = get_public_keys()

    # verfiy signature with M2Crypto
    for pub_key in pub_keys:
        bio = M2Crypto.BIO.MemoryBuffer(pub_key)
        rsa = M2Crypto.RSA.load_pub_key_bio(bio)
        pubkey = M2Crypto.EVP.PKey()
        pubkey.assign_rsa(rsa)
        pubkey.reset_context(md="sha256")
        pubkey.verify_init()
        pubkey.verify_update(lic_str)

        if (pubkey.verify_final(lic_sign) == 1):
            ret = True
            break

    log.debug("[verify_signature] signature is %r" % ret)
    return ret


def verify_expiration(lic_dic):
    """
    verify that license has not expired by now

    :param lic_dic: the dict with the license date
    :return: boolean - true if still valid
    """

    if "expire" not in lic_dic:
        msg = "%s %r" % (_("no license expiration information in license "),
                         lic_dic.info())
        log.error(msg)
        return (False, msg)

    if "subscription" not in lic_dic:
        msg = "%s %r" % (_("no license subscription information in license"),
                         lic_dic.info())
        log.error(msg)
        return (False, msg)

    # we check only for the date string which has to be the first part of
    # the expiration date definition
    temp = (lic_dic.get('expire', '') or '').strip()
    if temp:
        expire = temp.split()[0].strip()
        if expire.lower() not in ('never'):
            return check_date('expire', expire)

    temp = (lic_dic.get('subscription', '') or '').strip()
    if temp:
        subscription = temp.split()[0].strip()
        return check_date('subscription', subscription)

    # old style license, we have to check the date entry for the subscription
    temp = (lic_dic.get('date', '') or '').strip()
    if temp:
        subscription = temp.split()[0].strip()
        return check_date('date', subscription)

    msg = _("invalid license (old license style)")
    return (False, msg)


def verify_volume(lic_dict):

    # get the current number of active tokens
    num = getTokenNumResolver()

    try:
        token_volume = int(lic_dict.get('token-num', 0))
    except TypeError as err:
        log.exception("failed to convert license token num value:%r :%r" %
                      (lic_dict.get('token-num'), err))
        return False, "max %d" % token_volume

    if num >= token_volume:
        log.error("licensed token volume exceeded %r>%r" % (num, token_volume))
        used = _("tokens used")
        licnu = _("tokens supported")
        detail = " %s: %d > %s: %d" % (used, num, licnu, token_volume)
        return False, detail

    return True, ""


def get_public_keys():
    """
    get a list of all public keys, which could be used to verify
    a linOTP license

    :return: list with unique public keys
    """

    pubKeys = set()  # we use a set to get only unique keys
    pubKeys.add(PUB_KEY_LINOTP)

    key_files = []
    for key_dir in PUB_KEY_DIRS:
        if os.path.isdir(key_dir):
            for key_file in os.listdir(key_dir):
                for extension in PUB_KEY_EXTS:
                    if key_file.endswith(extension):
                        key_files.append(os.path.join(key_dir, key_file))

    for key_file in key_files:
        try:
            key_text = readPublicKey(key_file, decode=False)
            if not (key_text is None):
                pubKeys.add(key_text)
            else:
                log.error("[get_public_keys] public key file is not valid"
                          " (%s)" % key_file)
        except Exception as exx:
            log.exception("[get_public_keys] error during reading "
                          "public key file (%s): %r" % (key_file, exx))

    return list(pubKeys)


def check_date(expire_type, expire):
    import datetime
    today = datetime.datetime.now()

    # -with  support for two date formats
    expiration_date = None
    for fmt in ('%d.%m.%Y', "%m/%d/%Y", "%Y-%m-%d"):
        try:
            expiration_date = datetime.datetime.strptime(expire, fmt)
            break
        except:
            log.info("license expiration format not of format %s : %r" %
                     (fmt, expire))
            expiration_date = None

    if not expiration_date:
        msg = "%s %r" % (_("unsupported date format date %r"), expire)
        log.error("check of %s failed: %s" % (expire_type, msg))
        return (False, msg)

    if today > expiration_date:
        msg = "%s %r" % (_("expired - valid till"), expire)
        log.error("check of %s failed: %s" % (expiration_date, msg))
        return (False, msg)

    return (True, '')


def _isRangeSeparator(line, key):
    if line.startswith('---') and line.endsswith('---'):
        return line.strip(['-']).strip().lower() == key.lower()
    return False


def readPublicKey(filename, decode=False):
    pem_lines = []

    f = open(filename, 'r')
    try:
        record = False
        for line in f:
            temp = line.strip()
            if len(temp) > 0:
                if not record:
                    if _isRangeSeparator(temp, 'BEGIN PUBLIC KEY'):
                        pem_lines.append(temp)
                        record = True
                elif _isRangeSeparator(temp, 'END PUBLIC KEY'):
                    pem_lines.append(temp)
                    break
                else:
                    pem_lines.append(temp)
    finally:
        f.close()

    if len(pem_lines) == 0:
        return None

    txt_lines = os.linesep.join(pem_lines)
    if decode:
        return base64.b64decode(txt_lines)
    return txt_lines

# eof #########################################################################

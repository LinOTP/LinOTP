# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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

PUB_KEY_DIRS = ['/etc/lseappliance/pubKeys']
PUB_KEY_EXTS = ['.pem']

pubKey_linOTP = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoqgA4ium1T+0UafBjenx
Dclj79Nj/g55iA+hH8dsP/rIMLjwe8kimikhhXqkTKz1qHQvBF00DLy3L/aGbnKk
x4//EcqdcODP6lmazWSfkuy0MNkPBki3C5h9IlSY2qTrZGlup5NcRO2KK7G5iQZS
7r0zzQlN1mFNiZmob4rLYdNkcFOz52/yBm8QV//dKvvmCNOuHJJl8zAT7R0Oe1M+
BbKBUlx/8GqnwpftJjOmH3qQUjQistt0XJvAOBk2G+jfLMknQmK+KmfzrCxkY1t7
+YrjBwJgMQhdAD/n4sjuI21BYx9iX5OpTiO+K+F0UC6IHCeqHexZObTpE8a7MB8+
7wIDAQAB
-----END PUBLIC KEY-----"""


from pylons.i18n.translation import _

import base64
import binascii
import M2Crypto

from linotp.lib.config import getFromConfig
from linotp.lib.config import storeConfig
from linotp.lib.config import refreshConfig
from linotp.lib.util import get_version_number
from linotp.lib.token import getTokenNumResolver



support_info = {
    'comment' :'LinOTP Support Info',
    'issuer' : '',
    'token-num' : '',
    'licensee' : '',
    'address' :  '<a href="http://www.lsexperts.de" target="_blank">http://www.lsexperts.de</a>',
    'contact-name' : '',
    'contact-email' : '<a href="mailto:linotp@lsexperts.de">linotp@lsexperts.de</a>',
    'contact-phone' : '+49 6151 86086-115',
    'date' : '',
    'expire' : '',
    'subscription' : _('You are using the open source version with community '
            'support. For professional support, feel free to contact '
            'LSE by email or by phone.')
    }

import logging
log = logging.getLogger(__name__)

__all__ = ["parseSupportLicense", "getSupportLicenseInfo",
           "setSupportLicense", "isSupportLicenseValid"]


def parseSupportLicense(licString):
    """
    parse the support subscription license

    :param licString: the support license as multiline string
    :return: tuple of license dict, extracted signature and the
                      license as string, which the signature could be checked
                      against
    """
    licInfo = {}
    signature = ""
    licStr = ""

    read_license = 0
    read_signature = 0

    log.debug("[parseSupportLicense] license received: %r" % licString)
    licArry = licString.split('\n')

    if (licArry[0].strip() != "-----BEGIN LICENSE-----" and
        licArry[-1].strip() != "-----END LICENSE SIGNATURE-----"):
        log.error('Format error - not a valid license file! %r'
                  % licString[0:40])
        raise Exception('Format error - not a valid license file!')

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
                licStr = licStr + l + "\n"
                try:
                    (key, val) = l.split("=", 2)
                    licInfo[key] = val
                except:
                    log.debug("->parseLicense - %s", l)
            if 1 == read_signature:
                signature += l.rstrip()

    log.debug("[parseSupportLicense]: %s", licStr)

    if len(signature) < 20 or len(licStr) < 20 or len(licInfo) < 10:
        log.error('Format error - not a valid license file! %r'
                  % licString[0:40])
        raise Exception('Format error - not a valid license file!')


    return (licInfo, signature, licStr)

def getSupportLicenseInfo():
    """
    get the current support and subscription information

    :return: dict with the license informstion
    """
    info = {}

    refreshConfig()
    licString = getFromConfig("license", None)
    if licString:
        try:
            lic_str = binascii.unhexlify(licString)
        except TypeError:
            lic_str = licString
        (info, _lic_sign, _lic_txt) = parseSupportLicense(lic_str)

    else:
        # if we have no licens in the config, we compose the
        # comuninity edition text
        info.update(support_info)
        version = get_version_number()
        info['version'] = 'LinOTP %s' % version

    return info


def setSupportLicense(licString):
    """
    set the license to be the current one

    :param licString: the license with description and signature
    :return: tuple with status (boolean) and if faild, the reason
    """

    log.debug("[setSupportLicense] license %r", licString)
    valid, msg = isSupportLicenseValid(licString)

    storeConfig("license", binascii.hexlify(licString))
    log.info("[setLicense] license saved!")

    return (valid, msg)

def isSupportLicenseValid(licString, raiseException=False):
    """
    verify the support subscription
    with respect to signature validity, expriration and volume

    :param licString: the support license
    :param raiseException: define if in case of an invalid license
                           an exception should be raised

    :return: tuple with validity and reason, if invalid
    """

    (lic_dict, lic_sign, lic_str) = parseSupportLicense(licString)

    valid = verify_signature(lic_str, lic_sign)
    if not valid:
        error = _("License is not valid!")
        log.error("[setLicense] Verification of support license failed! %s\n %r"
                  % (error, licString))
        if raiseException:
            raise Exception(error)
        return valid, error

    valid = verify_expiration(lic_dict)
    if not valid:
        error = _("Subscription expired!")
        log.error("[setLicense] Verification of support license failed! %s\n %r"
                  % (error, licString))
        if raiseException:
            raise Exception(error)
        return valid, error

    valid, detail = verify_volume(lic_dict)
    if not valid:
        error = _("License volume exceeded:") + detail
        log.error("[setLicense] Verification of support license failed! %s\n %r"
                  % (error, licString))
        if raiseException:
            raise Exception(error)
        return valid, error

    return valid, ""


def verify_expiration(lic_dic):
    """
    verify that license has not expired by now

    :param lic_dic: the dict with the license date
    :return: boolean - true if still valid
    """
    ret = True

    import datetime
    today = datetime.datetime.now()

    if "expire" not in lic_dic:
        log.error("no license expiration information in license  %r" % lic_dic)
        return False

    # we check only for the date string which has to be the first part of
    # the expiration date definition
    expire = lic_dic.get('expire').split()[0].strip()
    if expire.lower() in ('never'):
        expire = lic_dic.get('subscription').split()[0].strip()
        return True

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
        log.error("Failed to convert license expiration date %r" % expire)
        return False

    if today > expiration_date:
        log.error("License expiration date %r overdue" % expire)
        return False


    return ret

def verify_volume(lic_dict):

    # get the current number of active tokens
    num = getTokenNumResolver()

    try:
        token_volume = int(lic_dict.get('token-num', 0))
    except TypeError as err:
        log.error("failed to convert license token num value:%r :%r" %
                  (lic_dict.get('token-num'), err))
        return False, "max %d" % token_volume

    if num > token_volume:
        log.error("licensed token volume exceeded %r>%r" % (num, token_volume))
        used = _("tokens used")
        licnu = _("tokens supported")
        detail = " %s: %d > %s: %d" % (used, num, licnu, token_volume)
        return False, detail

    return True, ""

def verify_signature(lic_str, lic_sign):
    """
    verfiy the license signature with the m2crypto

    :param lic_str: the license text
    :param lic_sign: the license signature

    :return: boolean
    """
    ret = False

    signature = base64.b64decode(lic_sign.rstrip())

    log.debug("[verify_signature] signature: %r", signature)
    log.debug("[verify_signature] license text: %r", lic_str)

    pub_keys = get_public_keys()

    # verfify signature with M2Crypto
    for pub_key in pub_keys:
        bio = M2Crypto.BIO.MemoryBuffer(pub_key)
        rsa = M2Crypto.RSA.load_pub_key_bio(bio)
        pubkey = M2Crypto.EVP.PKey()
        pubkey.assign_rsa(rsa)
        pubkey.reset_context(md="sha256")
        pubkey.verify_init()
        pubkey.verify_update(lic_str)

        if (pubkey.verify_final(signature) == 1):
            ret = True
            break

    log.debug("[verify_signature] signature is %r" % ret)
    return ret


def get_public_keys():
    """
    get a list of all public keys, which could be used to verify
    a linOTP license

    :return: list with uniq public keys
    """
    pubKeyStart = "-----BEGIN PUBLIC KEY-----"
    pubKeyEnd = "-----END PUBLIC KEY-----"

    pubKeys = set()  # we use a set to get only uniq keys
    pubKeys.add(pubKey_linOTP)

    pem_files = []

    for pem_dir in PUB_KEY_DIRS:
        if not os.path.isdir(pem_dir):
            continue
        for pem_file in os.listdir(pem_dir):
            for extension in PUB_KEY_EXTS:
                ext = pem_file[-len(extension):]
                if extension == ext:
                    pem_files.append("%s%s%s" % (pem_dir, os.sep, pem_file))

    for pem_file in pem_files:
        lines = []
        pem_lines = []
        try:
            # we remove all empyt lines, which are mostly trailing ones
            f = open(pem_file, 'r')
            pem = f.read()
            lines = pem.split('\n')
            for line in lines:
                if len(line.strip()) > 0:
                    pem_lines.append(line)

        except Exception as exx:
            log.error("[get_public_keys] error during reading "
                      "public key file (%s): %r" % (pem_file, exx))

        # only add keys, which contain key defintion at start and at end
        if (len(pem_lines) > 0
             and pem_lines[0][:len(pubKeyStart)] == pubKeyStart
             and pem_lines[-1][:len(pubKeyEnd)] == pubKeyEnd):
            pubKeys.add('\n'.join(pem_lines))
        else:
            log.error("[get_public_keys] public key file is not valid"
                      " (%s)" % pem_file)

    return list(pubKeys)

#eof###########################################################################

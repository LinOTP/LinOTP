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
import datetime

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

PUB_KEY_DEMO = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuhvX1dSdWaNsPXqZ5GjH
x+40swvnKsluAErcSvHRWFIMRG4UcNRFUiHsb5plaKJJoG+1JLhatbVgbEPcibfl
evGFzM5sGxc4T9ZFQskUZ4aAGqc/xefqwcVDG886ohtMXao+kuNAi52bBXrz2Ktd
uFJ+4yTnzy87vuH7wvoHl/Vfb3Rvm4bM8/lDhnzhJgTeYYbaCJa8agSQg2TZFQK4
TRQc5SPaiqyb0maFweBSJnJyNW65ZjQ+5P35y1Sq3+ekRc/6kMBjruVcrUwK25rt
ly9jWWpwUrLK8L7y+I/c1EQM0SG5fjsEhByY+hbzYLVQI308/mMAQ9JgY07MXK3k
FwIDAQAB
-----END PUBLIC KEY----- """

PUB_KEYS = {'linotp': PUB_KEY_LINOTP,
            'demo': PUB_KEY_DEMO
            }


BLACK_SIGNATURES = [("BQ+Iney5b97jAS2pxDNqtsqYTItYZCyF55/s1jwJwdGoJJLwe"
                     "hjgzXIdl54Z8cQ3rmjWYSiQ74XmQrxjLi5WYX2JoG+AxCje53"
                     "s82i4XPAWFVvWggxU9SwhL+hmatAbi550dIIYmG3OQxX1iMeo"
                     "vIW5BrWdNLkXJJYsPncG81Wu0JBids5NrhNakUXvONYa8YV3b"
                     "MeZsMG1AYWqLbDjJcca0wF1dBV7X/9mJ+zkgcPPsviYSAkzFO"
                     "blwWPKhUbMgem/aXwBSs1r3TitD0Nh/cZW8Fu/DuRM0QSRZbB"
                     "dD9D5ZGd/nBSO2HajAEa4s/8EeDLoRUs0umZX3nn9nQOYGuw==")
                    ]


class LicenseInfo(dict):
    """
    LicenseInfo
    special dict, which is able to return the original input strings,
    which is required to verify the License Signature
    """
    def __init__(self, *args, **kwargs):
        """
        initialize the special dict with some additional attributes
        """
        # parent dict init
        self.parent = super(LicenseInfo, self)
        self.parent.__init__(*args, **kwargs)
        self._list = []

        # add some more license info attribute to preserve parsing result
        self.license_type = 'linotp'
        self.license_volume_info = None
        self.license_expiration = None
        self.signature = None

    def add(self, line):
        """
        special method to add the license text line by line
        * into the dict and
        * into an line array for regeneration of the initial input,
          which is required to compare the signature
        :param line: one line of the license, containing key value pairs
        """
        self._list.append(line+'\n')
        key, val = line.split("=", 2)
        self[key.strip()] = val.strip()

    def info(self):
        """
        info - return the reconstructed license text from the array
        :return: license as string
        """
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

    licInfo.signature = base64.b64decode(signature)
    if 'days' in licInfo.get('expire', ''):
        licInfo.license_expiration = licInfo['expire']

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
    res, reason = verifyLicenseInfo(lic_dict, lic_sign,
                                    raiseException=raiseException)
    return res, reason, lic_dict


def check_license_restrictions():
    """
    check if there are restrictions, which are caused by the license

    :return: boolean - True if there are  restrictions
    """

    license_str = getFromConfig('license')
    if not license_str:
        return False

    licString = binascii.unhexlify(license_str)
    lic_dict, lic_sign = parseSupportLicense(licString)
    res, reason = verifyLicenseInfo(lic_dict, lic_sign,
                                    raiseException=False)

    if not res:
        log.info("license check: %r", reason)

    license_type = lic_dict.license_type or 'standard'
    if license_type != 'download' and license_type != 'demo':
        return False

    # in case of a download license, we check hard limits
    import linotp.lib.token
    installed_tokens = int(linotp.lib.token.getTokenNumResolver())
    allowed_tokens = lic_dict.get('token-num', 'unlimited')
    try:
        allowed_tokens = int(allowed_tokens.strip())
        if installed_tokens >= allowed_tokens:
            log.info("license check: too many tokens enrolled %r",
                     allowed_tokens)
            return True
    except ValueError as _val_err:
        # in case of no int we ignore this restriction as it could
        # be a string representation like 'unlimited'
        pass

    res, _msg = verify_expiration(lic_dict)
    if res is False:
        log.info("license check: license expired!")
        return True

    return False


def setSupportLicense(licString):
    """
    set the license to be the current one

    :param licString: the license with description and signature
    :return: tuple with status (boolean) and if faild, the reason
    """
    ret = True
    msg = ''
    lic_info, lic_sign = parseSupportLicense(licString)
    try:
        setSupportLicenseInfo(lic_info, lic_sign)
    except Exception as exx:
        ret = False
        msg = "%s" % exx.message

    return ret, msg


def do_nagging(lic_info, nag_days=7):
    """
    do nagging - answer the question if nagging should be done

    :param lic_info: the license info
    :return: boolean - True if nagging should be displayed
    """
    d_fmt = "%Y-%m-%d"

    # we start 7 days after download license was installed
    nag_offset = nag_days

    if not (lic_info.license_type and (lic_info.license_type == 'download' or
                                       lic_info.license_type == 'demo')):
        return False

    # in case there is no duration definition in 'xx days' we do the nagging
    if not lic_info.license_expiration:
        log.error("download license format error: "
                  "missing expiration definition!")
        return True

    now_date = datetime.datetime.now().date()

    expire = get_expiration_date(lic_info)
    expire_date = datetime.datetime.strptime(expire, d_fmt).date()

    # calculate back, when the license was enrolled
    duration = int(lic_info.license_expiration.replace('days', '').strip())
    lic_start_date = expire_date - datetime.timedelta(days=duration)

    # calulate the nagging start date with given nag_offset
    nag_start_date = lic_start_date + datetime.timedelta(days=nag_offset)

    if now_date <= nag_start_date:
        return False

    # ok, we are in the nagging time frame, so start nagging
    last_nagged = getFromConfig('last_nagged')
    if last_nagged:
        # nag only once a day: check, if we nagged already today
        last_nag_date = datetime.datetime.strptime(last_nagged, d_fmt).date()
        # check if we nagged already today
        if last_nag_date >= now_date:
            return False

    datum = now_date.strftime(d_fmt)
    storeConfig('last_nagged', datum, desc='last nagged')

    return True


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
            lic_dict['expire'] = get_expiration_date(lic_dict)

    except InvalidLicenseException as exx:
        log.info('invalid license error %r' % exx)

    return lic_dict, lic_sign


def get_expiration_date(lic_dict):
    """
    if there is a duration in the license, we deliver the real expiration date
    :param lic_dict: the license info object
    :return: expiration date
    """

    expiration = lic_dict.get('expire', '')
    if expiration and 'days' in expiration:

        date_format = "%d%m%y"
        # fetch config and split the signature and the expiration date
        duration = getFromConfig('enclinotp.license_duration', None)
        _signature, _sep, date = duration.rpartition(':')

        # now we create the volatile entry for the expiration
        expiration_date = datetime.datetime.strptime(date, date_format)
        return expiration_date.strftime('%Y-%m-%d')

    return expiration


def verify_duration(lic_dict, raiseException=False):
    """
    verify that the license duration is not already expired

    :param lic_dict: the license info object
    :return: boolean, if expired or not
    """

    if not (lic_dict.license_expiration and
            'days' in lic_dict.license_expiration):
        return False

    date_format = "%d%m%y"

    # get the decrypted value from the config, if there is one
    duration = getFromConfig('enclinotp.license_duration', None)

    # no entry set by now, so this must be an error
    if not duration:
        log.error("license incorrectly installed!")
        return False

    # ok, we already have an entry
    else:
        # fetch config and split the signature and the expiration date
        _signature, _sep, date = duration.rpartition(':')
        expiration_date = datetime.datetime.strptime(date, date_format)
        now = datetime.datetime.now()
        if now > expiration_date + datetime.timedelta(days=1):
            return False

    return True


def setSupportLicenseInfo(lic_dict, lic_sign):
    """
    set the license to be the current one

    :param lic_dict: the license with description
    :param lic_sign: the license signature
    :return: tuple with status (boolean) and if faild, the reason
    """

    verifyLicenseInfo(lic_dict, lic_sign, raiseException=True)

    # first set the duration if there is one
    if not set_duration(lic_dict, raiseException=True):
        return False

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


def set_duration(lic_dict, raiseException=False):
    """
    set the duration value in linotp config and thus in config database

    :param lic_dict: the license info object
    :param raiseException: switch to control if an exception should be thrown
           in case of a problem
    """

    # if there is no expiration in the license we just can go on
    if not (lic_dict.license_expiration and
            'days' in lic_dict.license_expiration):
        return True

    lic_sign = lic_dict.signature
    days = lic_dict.license_expiration.replace('days', '').strip()
    try:
        days = int(days)
    except ValueError as _val:
        raise Exception('Unable to interpret duration in'
                        ' license description')

    # we have a timely limited version, so we have to check if there is
    # already a license like this installed by comparing the signatures
    date_format = "%d%m%y"

    # get the decrypted value from the config, if there is one
    expiration = getFromConfig('enclinotp.license_duration', None)
    if expiration:
        # fetch config and split the signature and the expiration date
        signature, _sep, _date_str = expiration.rpartition(':')

        # here we only verify that the license signature is not the same
        # - we only take a slice as the stored signature will be
        #   stored in an encrypted way and then will become too long
        if base64.b64encode(lic_sign)[:500] == signature:
            error = _('License already installed!')
            if raiseException:
                raise Exception(error)
            else:
                log.error(error)
                return False

    # so we calculate the expiration and store this together
    # with the license signature
    expires = datetime.datetime.now() + datetime.timedelta(days=days)
    expires_str = expires.strftime(date_format)

    # we take only some bytes as it is encrypted afterwards
    signature = base64.b64encode(lic_sign)[:500]
    license_expire = "%s:%s" % (signature, expires_str)

    storeConfig("license_duration", license_expire, typ='password')
    log.info("license_expiration %s" % license_expire)

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
    lic_dict.license_type = valid

    (valid, expiration) = verify_expiration(lic_dict)
    if not valid:
        error = "%s" % expiration
        log.error("[isSupportLicenseValid] Verification of support license "
                  "failed! %s\n %r" % (error, lic_dict.info()))
        if raiseException:
            raise InvalidLicenseException(error, type='EXPIRED')
        return False, error
    lic_dict.license_expiration = expiration

    if checkVolume:
        valid, volume_info = verify_volume(lic_dict)
        if not valid:
            error = "volume exceeded:"
            try:
                error = _(error)
            except:
                pass
            error = error + volume_info
            log.error("[isSupportLicenseValid] Verification of support license"
                      " failed! %s\n %r" % (error, lic_dict.info()))
            if raiseException:
                raise InvalidLicenseException(error, type='INVALID_VOLUME')
            return False, error

        lic_dict.license_volume_info = volume_info

    return True, "license OK"


def verify_signature(lic_dict, lic_sign, licStr=None):
    """
    verfiy the license signature with the m2crypto

    :param lic_dict: the dict with the license data
    :param lic_sign: the license signature

    :return: None or the name of the license
    """
    if not lic_dict:
        return None

    if not licStr:
        lic_str = lic_dict.info()
    else:
        lic_str = licStr

    log.debug("[verify_signature] license text: %r", lic_str)
    log.debug("[verify_signature] signature: %r",    lic_sign)

    # we first verify against the in-code PUB_KEYS
    # if this fails, we make the lookup in the file system

    pub_keys = PUB_KEYS
    ret = _verify_signature(pub_keys, lic_str, lic_sign)

    if not ret:
        pub_keys = get_public_keys()
        ret = _verify_signature(pub_keys, lic_str, lic_sign)

    return ret


def _verify_signature(pub_keys, lic_str, lic_sign):
    """
    _verify_signature - the internal signature verification helper

    :param pub_key: the dict with the pubkey_name and pubkey
    :param lic_str: the license as string
    :param lic_sign: the license signature
    :return: None or the name of the key
    """
    ret = None
    # blacklisted signatures
    if base64.b64encode(lic_sign) in BLACK_SIGNATURES:
        return False

    # verify signature with M2Crypto
    for pub_key_name, pub_key in pub_keys.items():

        # some M2Crypto magic
        bio = M2Crypto.BIO.MemoryBuffer(pub_key)
        rsa = M2Crypto.RSA.load_pub_key_bio(bio)
        pubkey = M2Crypto.EVP.PKey()
        pubkey.assign_rsa(rsa)
        pubkey.reset_context(md="sha256")
        pubkey.verify_init()
        pubkey.verify_update(lic_str)

        if (pubkey.verify_final(lic_sign) == 1):
            ret = pub_key_name
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
    if lic_dic.license_expiration and 'days' in lic_dic.license_expiration:
        return check_duration(lic_dic.license_expiration, lic_dic)

    temp = (lic_dic.get('expire', '') or '').strip()
    if temp:
        if 'days' in temp:
            return check_duration(temp, lic_dic)
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

    pubKeys = {}  # we use a dict to preserve the type of the license
    pubKeys['linotp'] = PUB_KEY_LINOTP

    key_files = set()
    for key_dir in PUB_KEY_DIRS:
        if os.path.isdir(key_dir):
            for key_file in os.listdir(key_dir):
                for extension in PUB_KEY_EXTS:
                    if key_file.endswith(extension):
                        key_files.add(os.path.join(key_dir, key_file))

    for key_file in key_files:
        try:
            key_text = readPublicKey(key_file)
            if key_text and key_text not in pubKeys.values():
                    idx = os.path.split(key_file)[-1]
                    if idx[-4:] == '.pem':
                        idx, _sep, _rest = idx.rpartition(".pem")
                    if idx[-4:] == '_pub':
                        idx, _sep, _rest = idx.rpartition("_pub")
                    pubKeys[idx] = key_text
            else:
                log.error("[get_public_keys] public key file is not valid"
                          " (%s)" % key_file)
        except Exception as exx:
            log.exception("[get_public_keys] error during reading "
                          "public key file (%s): %r" % (key_file, exx))

    return pubKeys


def check_duration(expire, lic_info):
    """
    check duration - check only for duration in days

    :param: the expiration string value
    :return: tuple of bool and the amount of days as string
    """
    if 'days' not in expire:
        return False, 'no expiration days found!'

    lic_sign = lic_info.signature

    # if there is already a license with duration installed
    # check if it is still valid
    date_format = "%d%m%y"
    duration = getFromConfig('enclinotp.license_duration', None)

    if duration:
        signature, _sep, date = duration.rpartition(':')
        expiration_date = datetime.datetime.strptime(date, date_format)

        # only check the current license
        if base64.b64encode(lic_sign)[:500] == signature:
            now = datetime.datetime.now()
            expiration_date = datetime.datetime.strptime(date, date_format)

            # preserve the volatile expiration date
            lic_info["expire"] = expiration_date.strftime("%Y-%m-%d")

            if now > expiration_date + datetime.timedelta(days=1):
                return False, 'License expired'

    duration = int(expire.replace('days', '').strip())
    return duration > 0, "%d days" % duration


def check_date(expire_type, expire):
    """
    check if the license date is still valid
    """
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


def readPublicKey(filename):
    """
    read the public key from a given file
    :param filename: the pem filename
    :return: string containing the pubkey
    """
    pubKeyStart = "-----BEGIN PUBLIC KEY-----"
    pubKeyEnd = "-----END PUBLIC KEY-----"

    pubKey = ''

    try:
        with open(filename, 'r') as f:
            pem = f.read()
    except Exception as exx:
        log.exception("problem reading public key file: %s: %r", filename, exx)

    pem_lines = []
    lines = pem.split('\n')
    for line in lines:
        # we drop all empty lines
        if line.strip():
            pem_lines.append(line)

    # only add keys, which contain key definition at start and at end
    if pem_lines and pubKeyStart in pem_lines[0] and pubKeyEnd in pem_lines[-1]:
        pubKey = '\n'.join(pem_lines)

    else:
        log.error("public key file is not valid (%s)" % filename)

    return pubKey

# eof ########################################################################

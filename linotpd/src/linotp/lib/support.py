# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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

import sys, os

from pylons.i18n.translation import _

import base64
import binascii
import M2Crypto

from linotp.lib        import deprecated  
from linotp.lib.config import refreshConfig, getFromConfig, storeConfig, removeFromConfig
from linotp.lib.util   import get_version_number
from linotp.lib.token  import getTokenNumResolver
from linotp.lib.reply  import LinOTPJsonEncoder


import logging
log = logging.getLogger(__name__)

__all__ = ["parseSupportLicense", "getSupportLicenseInfo",
           "setSupportLicense", "isSupportLicenseValid"]

PUB_KEY_DIRS   = ['/etc/lseappliance/pubkeys']
PUB_KEY_EXTS   = ['.pem']
PUB_KEY_LINOTP = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoqgA4ium1T+0UafBjenx
Dclj79Nj/g55iA+hH8dsP/rIMLjwe8kimikhhXqkTKz1qHQvBF00DLy3L/aGbnKk
x4//EcqdcODP6lmazWSfkuy0MNkPBki3C5h9IlSY2qTrZGlup5NcRO2KK7G5iQZS
7r0zzQlN1mFNiZmob4rLYdNkcFOz52/yBm8QV//dKvvmCNOuHJJl8zAT7R0Oe1M+
BbKBUlx/8GqnwpftJjOmH3qQUjQistt0XJvAOBk2G+jfLMknQmK+KmfzrCxkY1t7
+YrjBwJgMQhdAD/n4sjuI21BYx9iX5OpTiO+K+F0UC6IHCeqHexZObTpE8a7MB8+
7wIDAQAB
-----END PUBLIC KEY-----"""


if sys.version_info < (2,7,0):
    class LegacyLicenseInfo:
        class OrderedItem:
            def __init__(self, value, key=None, oprev=None, onext=None):
                self.value = value
                self.key   = key
                self.prev  = oprev
                self.next  = onext
                
        def __init__(self, *args, **kwds):
            if len(args) > 1:
                raise TypeError('expected maximal 1 argument, specified were %d' % len(args))
            self.__root = None
            self.__last = None
            self.__map  = {}
            self.update(*args, **kwds)
    
        def has_key(self, key):
            return self.__map.has_key(key)
    
        def __len__(self):
            return len(self.__map)
        
        def __getitem__(self, key):
            oitem = self.__map[key]
            if oitem is None:
                return None
            return oitem.value
            
        def __setitem__(self, key, value):
            if key in self.__map:
                oitem = self.__map[key]
                oitem.value = value
            else:
                olast       = self.__last
                self.__last = LegacyLicenseInfo.OrderedItem(value, key=key, prev=olast)
                if not (olast is None):
                    olast.next  = self.__last
                if self.__root is None:
                    # assert(last is None)
                    self.__root = self.__last
                self.__map[key] = self.__last
    
        def __delitem__(self, key):
            oitem = self.__map.pop(key)
            if oitem is None:
                return
            
            oprev = oitem.prev
            onext = oitem.next
            if oprev is None:
                self.__root = onext
            else:
                oprev.next  = onext
            if onext is None:
                self.__last = oprev
            else:
                onext.prev  = oprev
            
        def __iter__(self):
            oitem = self.__root
            while not (oitem is None):
                yield oitem.key
                oitem = oitem.next
    
        def __reversed__(self):
            oitem = self.__last
            while not (oitem is None):
                yield oitem.key
                oitem = oitem.prev
    
        def clear(self):
            self.__root = None
            self.__last = None
            self.__map.clear()
            dict.clear(self)
    
        def get(self, key, default=None):
            if self.__map.has_key(key):
                return self.__map[key].value
            return default
        
        def popitem(self, last=True):
            if not self:
                raise KeyError('dictionary is empty')
            if last:
                oitem = self.__last
                otemp = oitem.prev
                if not (otemp is None):
                    otemp.next = None
                self.__last = otemp
            else:
                oitem = self.__root
                otemp = oitem.next
                if not (otemp is None):
                    otemp.prev = None
                self.__root = otemp
            del self.__map[oitem.key]
            value = dict.pop(self, oitem.key)
            return oitem.key, value
    
        def keys(self):
            return list(self)
        
        def values(self):
            return [self[key] for key in self]
        
        def items(self):
            return [(key, self[key]) for key in self]

        def copy(self):
            return self.__class__(self)
    
        def update(self, *args, **kwds):
            if len(args) > 1:
                raise TypeError('update() takes maximal 1 positional '
                                'argument (%d given)' % (len(args),))
            
            if len(args) > 0:
                other = args[0]
                if isinstance(other, dict):
                    for key in other:
                        self[key] = other[key]
                elif hasattr(other, 'keys'):
                    for key in other.keys():
                        self[key] = other[key]
                else:
                    for key, value in other:
                        self[key] = value
                        
            for key, value in kwds.items():
                self[key] = value
                
        __marker = object()
        def pop(self, key, default=__marker):
            if key in self:
                result = self[key]
                del self[key]
                return result
            if default is self.__marker:
                raise KeyError(key)
            return default
    
        def setdefault(self, key, default=None):
            if key in self:
                return self[key]
            self[key] = default
            return default
        
        def __eq__(self, other):
            if isinstance(other, LegacyLicenseInfo):
                return len(self)==len(other) and self.items() == other.items()
            if isinstance(other, dict):
                return len(self)==len(other) and self.items() == other.items()
            return False #dict.__eq__(self, other)
    
        def __ne__(self, other):
            return not self == other
        
    def licenseJsonEncoder(licinfo):
        return licinfo.items()
    
    # Register our own "LicenseInfo" Json-Encoder...
    LinOTPJsonEncoder.registerEncoder(LegacyLicenseInfo, licenseJsonEncoder)
    
    LicenseInfo = LegacyLicenseInfo
else:
    from collections import OrderedDict
    LicenseInfo = OrderedDict


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
        log.error('Format error - license file is empty!')
        raise Exception('Format error - license file is empty!')

    licInfo   = LicenseInfo()
    signature = ""

    log.debug("[parseSupportLicense] license received: %r" % licString)
    licArry = licString.splitlines()

    if (licArry[ 0].strip() != "-----BEGIN LICENSE-----" and
        licArry[-1].strip() != "-----END LICENSE SIGNATURE-----"):
        log.error('Format error - not a valid license file! %r'
                  % licString[0:40])
        raise InvalidLicenseException('Format error - not a valid license file!', type='INVALID_FORMAT')

    read_license   = 0
    read_signature = 0
    for line in licArry:
        l = line.strip()
        if   l == "-----BEGIN LICENSE-----":
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
                    key, val = l.split("=", 2)
                    licInfo[key] = val
                except:
                    log.debug("->parseLicense - %s", l)
            if 1 == read_signature:
                signature += l.rstrip()

    if len(signature) < 20 or len(licInfo) < 10: #or len(licStr) < 20:
        log.error('Format error - not a valid license file! %r'
                  % licString[0:40])
        raise InvalidLicenseException('Format error - not a valid license file!', type='INVALID_FORMAT')

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

        
@deprecated
def isSupportLicenseValid(licString, raiseException=False):
    """
    verify the support subscription
    with respect to signature validity, expriration and volume

    :param licString: the support license
    :param raiseException: define if in case of an invalid license
                           an exception should be raised

    :return: tuple with validity and reason, if invalid
    """

    lic_dict, lic_sign = parseSupportLicense(licString)
    return verifyLicenseInfo(lic_dict, lic_sign, raiseException=raiseException)

def setSupportLicense(licString):
    """
    set the license to be the current one

    :param licString: the license with description and signature
    :return: tuple with status (boolean) and if faild, the reason
    """
    lic_dict, lic_sign = parseSupportLicense(licString)
    setSupportLicenseInfo(lic_dict, lic_sign)


def getSupportLicenseInfo(validate=True, raiseException=True):
    """
    get the current support and subscription information

    :param validate: inform program to validate or not the license info
    :return: dict with the license informstion
    """

    refreshConfig()
    licString = getFromConfig("license", None)
    try:
        if licString:
            licString = binascii.unhexlify(licString)
    except TypeError:
        pass
            
    try:
        if not licString:
            raise InvalidLicenseException('Support not available, your product is unlicensed', type='UNLICENSED')

        lic_dict, lic_sign = parseSupportLicense(licString)
        if not validate:
            return lic_dict, lic_sign
    except InvalidLicenseException as err:
        if not validate or raiseException:
            raise
        return False, str(err)
        
    valid, msg = verifyLicenseInfo(lic_dict, lic_sign, raiseException=raiseException)
    if raiseException:
        return lic_dict
    elif not valid:
        return False, msg
    return True, lic_dict

def setSupportLicenseInfo(lic_dict, lic_sign):
    """
    set the license to be the current one

    :param lic_dict: the license with description
    :param lic_sign: the license signature
    :return: tuple with status (boolean) and if faild, the reason
    """

    #valid, msg = 
    verifyLicenseInfo(lic_dict, lic_sign, raiseException=True)

    lic_str = packLicenseInfo(lic_dict)
    log.debug("[setSupportLicense] license %r", lic_str)

    licTemp  = "-----BEGIN LICENSE-----\n"
    licTemp += lic_str 
    licTemp += "-----END LICENSE-----\n" 
    licTemp += "-----BEGIN LICENSE SIGNATURE-----\n"
    licTemp += base64.b64encode(lic_sign)
    licTemp += "\n-----END LICENSE SIGNATURE-----"

    storeConfig("license", binascii.hexlify(licTemp))
    log.info("[setLicense] license saved!")

def removeSupportLicenseInfo():
    removeFromConfig('license')
    

def verifyLicenseInfo(lic_dict, lic_sign, raiseException=False, checkVolume=True): 
    """
    verify the license information

    :param lic_dict: the dict with the license data
    :param lic_sign: the license signature
    :param raiseException: define if in case of an invalid license
                           an exception should be raised
    :return: tuple with validity and reason, if invalid
    """
    if not lic_dict:
        error = "license file is empty!"
        try:
            error = _(error)
        except TypeError:
            pass
        log.error("[isSupportLicenseValid] Verification of support license failed! %s"
                  % (error))
        if raiseException:
            raise InvalidLicenseException(error, type='UNLICENSED')
        return False, error

    # ToDo: probably, we need to check the version number too!

    valid = verify_signature(lic_dict, lic_sign)
    if not valid:
        error = "signature could not be verified!"
        try:
            error = _(error)
        except TypeError:
            pass
        log.error("[isSupportLicenseValid] Verification of support license failed! %s\n %r"
                  % (error, packLicenseInfo(lic_dict)))
        if raiseException:
            raise InvalidLicenseException(error, type='INVALID_SIGNATURE')
        return False, error

    (valid, msg) = verify_expiration(lic_dict)
    if not valid:
        error = "%s" % msg
        log.error("[isSupportLicenseValid] Verification of support license failed! %s\n %r"
                  % (error, packLicenseInfo(lic_dict)))
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
            log.error("[isSupportLicenseValid] Verification of support license failed! %s\n %r"
                      % (error, packLicenseInfo(lic_dict)))
            if raiseException:
                raise InvalidLicenseException(error, type='INVALID_VOLUME')
            return False, error

    return True, "license OK"

def verify_signature(lic_dict, lic_sign):
    """
    verfiy the license signature with the m2crypto

    :param lic_dict: the dict with the license data
    :param lic_sign: the license signature

    :return: boolean
    """
    if not lic_dict:
        return False

    ret = False
    
    lic_str = packLicenseInfo(lic_dict)

    log.debug("[verify_signature] license text: %r", lic_str)
    log.debug("[verify_signature] signature: %r",    lic_sign)

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
        msg = "no license expiration information in license  %r" % lic_dic
        log.error(msg)
        return (False, msg)

    if "subscription" not in lic_dic:
        msg = "no license subscription information in license  %r" % lic_dic
        log.error(msg)
        return (False, msg)

    # we check only for the date string which has to be the first part of
    # the expiration date definition
    temp = (lic_dic.get('expire','') or '').strip()
    if temp:
        expire = temp.split()[0].strip()
        if expire.lower() not in ('never'):
            return check_date('expire', expire)

    temp = (lic_dic.get('subscription','') or '').strip() 
    if temp:
        subscription = temp.split()[0].strip()
        return check_date('subscription', subscription)

    # old style license, we have to check the date entry for the subscription
    temp = (lic_dic.get('date','') or '').strip() 
    if temp:
        subscription = temp.split()[0].strip()
        return check_date('date', subscription)
    
    msg = "invalid license (old license style)"
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

    :return: list with uniq public keys
    """

    pubKeys = set()  # we use a set to get only uniq keys
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
        msg = "unsuported date format date %r" % (expire)
        log.error("check of %s failed: %s" % (expire_type, msg))
        return (False, msg)

    if today > expiration_date:
        msg_txt = "expired - valid till"
        try:
            msg_txt = _(msg_txt)
        except TypeError:
            pass
        msg = "%s %r" % (msg_txt, expire)
        log.error("check of %s failed: %s" % (expiration_date, msg))
        return (False, msg)

    return (True,'')

def packLicenseInfo(lic_dict):
    if not lic_dict:
        return None
    lic_str = ''
    for k, v in lic_dict.items():
        lic_str += "%s=%s\n" % (k, v)
    return lic_str
    
def isRangeSeparator(line, key):
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
                    if isRangeSeparator(temp, 'BEGIN PUBLIC KEY'):
                        pem_lines.append(temp)
                        record = True
                elif isRangeSeparator(temp, 'END PUBLIC KEY'):
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

#eof###########################################################################

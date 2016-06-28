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
'''access to all cryptographic aspects - declare the SecretObject to
encapsulate security aspects
'''


import hmac
import logging
import struct
from hashlib import sha256
import base64

import binascii
import os
import stat

from pysodium import crypto_scalarmult_curve25519 as calc_dh
from pysodium import crypto_scalarmult_curve25519_base as calc_dh_base
from pysodium import crypto_sign_keypair as gen_dsa_keypair
from pysodium import sodium as c_libsodium
from pysodium import __check as __libsodium_check

''' for the hmac algo, we have to check the python version '''
import sys
(ma, mi, _, _, _,) = sys.version_info
pver = float(int(ma) + int(mi) * 0.1)

import ctypes
import linotp

from pylons.configuration import config as env
from pylons import tmpl_context as c
from linotp.lib.error import HSMException
from linotp.lib.error import ConfigAdminError

import Cryptodome.Hash as CryptoHash
from Cryptodome.Hash import HMAC
from Cryptodome.Hash import SHA as SHA1
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import SHA512
from Cryptodome.Cipher import AES


from linotp.lib.ext.pbkdf2  import PBKDF2
from linotp.lib.context import request_context as context
from linotp.lib.error import ValidateError

from pylons import config

try:
    import json
except ImportError:
    import simplejson as json


log = logging.getLogger(__name__)

c_hash = {
         'sha1': SHA1,
         'sha256': SHA256,
         }

try:
    from Cryptodome.Hash import SHA224
    c_hash['sha224'] = SHA224
except:
    log.warning('Your system does not support Crypto SHA224 hash algorithm')

try:
    from Cryptodome.Hash import SHA384
    c_hash['sha384'] = SHA384
except:
    log.warning('Your system does not support Crypto SHA384 hash algorithm')

try:
    from Cryptodome.Hash import SHA512
    c_hash['sha512'] = SHA512
except:
    log.warning('Your system does not support Crypto SHA512 hash algorithm')



# constant - later taken from the env?
CONFIG_KEY = 1
TOKEN_KEY = 2
VALUE_KEY = 3


class SecretObj(object):
    def __init__(self, val, iv, preserve=True, hsm=None):
        self.val = val
        self.iv = iv
        self.bkey = None
        self.preserve = preserve
        self.hsm = hsm

    def getKey(self):
        log.debug('Warning: Requesting secret key '
                  '- verify the usage scope and zero + free ')
        return decrypt(self.val, self.iv, hsm=self.hsm)

    def getPin(self):
        return decrypt(self.val, self.iv, hsm=self.hsm)

    def compare(self, key):
        bhOtpKey = binascii.unhexlify(key)
        enc_otp_key = encrypt(bhOtpKey, self.iv, hsm=self.hsm)
        otpKeyEnc = binascii.hexlify(enc_otp_key)
        return (otpKeyEnc == self.val)


    def hmac_digest(self, data_input, hash_algo):
        self._setupKey_()
        if pver > 2.6:
            h = hmac.new(self.bkey, data_input, hash_algo).digest()
        else:
            h = hmac.new(self.bkey, str(data_input), hash_algo).digest()
        self._clearKey_(preserve=self.preserve)
        return h

    def aes_decrypt(self, data_input):
        '''
        support inplace aes decryption for the yubikey

        :param data_input: data, that should be decrypted
        :return: the decrypted data
        '''
        self._setupKey_()
        aes = AES.new(self.bkey, AES.MODE_ECB)
        msg_bin = aes.decrypt(data_input)
        self._clearKey_(preserve=self.preserve)
        return msg_bin

    @staticmethod
    def encrypt(seed, iv=None, hsm=None):
        if not iv:
            iv = geturandom(16)
        enc_seed = encrypt(seed, iv, hsm=hsm)
        return iv, enc_seed

    @staticmethod
    def decrypt(enc_seed, iv=None, hsm=None):
        dec_seed = decrypt(enc_seed, iv=iv, hsm=hsm)
        return dec_seed

    @staticmethod
    def hash_pin(pin, iv=None, hsm=None):
        if not iv:
            iv = geturandom(16)
        hashed_pin = hash(pin, iv)
        return iv, hashed_pin

    @staticmethod
    def encrypt_pin(pin, iv=None, hsm=None):
        """
        returns a concatenated 'iv:crypt'
        """
        if not iv:
            iv = geturandom(16)
        enc_pin = encryptPin(pin, iv=iv, hsm=hsm)
        return enc_pin

    @staticmethod
    def decrypt_pin(pin, hsm=None):
        dec_pin = decryptPin(pin, hsm=hsm)
        return dec_pin

    def encryptPin(self):
        self._setupKey_()
        res = encryptPin(self.bkey)
        self._clearKey_(preserve=self.preserve)
        return res

    def _setupKey_(self):
        if not hasattr(self, 'bkey'):
            self.bkey = None

        if self.bkey is None:
            akey = decrypt(self.val, self.iv, hsm=self.hsm)
            self.bkey = binascii.unhexlify(akey)
            zerome(akey)
            del akey

    def _clearKey_(self, preserve=False):
        if preserve is False:

            if not hasattr(self, 'bkey'):
                self.bkey = None

            if self.bkey is not None:
                zerome(self.bkey)
                del self.bkey

    def __del__(self):
        self._clearKey_()

    def __enter__(self):
        self._clearKey_()

    def __exit__(self, type, value, traceback):
        self._clearKey_()


def getSecretDummy():
    log.debug('getSecretDummy()')
    return "no secret file defined: linotpSecretFile!"


def getSecret(id=0):
    log.debug('getSecret()')

    if not env.has_key("linotpSecretFile"):
        log.error("[getSecret] no secret file defined. A parameter linotpSecretFile is missing in your linotp.ini.")
        raise Exception("no secret file defined: linotpSecretFile!")

    secFile = env["linotpSecretFile"]

    # if True == isWorldAccessible(secFile):
    #    log.error("file permission of the secret file :%s: are not secure!", secFile)
    #    raise Exception("permissions of the secret file are not secure!")
    secret = ''

    try:
        f = open(secFile)
        for _i in range(0, id + 1):
            secret = f.read(32)
        f.close()
        if secret == "":
            # secret = setupKeyFile(secFile, id+1)
            raise Exception("No secret key defined for index: %s !\n"
                             "Please extend your %s !"
                             % (unicode(id), secFile))
    except Exception as exx:
        raise Exception("Exception: %r" % exx)

    return secret


def setupKeyFile(secFile, maxId):
    secret = ''
    for index in range(0, maxId):
        f = open(secFile)
        for _c in range(0, index + 1):
            secret = f.read(32)
        f.close()

        # if no secret: fill in a new one
        if secret == "":
            f = open(secFile, 'ab+')
            secret = geturandom(32)
            f.write(secret)
            f.close()

    return secret


def isWorldAccessible(filepath):
    log.debug('isWorldAccessible()')

    st = os.stat(filepath)
    u_w = bool(st.st_mode & stat.S_IWUSR)
    g_r = bool(st.st_mode & stat.S_IRGRP)
    g_w = bool(st.st_mode & stat.S_IWGRP)
    o_r = bool(st.st_mode & stat.S_IROTH)
    o_w = bool(st.st_mode & stat.S_IWOTH)
    return g_r or g_w or o_r or o_w or u_w


def _getCrypto(description):
    '''
       Convert the name of a hash algorithm as described in the OATH
       specifications, to a python object handling the digest algorithm
       interface
    '''
    algo = getattr(CryptoHash, description.upper(), None)
    # if not callable(algo):
    #    raise ValueError, ('Unknown hash algorithm', s[1])
    return algo


def check(st):
    """
    calculate the checksum of st
    :param st: input string
    :return: the checksum code as 2 hex bytes
    """
    sum = 0
    arry = bytearray(st)
    for x in arry:
        sum = sum ^ x
    res = str(hex(sum % 256))[2:]
    if len(res) < 2:
        res = '0' * (2 - len(res)) + res
    return res.upper()


def createActivationCode(acode=None, checksum=True):
    """
    create the activation code

    :param acode: activation code or None
    :param checksum: flag to indicate, if a checksum will be calculated
    :return: return the activation code
    """
    if acode is None:
        acode = geturandom(20)
    activationcode = base64.b32encode(acode)
    if checksum is True:
        chsum = check(acode)
        activationcode = u'' + activationcode + chsum

    return activationcode


def createNonce(len=64):
    """
    create a nonce - which is a random string
    :param len: len of bytes to return
    :return: hext string
    """
    key = os.urandom(len)
    return binascii.hexlify(key)


def kdf2(sharedsecret, nonce, activationcode, len, iterations=10000,
         digest='SHA256', macmodule=HMAC, checksum=True):
    '''
    key derivation function

    - takes the shared secret, an activation code and a nonce to generate
      a new key
    - the last 4 btyes (8 chars) of the nonce is the salt
    - the last byte    (2 chars) of the activation code are the checksum
    - the activation code mitght contain '-' signs for grouping char blocks
       aabbcc-ddeeff-112233-445566

    :param sharedsecret:    hexlified binary value
    :param nonce:           hexlified binary value
    :param activationcode:  base32 encoded value

    '''
    digestmodule = c_hash.get(digest.lower(), None)

    byte_len = 2
    salt_len = 8 * byte_len

    salt = u'' + nonce[-salt_len:]
    bSalt = binascii.unhexlify(salt)
    activationcode = activationcode.replace('-', '')

    acode = activationcode
    if checksum is True:
        acode = str(activationcode)[:-2]

    try:
        bcode = base64.b32decode(acode)

    except Exception as exx:
        error = "Error during decoding activationcode %r: %r" % (acode, exx)
        log.error(error)
        raise Exception(error)

    if checksum is True:
        checkCode = str(activationcode[-2:])
        veriCode = str(check(bcode)[-2:])
        if checkCode != veriCode:
            raise Exception('[crypt:kdf2] activation code checksum error!!'
                            ' [%s]%s:%s' % (acode, veriCode, checkCode))

    activ = binascii.hexlify(bcode)
    passphrase = u'' + sharedsecret + activ + nonce[:-salt_len]
    keyStream = PBKDF2(binascii.unhexlify(passphrase), bSalt,
                       iterations=iterations, digestmodule=digestmodule)
    key = keyStream.read(len)
    return key


def hash(val, seed, algo=None):
    log.debug('hash()')
    m = sha256()
    m.update(val.encode('utf-8'))
    m.update(seed)
    return m.digest()


def encryptPassword(password):

    log.debug('encryptPassword()')
    if hasattr(c, 'hsm') is False or isinstance(c.hsm, dict) is False:
        raise HSMException('no hsm defined in execution context!')

    hsm = c.hsm.get('obj')
    if hsm is None or hsm.isReady() is False:
        raise HSMException('hsm not ready!')

    ret = hsm.encryptPassword(password)
    return ret


def encryptPin(cryptPin, iv=None, hsm=None):

    if hsm:
        hsm_obj = hsm.get('obj')
    else:
        log.debug('encryptPin()')
        if hasattr(c, 'hsm') is False or isinstance(c.hsm, dict) is False:
            raise HSMException('no hsm defined in execution context!')
        hsm_obj = c.hsm.get('obj')

    if hsm_obj is None or hsm_obj.isReady() is False:
        raise HSMException('hsm not ready!')

    ret = hsm_obj.encryptPin(cryptPin, iv)
    return ret


def decryptPassword(cryptPass):

    log.debug('decryptPassword()')
    if hasattr(c, 'hsm') is False or isinstance(c.hsm, dict) is False:
        raise HSMException('no hsm defined in execution context!')

    hsm = c.hsm.get('obj')
    if hsm is None or hsm.isReady() is False:
        raise HSMException('hsm not ready!')

    ret = hsm.decryptPassword(cryptPass)
    return ret


def decryptPin(cryptPin, hsm=None):

    log.debug('decryptPin()')
    if hsm:
        hsm_obj = hsm.get('obj')
    else:
        if hasattr(c, 'hsm') is False or isinstance(c.hsm, dict) is False:
            raise HSMException('no hsm defined in execution context!')
        hsm_obj = c.hsm.get('obj')

    if hsm_obj is None or hsm_obj.isReady() is False:
        raise HSMException('hsm not ready!')

    ret = hsm_obj.decryptPin(cryptPin)
    return ret


def encrypt(data, iv, id=0, hsm=None):
    """
    encrypt a variable from the given input with an initialization vector

    :param input: buffer, which contains the value
    :type  input: buffer of bytes
    :param iv:    initialization vector
    :type  iv:    buffer (20 bytes random)
    :param id:    contains the id of which key of the keyset should be used
    :type  id:    int

    :return:      encryted buffer
    """

    log.debug('encrypt()')
    if hsm:
        hsm_obj = hsm.get('obj')
    else:
        if hasattr(c, 'hsm') is False or isinstance(c.hsm, dict) is False:
            raise HSMException('no hsm defined in execution context!')

        hsm_obj = c.hsm.get('obj')
    if hsm_obj is None or hsm_obj.isReady() is False:
        raise HSMException('hsm not ready!')
    ret = hsm_obj.encrypt(data, iv, id)
    return ret


def decrypt(input, iv, id=0, hsm=None):
    """
    decrypt a variable from the given input with an initialization vector

    :param input: buffer, which contains the crypted value
    :type  input: buffer of bytes
    :param iv:    initialization vector
    :type  iv:    buffer (20 bytes random)
    :param id:    contains the id of which key of the keyset should be used
    :type  id:    int

    :return:      decryted buffer
    """

    log.debug('decrypt()')
    if hsm:
        hsm_obj = hsm.get('obj')
    else:
        if hasattr(c, 'hsm') is False or isinstance(c.hsm, dict) is False:
            raise HSMException('no hsm defined in execution context!')
        hsm_obj = c.hsm.get('obj')

    if hsm_obj is None or hsm_obj.isReady() is False:
        raise HSMException('hsm not ready!')

    ret = hsm_obj.decrypt(input, iv, id)
    return ret


def uencode(value):
    """
    unicode escape the value - required to support non-unicode
    databases
    :param value: string to be escaped
    :return: \u encoded value
    """
    ret = value

    if ("linotp.uencode_data" in env
        and env["linotp.uencode_data"].lower() == 'true'):
        try:
            ret = json.dumps(value)[1:-1]
        except Exception as exx:
            log.exception("Failed to encode value %r : %r" % (value, exx))

    return ret


# encrypted cookie data
def aes_encrypt_data(data, key, iv=None):
    """
    encypt data for the cookie handling -
    other than the std linotp key slots, here the key might change per server
    startup, which is not in scope of std linotp encrypt

    :param key: the encryption key
    :param data: the data, which should be encrypted
    :param iv: the salt value
    :return: the encrypted data
    """
    if iv is None:
        iv = key

    padding = (16 - len(iv) % 16) % 16
    iv += padding * "\0"
    iv = iv[:16]

    # convert data from binary to hex as it might contain unicode++
    input_data = binascii.b2a_hex(data)
    input_data += '\x01\x02'
    padding = (16 - len(input_data) % 16) % 16
    input_data += padding * "\0"
    aes = AES.new(key, AES.MODE_CBC, iv)
    res = aes.encrypt(input_data)
    return res


def aes_decrypt_data(data, key, iv=None):
    """
    decrypt the given data
    other than the linotp std decrypt this method takes a key not a keyslot,
    which is required, as for every server startup the encryption key might
    change

    :param data: the to be decrypted data
    :param key: the encryption key
    :param iv: the random initialization vector
    :return: the decrypted value
    """
    if iv is None:
        iv = key

    padding = (16 - len(iv) % 16) % 16
    iv += padding * "\0"
    iv = iv[:16]

    aes = AES.new(key, AES.MODE_CBC, iv)
    output = aes.decrypt(data)
    eof = output.rfind('\x01\x02')
    if eof >= 0:
        output = output[:eof]

    # convert output from ascii, back to bin data, which might be unicode++
    res = binascii.a2b_hex(output)
    return res


def udecode(value):
    """
    unicode de escape the value - required to support non-unicode
    databases
    :param value: string to be deescaped
    :return: unicode value
    """

    ret = value
    if ("linotp.uencode_data" in env
        and env["linotp.uencode_data"].lower() == 'true'):
        try:
            # add surrounding "" for correct decoding
            ret = json.loads('"%s"' % value)
        except Exception as exx:
            log.exception("Failed to decode value %r : %r" % (value, exx))
    return ret


def geturandom(len=20):
    '''
    get random - from the security module

    :param len:  len of the returned bytes - defalt is 20 bytes
    :tyrpe len:    int

    :return: buffer of bytes

    '''
    log.debug('geturandom()')
    if hasattr(c, 'hsm') is False:
        ret = os.urandom(len)
        return ret

    if isinstance(c.hsm, dict) is False:
        raise HSMException('hsm not found!')

    hsm = c.hsm.get('obj')
    if hsm is None or hsm.isReady() is False:
        raise HSMException('hsm not ready!')

    ret = hsm.random(len)
    return ret

### some random functions based on geturandom #################################


class urandom(object):

    precision = 12

    @classmethod
    def random(cls):
        """
        get random float value between 0.0 and 1.0

        :return: float value
        """
        # get a binary random string
        randbin = geturandom(urandom.precision)

        # convert this to an integer
        randi = int(randbin.encode('hex'), 16) * 1.0

        # get the max integer
        intmax = 2 ** (8 * urandom.precision) * 1.0

        # scale the integer to an float between 0.0 and 1.0
        randf = randi / intmax

        assert randf >= 0.0
        assert randf <= 1.0

        return randf

    @classmethod
    def uniform(cls, start, end=None):
        """
        get a floating value between start and end

        :param start: start floating value
        :param end: end floating value
        :return: floating value between start and end
        """
        if end is None:
            end = start
            start = 0.0

        # make sure we have a float
        startf = start * 1.0

        dist = (end - start)
        # if end lower than start invert the distance and start at the end
        if dist < 0:
            dist = dist * -1.0
            startf = end * 1.0

        ret = urandom.random()

        # result is start value + stretched distance
        res = startf + ret * dist

        return res

    @classmethod
    def randint(cls, start, end=None):
        """
        get random integer in between of start and end

        :return: random int
        """
        if end is None:
            end = start
            start = 0

        dist = end - start
        # if end lower than start invert the distance and start at the end
        if dist < 0:
            dist = dist * -1
            start = end

        randf = urandom.random()

        # result is start value + stretched distance
        ret = int(start + randf * dist)

        return ret

    @classmethod
    def choice(cls, array):
        '''
        get one out of an array

        :param array: sequence - string or list
        :return: array element
        '''
        size = len(array)
        idx = urandom.randint(0, size)
        return array[idx]

    @classmethod
    def randrange(cls, start, stop=None, step=1):
        """
        get one out of a range of values

        :param start: start of range
        :param stop: end value
        :param step: the step distance beween two values

        :return: int value
        """
        if stop is None:
            stop = start
            start = 0
        # see python definition of randrange
        res = urandom.choice(range(start, stop, step))
        return res


def get_rand_digit_str(length=16):
    '''
    return a sting of digits with a defined length using the urandom

    if we have leading zeros, the len of s could be smaller. Therefore
    we run in a repeat-until-int(len) matches loop

    :param length: number of digits the string should return (w.o. leading 0s)
    :return: return string, which will contain length digits, even when
             converted to an int
    '''

    s = ""
    while len(s) < length:
        # some optimization len int chars does not require len hex bytes
        missing = (length - len(s)) + 1  # prevent getting zero in next step
        randd = geturandom(len=int(missing / 2))
        s2 = "%d" % (int(randd.encode('hex'), 16))
        s = s + s2[:missing]

    if len(s) > length:
        s = s[:length]
    return s


def zerome(bufferObject):
    '''
    clear a string value from memory

    :param string: the string variable, which should be cleared
    :type  string: string or key buffer

    :return:    - nothing -
    '''
    data = ctypes.POINTER(ctypes.c_char)()
    size = ctypes.c_int()  # Note, int only valid for python 2.5
    ctypes.pythonapi.PyObject_AsCharBuffer(ctypes.py_object(bufferObject),
                                    ctypes.pointer(data), ctypes.pointer(size))
    ctypes.memset(data, 0, size.value)
    # print repr(bufferObject)
    return


def init_qrtoken_secret_key(config, cert_id='system'):
    """
    create an elliptic curve secret + public key pair and
    store it in the linotp config
    """

    import linotp.lib.config

    public_key, secret_key = gen_dsa_keypair()
    secret_key_entry = 'qrtokensk:' + base64.b64encode(secret_key)

    linotp.lib.config.storeConfig(key='QrTokenSecretKey.' + cert_id,
                                  val=secret_key_entry,
                                  typ='password')

    public_key_entry = 'qrtokenpk:' + base64.b64encode(public_key)

    linotp.lib.config.storeConfig(key='QrTokenPublicKey.' + cert_id,
                                  val=public_key_entry)

    return


def get_qrtoken_secret_key(cert_id='system'):
    """
    reads the config entry 'enclinotp.QrTokenSecretKey',
    extracts and decodes the secret key and returns it as a 32 bytes.
    """
    import linotp.lib.config

    secret_key_b64 = linotp.lib.config.getFromConfig(
                        'enclinotp.QrTokenSecretKey.' + cert_id)

    if not secret_key_b64:
        raise ConfigAdminError('Missing entry QrTokenSecretKey')

    if not secret_key_b64.startswith('qrtokensk:'):
        raise ValidateError('QR secret key has an invalid '
                            'format. Must begin with \'qrtokensk:\'')

    secret_key = base64.b64decode(secret_key_b64[len('qrtokensk:'):])
    if len(secret_key) != 64:
        raise ValidateError('QR secret key has an invalid '
                            'format. Key must be 64 bytes long')

    return secret_key


def get_qrtoken_public_key(cert_id='system'):
    """
    reads the config entry 'linotp.QrTokenPublicKey',
    extracts and decodes the public key and returns it as a 32 bytes.
    """
    import linotp.lib.config

    public_key_b64 = linotp.lib.config.getFromConfig(
                                'QrTokenPublicKey.' + cert_id)
    if not public_key_b64:
        raise ConfigAdminError('Missing entry QrTokenPublicKey')

    if not public_key_b64.startswith('qrtokenpk:'):
        raise ValidateError('Curve 25519 / QR secret key has an invalid '
                            'format. Must begin with \'qrtokenpk:\'')

    public_key = base64.b64decode(public_key_b64[len('qrtokenpk:'):])
    if len(public_key) != 32:
        raise ValidateError('Curve 25519 / QR public key has an invalid '
                            'format. Key must be 32 bytes long')

    return public_key

def dsa_to_dh_secret(dsa_secret_key):

    out = ctypes.create_string_buffer(c_libsodium.crypto_scalarmult_bytes())
    __libsodium_check(c_libsodium.crypto_sign_ed25519_sk_to_curve25519(
                      out,
                      dsa_secret_key))
    return out.raw

def dsa_to_dh_public(dsa_public_key):

    out = ctypes.create_string_buffer(c_libsodium.crypto_scalarmult_bytes())
    __libsodium_check(c_libsodium.crypto_sign_ed25519_pk_to_curve25519(
                      out,
                      dsa_public_key))
    return out.raw

def get_qrtoken_dh_secret_key():

    """ transforms the qrtoken secret key (which is used for DSA) into
    a Diffie-Hellman secret key """

    dsa_secret_key = get_qrtoken_secret_key()
    return dsa_to_dh_secret(dsa_secret_key)


def get_qrtoken_dh_public_key():

    """ transforms the qrtoken public key (which is used for DSA) into
    a Diffie-Hellman public key """

    dsa_public_key = get_qrtoken_public_key()
    return dsa_to_dh_public(dsa_public_key)


def extract_tan(signature, digits):

    """
    Calculates a TAN from a signature using a procedure
    similar to HOTP

    :param signature: the signature used as a source for the TAN
    :param digits: number of digits the should be long

    :returns TAN (as integer)
    """

    offset = ord(signature[-1:]) & 0xf
    tan = struct.unpack('>I', signature[offset:offset+4])[0] & 0x7fffffff
    tan = tan % 10**digits
    return tan

# #############################################################################


def encode_base64_urlsafe(data):
    """ encodes a string with urlsafe base64 and removes its padding """
    return base64.urlsafe_b64encode(data).decode('utf8').rstrip('=')


def decode_base64_urlsafe(data):
    """ decodes a string encoded with :func encode_base64_urlsafe """
    return base64.urlsafe_b64decode(data.encode() + (-len(data) % 4)*b'=')


# #############################################################################

# eof #########################################################################

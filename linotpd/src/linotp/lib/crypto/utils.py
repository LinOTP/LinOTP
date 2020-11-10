# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
'''
Cryptographic utility functions
'''

import base64
import binascii

import ctypes
import hmac
import json
import logging
import secrets

from linotp.flap import config as env
from pysodium import sodium as c_libsodium
from pysodium import __check as __libsodium_check
from pysodium import crypto_sign_keypair as gen_dsa_keypair
import struct

from hashlib import md5
from hashlib import sha1
from hashlib import sha224
from hashlib import sha256
from hashlib import sha384
from hashlib import sha512

from linotp.lib.ext.pbkdf2 import PBKDF2
from linotp.lib.context import request_context as context
from linotp.lib.error import ConfigAdminError
from linotp.lib.error import HSMException
from linotp.lib.error import ProgrammingError
from linotp.lib.error import ValidateError

from crypt import crypt as libcrypt

from passlib.context import CryptContext

PasslibHashes = CryptContext(schemes=[
    "sha512_crypt", "sha256_crypt", "sha1_crypt",
    "md5_crypt", "bcrypt", "bcrypt_sha256"
])

log = logging.getLogger(__name__)

Hashlib_map = {'md5': md5, 'sha1': sha1,
               'sha224': sha224, 'sha256': sha256,
               'sha384': sha384, 'sha512': sha512}


def compare_password(password, crypted_password):
    """
    comparing passwords

    for password comparison the passwords crypt algorithms are supported,
    which are indicated by the "$ID$" prefix :

      ID  | Method
      ─────────────────────────────────────────────────────────
      1   | MD5
      2a  | Blowfish (not in mainline glibc; added in some
          | Linux distributions)
      5   | SHA-256 (since glibc 2.7)
      6   | SHA-512 (since glibc 2.7)

    to upport passowrds on a broad range of platforms the passlib library
    is used:

        https://passlib.readthedocs.io/en/stable/index.html

    algorithm:
    we iterate over supported list of passlib modules to identify the
    hashing algorithm (s.o.) and do the comparison with the matching one.

    :param password: the plain text password
    :param crypted_password: the encrypted password

    :return: boolean - for the password comparison result
    """

    if PasslibHashes.identify(crypted_password):
        return PasslibHashes.verify(password, crypted_password)

    # compatibilty case:
    # the rare case for the broken system crypto libs like on macos

    new_crypted_passw = libcrypt(password, crypted_password)
    return compare(new_crypted_passw, crypted_password)


def crypt_password(password):
    """
    generate a new crypted hashed password from a given password

    we use crypt type sha512, which is a secure and standard according to:
    http://security.stackexchange.com/questions/20541/\
                     insecure-versions-of-crypt-hashes

    sha512 is selected be the first position in the PasslibHashes schemes

    :param password: the plaintext password
    :return: the encrypted password
    """

    log.debug("hashing password schema %r", PasslibHashes.default_scheme())
    return PasslibHashes.hash(password)


def compare(one, two):
    """
    position independend comparison of values

    :param one: first value
    :param two: second value
    :return: boolean

    """
    res = True
    for tup1, tup2 in zip(one, two):
        res = res and (tup1 == tup2)

    return res


def get_hashalgo_from_description(description, fallback='sha1'):
    """
    get the hashing function from a string value

    :param description: the literal description of the hash
    :param fallback: the fallback hash allgorithm
    :return: hashing function pointer
    """

    if not description:
        description = fallback

    try:
        hash_func = Hashlib_map.get(description.lower(),
                                    Hashlib_map[fallback.lower()])
    except Exception as exx:
        raise Exception("unsupported hash function %r:%r",
                        description, exx)
    if not callable(hash_func):
        raise Exception("hash function not callable %r", hash_func)

    return hash_func


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


def createActivationCode(acode:str=None, checksum=True):
    """
    create the activation code

    :param acode: activation code or None
    :param checksum: flag to indicate, if a checksum will be calculated
    :return: return the activation code
    """
    if acode is None:
        acode = geturandom(20)
    else:
        acode =acode.encode('utf-8')

    activationcode = base64.b32encode(acode)
    if checksum is True:
        chsum = check(acode)
        activationcode = b'' + activationcode + chsum.encode('utf-8')

    return activationcode.decode()


def createNonce(len=64):
    """
    create a nonce - which is a random string
    :param len: len of bytes to return
    :return: hext string
    """
    key = secrets.token_bytes(len)
    return binascii.hexlify(key).decode()


def kdf2(sharedsecret, nonce, activationcode, len, iterations=10000,
         digest='SHA256', macmodule=hmac, checksum=True):
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
    digestmodule = get_hashalgo_from_description(digest,
                                                 fallback='SHA256')

    byte_len = 2
    salt_len = 8 * byte_len

    salt = '' + nonce[-salt_len:]
    bSalt = binascii.unhexlify(salt)
    activationcode = activationcode.replace('-', '')

    acode = activationcode
    if checksum is True:
        acode = str(activationcode)[:-2]

    try:
        bcode = base64.b32decode(acode)

    except Exception as exx:
        error = "Error during decoding activation code %r: %r" % (acode, exx)
        log.error(error)
        raise Exception(error)

    if checksum is True:
        checkCode = str(activationcode[-2:])
        veriCode = str(check(bcode)[-2:])
        if checkCode != veriCode:
            raise Exception('[crypt:kdf2] activation code checksum error.'
                            ' [%s]%s:%s' % (acode, veriCode, checkCode))

    activ = binascii.hexlify(bcode).decode()

    if not isinstance(sharedsecret, str):
        sharedsecret = sharedsecret.decode()

    passphrase = '' + sharedsecret + activ + nonce[:-salt_len]

    keyStream = PBKDF2(
        binascii.unhexlify(passphrase.encode('utf-8')),
        bSalt, iterations=iterations, digestmodule=digestmodule)

    key = keyStream.read(len)
    return key


def hash_digest(val: bytes, seed:bytes, algo=None, hsm=None):
    """
    hash_digest - hmac digest, lower level api

    - operating on byte level
    - calling level to the hsm module


    """
    hsm_obj = _get_hsm_obj_from_context(hsm)

    if algo is None:
        algo = get_hashalgo_from_description('sha256')

    h = hsm_obj.hash_digest(val, seed, algo)

    return h


def hmac_digest(bkey, data_input, hsm=None, hash_algo=None):

    hsm_obj = _get_hsm_obj_from_context(hsm)

    if hash_algo is None:
        hash_algo = get_hashalgo_from_description('sha1')

    h = hsm_obj.hmac_digest(bkey, data_input, hash_algo)

    return h


def encryptPassword(password):
    """Encrypt password (i.e. ldap password)

    :param password: password to encrypt
    :return: encrypted password
    """
    # TODO: this function have no iv and hsm. encryptPin does; is this correct?
    hsm_obj = _get_hsm_obj_from_context()
    return hsm_obj.encryptPassword(password)


def encryptPin(cryptPin:bytes, iv=None, hsm=None):
    """Encrypt pin (i.e. token pin)

    :param cryptPin: pin to encrypt
    :param iv: initializain vector
    :param hsm: hsm security object instance
    :return: return encrypted pin
    """
    hsm_obj = _get_hsm_obj_from_context(hsm)
    return hsm_obj.encryptPin(cryptPin, iv)


def _get_hsm_obj_from_context(hsm=None):
    """Get the hsm from  LinOTP request context

    If no hsm parameter is given, we get the hsm from the LinOTP request context
    (var context) which was extended some time ago.

    :param hsm: hsm security object instance
    :return: return the hsm object
    :rtype:
    """

    if hsm:
        hsm_obj = hsm.get('obj')
    else:
        hsm_obj = context.get('hsm', {}).get('obj')

    if not hsm_obj:
        raise HSMException('no hsm defined in execution context!')

    if hsm_obj.isReady() is False:
        raise HSMException('hsm not ready!')
    return hsm_obj


def decryptPassword(cryptPass:str)-> bytes:
    """
    Restore the encrypted password

    :param cryptPass: encrypted password (i.e. ldap password)
    :return: decrypted password
    """
    hsm_obj = _get_hsm_obj_from_context()
    ret = hsm_obj.decryptPassword(cryptPass)
    return ret


def decryptPin(cryptPin, hsm=None):
    """
    :param cryptPin: encrypted pin (i.e. token pin)
    :param hsm: hsm security object instance
    :return: decrypted pin
    """

    hsm_obj = _get_hsm_obj_from_context(hsm)
    return hsm_obj.decryptPin(cryptPin)


def encrypt(data: str, iv: bytes, id: int=0, hsm=None) -> bytes:
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

    hsm_obj = _get_hsm_obj_from_context(hsm)
    return hsm_obj.encrypt(data.encode('utf-8'), iv, id)


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

    hsm_obj = _get_hsm_obj_from_context(hsm)
    return hsm_obj.decrypt(input, iv, id)


def uencode(value):
    """
    unicode escape the value - required to support non-unicode
    databases
    :param value: string to be escaped
    :return: unicode encoded value
    """
    ret = value

    if (env.get("linotp.uencode_data", "").lower() == 'true'):
        try:
            ret = json.dumps(value)[1:-1]
        except Exception as exx:
            log.exception("Failed to encode value %r. Exception was %r"
                          % (value, exx))

    return ret


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
            log.exception("Failed to decode value %r. Exception was %r"
                          % (value, exx))
    return ret


def get_rand_digit_str(length=16):
    '''
    return a string of digits with a defined length using the urandom

    :param length: number of digits the string should return
    :return: return string, which will contain length digits
    '''

    digit_str = str(1 + (struct.unpack(">I", secrets.token_bytes(4))[0] % 9))

    for _i in range(length - 1):
        digit_str += str(struct.unpack("<I", secrets.token_bytes(4))[0] % 10)

    return digit_str


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


def init_key_partition(config, partition, key_type='ed25519'):
    """
    create an elliptic curve secret + public key pair and
    store it in the linotp config
    """

    if not key_type == 'ed25519':
        raise ValueError('Unsupported keytype: %s', key_type)

    import linotp.lib.config

    public_key, secret_key = gen_dsa_keypair()
    secret_key_entry = base64.b64encode(secret_key).decode('utf-8')

    linotp.lib.config.storeConfig(key='SecretKey.Partition.%d' % partition,
                                  val=secret_key_entry,
                                  typ='encrypted_data')

    public_key_entry = base64.b64encode(public_key).decode('utf-8')

    linotp.lib.config.storeConfig(key='PublicKey.Partition.%d' % partition,
                                  val=public_key_entry,
                                  typ='encrypted_data')


def get_secret_key(partition):
    """
    reads the password config entry 'linotp.SecretKey.Partition.<partition>',
    extracts and decodes the secret key and returns it as a 32 bytes.
    """

    import linotp.lib.config

    key = 'linotp.SecretKey.Partition.%d' % partition

    # FIXME: unencryption should not happen at this early stage
    secret_key_b64 = linotp.lib.config.getFromConfig(key).get_unencrypted()

    if not secret_key_b64:
        raise ConfigAdminError('No secret key found for %d' % partition)

    secret_key = base64.b64decode(secret_key_b64)

    # TODO: key type checking

    if len(secret_key) != 64:
        raise ValidateError('Secret key has an invalid '
                            'format. Key must be 64 bytes long')

    return secret_key


def get_public_key(partition):
    """
    reads the password config entry 'linotp.PublicKey.Partition.<partition>',
    extracts and decodes the public key and returns it as a 32 bytes.
    """

    import linotp.lib.config

    key = 'linotp.PublicKey.Partition.%d' % partition

    # FIXME: unencryption should not happen at this early stage
    public_key_b64 = linotp.lib.config.getFromConfig(key).get_unencrypted()

    if not public_key_b64:
        raise ConfigAdminError('No public key found for %d' % partition)

    public_key = base64.b64decode(public_key_b64)

    # TODO: key type checking

    if len(public_key) != 32:
        raise ValidateError('Public key has an invalid '
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


def geturandom(len=20):
    '''
    get random - from the security module

    :param len:  len of the returned bytes - defalt is 20 bytes
    :tyrpe len:    int

    :return: buffer of bytes

    '''

    try:
        hsm_obj = _get_hsm_obj_from_context()
        return hsm_obj.random(len)
    except (HSMException, ProgrammingError):
        return secrets.token_bytes(len)

def get_dh_secret_key(partition):
    """ transforms the ed25519 secret key (which is used for DSA) into
    a Diffie-Hellman secret key """

    dsa_secret_key = get_secret_key(partition)
    return dsa_to_dh_secret(dsa_secret_key)


def extract_tan(signature, digits):
    """
    Calculates a TAN from a signature using a procedure
    similar to HOTP

    :param signature: the signature used as a source for the TAN
    :param digits: number of digits the should be long

    :returns TAN (as string)
    """

    offset = ord(signature[-1:]) & 0xf
    itan = struct.unpack('>I', signature[offset:offset+4])[0] & 0x7fffffff

    # convert the binaries of the signature to an integer based string
    tan = "%d" % (itan % 10**digits)

    # fill up the tan with leading zeros
    stan = "%s%s" % ('0' * (digits - len(tan)), tan)

    return stan


def encode_base64_urlsafe(data):
    """ encodes a string with urlsafe base64 and removes its padding """
    return base64.urlsafe_b64encode(data).decode('utf8').rstrip('=')


def decode_base64_urlsafe(data):
    """ decodes a string encoded with :func encode_base64_urlsafe """
    return base64.urlsafe_b64decode(data.encode() + (-len(data) % 4)*b'=')

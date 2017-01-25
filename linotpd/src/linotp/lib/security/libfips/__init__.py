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
    Interface for OpenSSL in FIPS mode
"""

# fips - interface for OpenSSL in FIPS mode
#
#

import ctypes
from ctypes import c_int
from ctypes import c_void_p
from ctypes import c_char_p
from ctypes import CDLL

__all__ = ["FipsModule", "SSLError", "ParameterError"]


# exceptions we will raise
class ParameterError(Exception):
    pass


class SSLError(Exception):
    pass


class FipsModule(object):

    def __init__(self, library):

        # this will raise an OSError exception, in case of an error.
        _libcrypto = CDLL(library)

        #
        # function signatures from OpenSSL's libcrypto we will use
        #

        # int FIPS_mode_set(int);
        _libcrypto.FIPS_mode_set.argtypes = [c_int]
        _libcrypto.FIPS_mode_set.restype = c_int

        _libcrypto.FIPS_mode.argtypes = []
        _libcrypto.FIPS_mode.restype = c_int

        # const EVP_MD *EVP_sha1(void);
        _libcrypto.EVP_sha1.argtypes = []
        _libcrypto.EVP_sha1.restype = c_void_p

        # const EVP_MD *EVP_sha256(void);
        _libcrypto.EVP_sha256.argtypes = []
        _libcrypto.EVP_sha256.restype = c_void_p

        # const EVP_MD *EVP_sha512(void);
        _libcrypto.EVP_sha512.argtypes = []
        _libcrypto.EVP_sha512.restype = c_void_p

        # const EVP_MD *EVP_ripemd160(void);
        _libcrypto.EVP_ripemd160.argtypes = []
        _libcrypto.EVP_ripemd160.restype = c_void_p

        # int EVP_MD_size(const EVP_MD *)
        _libcrypto.EVP_MD_size.argtypes = [c_void_p]
        _libcrypto.EVP_MD_size.restype = c_int

        # unsigned char *HMAC(const EVP_MD *, const void *, int,
        #                     const unsigned char *, int, unsigned char *,
        #                     unsigned int *)
        _libcrypto.HMAC.argtypes = [c_void_p, c_void_p, c_int,
                                    c_char_p, c_int, c_char_p,
                                    c_void_p]

        _libcrypto.HMAC.restype = c_char_p

        #
        # activate FIPS mode
        #
        if _libcrypto.FIPS_mode() != 1:
            if _libcrypto.FIPS_mode_set(1) == 0:
                raise SSLError("can't enable OpenSSL FIPS mode")

        self._libcrypto = _libcrypto

        self._sha1 = _libcrypto.EVP_sha1()
        self._sha256 = _libcrypto.EVP_sha256()
        self._sha512 = _libcrypto.EVP_sha512()

    #
    # HMAC - call OpenSSL HMAC function and return it's result
    #
    # NOTE: Using a wrong md might result in a program crash! Please use the
    #       shortcuts defined below for a much safer interface.
    #
    def _HMAC(self, md, key, msg):
        """
        Call OpenSSL HMAC function with the given md, key and msg.

        :param md: is the hash function used for HMAC, use the predefined
                   fips.sha1, fips.sha256 or fips.sha512. You could request
                   other OpenSSL hash functions (with fips._libcrypto.EVP_X()
                   where X is the name of your hash), but be aware that not all
                   of them are FIPS certified and may not work.

        :param key: is the secret key used for HMAC and expected to be
                    a 'bytes' array.

        :param msg: is the data we want to calculate a HMAC of, expected to
                    be a 'bytes' array.

        :return: This function returns an bytes array with the requested
                 digest.

        NOTE: please use the HMAC_XXX functions, defined below unless you know
        what you are doing.
        """
        if not isinstance(key, bytes):
            raise ParameterError("key must be a byte array")

        if not isinstance(msg, bytes):
            raise ParameterError("msg must be a byte array")

        # create memory to store digest in
        digest = ctypes.create_string_buffer(self._libcrypto.EVP_MD_size(md))

        # call OpenSSL
        res = self._libcrypto.HMAC(md,
                                   key, len(key),
                                   msg, len(msg),
                                   digest, None)

        # OpenSSL will return NULL (None for us) to indicate an error
        if res is None:
            raise SSLError("HMAC failed")

        return digest.raw

    #
    # shortcuts - this is the preferred way for requesting an HMAC from OpenSSL
    #
    def hmac_sha1(self, key, msg):
        """
        Calculate and return a HMAC-sha1 digest of msg with the given key using
        OpenSSL.

        A 20 byte long 'bytes' array with the requested digest is returned.
        """
        return self._HMAC(self._sha1, key, msg)

    def hmac_sha256(self, key, msg):
        """
        Calculate and return a HMAC-sha256 digest of msg with the given
        key using OpenSSL.

        A 32 byte long 'bytes' array with the requested digest is returned.
        """
        return self._HMAC(self._sha256, key, msg)

    def hmac_sha512(self, key, msg):
        """
        Calculate and return a HMAC-sha512 digest of msg with the given
        key using OpenSSL.

        A 64 byte long 'bytes' array with the requested digest is returned.
        """
        return self._HMAC(self._sha512, key, msg)

# --

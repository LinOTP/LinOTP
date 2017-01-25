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
"""fips library self test"""

import os
from binascii import unhexlify

from linotp.lib.security.libfips import FipsModule
from linotp.lib.security.libfips import SSLError

# assune the cryptolib is in the same directory as libfips

Cryptolib_Location = os.path.dirname(os.path.abspath(__file__))
Cryptolib = os.path.join(Cryptolib_Location, 'libcrypto.so')

Fips = FipsModule(Cryptolib)


#
# check test vectors for HMAC-sha1 from RFC2202
#

# test case 1
if (Fips.hmac_sha1(20 * b"\x0b", b"Hi There") !=
        unhexlify("b617318655057264e28bc0b6fb378c8ef146be00")):
    raise Exception("HMAC-sha1 self check number 1 failed")

# test case 2
if (Fips.hmac_sha1(b"Jefe", b"what do ya want for nothing?") !=
        unhexlify("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")):
    raise Exception("HMAC-sha1 self check number 2 failed")

# test case 3
if (Fips.hmac_sha1(20 * b"\xaa", 50 * b"\xdd") !=
        unhexlify("125d7342b9ac11cd91a39af48aa17b4f63f175d3")):
    raise Exception("HMAC-sha1 self check number 3 failed")

# test case 4
if (Fips.hmac_sha1(unhexlify("0102030405060708090a0b0c0d0e0f10111213141516"
                             "171819"), 50 * b"\xcd") !=
        unhexlify("4c9007f4026250c6bc8414f9bf50c86c2d7235da")):
    raise Exception("HMAC-sha1 self check number 4 failed")

# test case 5
if (Fips.hmac_sha1(20 * b"\x0c", b"Test With Truncation") !=
        unhexlify("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04")):
    raise Exception("HMAC-sha1 self check number 5 failed")

# test case 6
if (Fips.hmac_sha1(80 * b"\xaa", b"Test Using Larger Than Block-Size Key"
                   " - Hash Key First") !=
        unhexlify("aa4ae5e15272d00e95705637ce8a3b55ed402112")):
    raise Exception("HMAC-sha1 self check number 6 failed")

# test case 7
if (Fips.hmac_sha1(80 * b"\xaa", b"Test Using Larger Than Block-Size Key "
                   "and Larger Than One Block-Size Data") !=
        unhexlify("e8e99d0f45237d786d6bbaa7965c7808bbff1a91")):
    raise Exception("HMAC-sha1 self check number 7 failed")


#
# now check if non-Fips algorithms are really disabled by trying to calculate
# a HMAC-ripemd160
#
try:
    ripemd160 = Fips._libcrypto.EVP_ripemd160()
    Fips._HMAC(ripemd160, b"foo", b"bar")
    raise Exception("HMAC with ripemd160 hash should be "
                    "disabled by FIPS mode!")
except SSLError:
    pass  # that is what we want

# end of file

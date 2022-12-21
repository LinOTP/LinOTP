#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#
#    This file is part of LinOTP admin clients.
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
" HMAC-OTP Software Token "

import os, sys, platform
import binascii
import hmac
from hashlib import sha1
import struct
from getopt import getopt, GetoptError


class HmacOtp:
    def __init__(self, key, counter=0, digits=6):
        self.key = key
        self.counter = counter
        self.digits = digits

    def hmac(self, key=None, counter=None):
        key = key or self.key
        counter = counter or self.counter
        digest = hmac.new(key, struct.pack(">Q", counter), sha1)
        return digest.digest()

    def truncate(self, digest):
        offset = ord(digest[-1:]) & 0x0f

        binary = (ord(digest[offset + 0]) & 0x7f) << 24
        binary |= (ord(digest[offset + 1]) & 0xff) << 16
        binary |= (ord(digest[offset + 2]) & 0xff) << 8
        binary |= (ord(digest[offset + 3]) & 0xff)

        return binary % (10 ** self.digits)

    def generate(self, key=None, counter=None):
        key = key or self.key
        counter = counter or self.counter
        otp = self.truncate(self.hmac(key, counter))
        self.counter = counter + 1
        return otp


def main():

    HEXKEY = "400edad7f3e8939c7ffa2d57d1bed94695bfd46c"
    TIMESTEP = 60
    OFFSET = 0

    def usage():
       print "o, offset=      tokenoffset in seconds"

    try:
        opts, args = getopt(sys.argv[1:], "o:",
                ['offset=', '--help'])

    except GetoptError:
        print "There is an error in your parameter syntax:"
        usage()
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('o', '--offset'):
            print "setting offset : ", arg
            OFFSET = int(arg)




    from time import time
    counter = int((time() + OFFSET) / TIMESTEP + 0.5)

    key = binascii.a2b_hex(HEXKEY)
    otp = HmacOtp(key, counter=counter).generate()

    print "Your OTP with number %d is %06d." % (counter, otp)
    print "Happy Authenticating!"


if __name__ == '__main__':
    main()


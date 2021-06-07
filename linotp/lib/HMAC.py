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
"""
HMAC-OTP (RFC 4226)
"""

import hmac
import logging
import struct

from hashlib import sha1


log = logging.getLogger(__name__)


class HmacOtp():

    def __init__(self, secObj=None, counter: int = 0, digits: int = 6, hashfunc=sha1):
        self.secretObj = secObj
        self.counter = counter
        self.digits = digits
        self.hashfunc = hashfunc

    def hmac(self, counter: int = None, key=None):
        counter = counter or self.counter

        data_input = struct.pack(">Q", counter)

        if key is None:
            dig = self.secretObj.hmac_digest(
                data_input, hash_algo=self.hashfunc)
        else:
            dig = hmac.new(key, data_input, self.hashfunc).digest()

        return dig

    def truncate(self, digest):
        offset = ord(digest[-1:]) & 0x0f

        binary = (digest[offset + 0] & 0x7f) << 24
        binary |= (digest[offset + 1] & 0xff) << 16
        binary |= (digest[offset + 2] & 0xff) << 8
        binary |= (digest[offset + 3] & 0xff)

        return binary % (10 ** self.digits)

    def generate(self, counter: int = None, inc_counter=True, key=None):

        counter = counter or self.counter

        otp = str(
            self.truncate(
                self.hmac(counter=counter, key=key))
            )

        # fill in the leading zeros

        sotp = (self.digits - len(otp)) * "0" + otp
        if inc_counter:
            self.counter = counter + 1
        return sotp

    def checkOtp(self, anOtpVal, window, symetric=False):
        res = -1
        start = self.counter
        end = self.counter + window
        if symetric is True:
            # changed window/2 to window for TOTP
            start = self.counter - (window)
            start = 0 if (start < 0) else start
            end = self.counter + (window)

        for c in range(start , end):
            otpval = self.generate(c)

            if otpval == anOtpVal:
                res = c
                break

        #return -1 or the counter
        return res

#eof##########################################################################

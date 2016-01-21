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
HMAC-OTP (RFC 4226)
"""

import hmac
import logging
import struct

from hashlib import sha1

import sys
(ma, mi, _, _, _,) = sys.version_info
pver = float(int(ma) + int(mi) * 0.1)


log = logging.getLogger(__name__)


class HmacOtp():

    def __init__(self, secObj=None, counter=0, digits=6, hashfunc=sha1):
        self.secretObj = secObj
        self.counter = counter
        self.digits = digits
        self.hashfunc = hashfunc

    def hmac(self, counter=None, key=None):
        #log.error("hmacSecret()")
        counter = counter or self.counter

        data_input = struct.pack(">Q", counter)
        if key is None:
            dig = str(self.secretObj.hmac_digest(data_input, self.hashfunc))
        else:
            if pver > 2.6:
                dig = hmac.new(key, data_input, self.hashfunc).digest()
            else:
                dig = hmac.new(key, str(data_input), self.hashfunc).digest()

        return dig

    def truncate(self, digest):
        offset = ord(digest[-1:]) & 0x0f

        binary = (ord(digest[offset + 0]) & 0x7f) << 24
        binary |= (ord(digest[offset + 1]) & 0xff) << 16
        binary |= (ord(digest[offset + 2]) & 0xff) << 8
        binary |= (ord(digest[offset + 3]) & 0xff)

        return binary % (10 ** self.digits)

    def generate(self, counter=None, inc_counter=True, key=None):
        counter = counter or self.counter

        otp = str(self.truncate(self.hmac(counter=counter, key=key)))
        """  fill in the leading zeros  """
        sotp = (self.digits - len(otp)) * "0" + otp
        #log.debug("[generate] %s %s %s" % (str(counter), str(otp), str(sotp) ) )
        if inc_counter:
            self.counter = counter + 1
        return sotp

    def checkOtp(self, anOtpVal, window, symetric=False):
        res = -1
        start = self.counter
        end = self.counter + window
        if symetric == True:
            # changed window/2 to window for TOTP
            start = self.counter - (window)
            start = 0 if (start < 0) else start
            end = self.counter + (window)

        log.debug("[checkOTP] OTP range counter: %r - %r" % (start, end))
        for c in range(start , end):
            otpval = self.generate(c)
            log.debug("[checkOtp] calculating counter %r: %r %r"
                      % (c, anOtpVal, otpval))
            #log.error("otp[%d]: %s : %s",c,otpval,anOtpVal)

            if (unicode(otpval) == unicode(anOtpVal)):
                # log.debug("Match Pin: %s : %d : %s",otpval,c,anOtpVal)
                res = c
                break
        #return -1 or the counter
        return res

#eof##########################################################################


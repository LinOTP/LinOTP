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
'''
lib for calculating day passwords. (Tagespasswort)
'''


from hashlib import md5
from datetime import datetime
from binascii import hexlify

from linotp.lib.crypt import zerome

import logging
log = logging.getLogger(__name__)





class dpwOtp:

    def __init__(self, secObj, digits=6):
        self.secretObject = secObj
        self.digits = digits

    def checkOtp(self, anOtpVal, window=0, options=None):
        '''
        window is the seconds before and after the current time
        '''
        res = -1

        key = self.secretObject.getKey()

        date_string = datetime.now().strftime("%d%m%y")
        input = key + date_string

        md = hexlify(md5(input).digest())
        md = md[len(md) - self.digits:]
        otp = int(md, 16)
        otp = unicode(otp)
        otp = otp[len(otp) - self.digits:]

        if unicode(anOtpVal) == otp:
            res = 1

        zerome(key)
        del key

        return res

    def getOtp(self, date_string=None):

        key = self.secretObject.getKey()

        if date_string == None:
            date_string = datetime.now().strftime("%d%m%y")

        input = key + date_string

        md = hexlify(md5(input).digest())
        md = md[len(md) - self.digits:]
        otp = int(md, 16)
        otp = unicode(otp)
        otp = otp[len(otp) - self.digits:]

        zerome(key)
        del key

        return otp

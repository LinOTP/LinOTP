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

""" This file containes PasswordTokenClass """

import logging
from linotp.lib.crypt   import zerome

from linotp.lib.util    import getParam


optional = True
required = False

from linotp.lib.tokenclass import TokenClass

log = logging.getLogger(__name__)

###############################################
class PasswordTokenClass(TokenClass):
    '''
    This Token does use a fixed Password as the OTP value.
    In addition, the OTP PIN can be used with this token.
    This Token can be used for a scenario like losttoken
    '''

    class __secretPassword__(object):

        def __init__(self, secObj):
            self.secretObject = secObj

        def getPassword(self):
            return self.secretObject.getKey()

        def checkOtp(self, anOtpVal):
            res = -1

            key = self.secretObject.getKey()

            if key == anOtpVal:
                res = 0

            zerome(key)
            del key

            return res

    def __init__(self, aToken):
        TokenClass.__init__(self, aToken)
        self.hKeyRequired = True
        self.setType(u"pw")

    @classmethod
    def getClassType(cls):
        return "pw"

    @classmethod
    def getClassInfo(cls, key=None, ret='all'):
        '''
        getClassInfo - returns a subtree of the token definition

        :param key: subsection identifier
        :type key: string

        :param ret: default return value, if nothing is found
        :type ret: user defined

        :return: subsection if key exists or user defined
        :rtype: s.o.

        '''
        log.debug("[getClassInfo] begin. Get class render info for section: key %r, ret %r " %
                  (key, ret))

        res = {
               'type'           : 'pw',
               'title'          : 'Password Token',
               'description'    : ('A token with a fixed password. Can be combined with the OTP PIN. Is used for the lost token scenario.'),
               'init'         : {},
               'config'        : {},
               'selfservice'   :  {},
               'policy' : {},
               }
        # I don't think we need to define the lost token policies here...

        if key is not None and res.has_key(key):
            ret = res.get(key)
        else:
            if ret == 'all':
                ret = res
        log.debug("[getClassInfo] end. Returned the configuration section: ret %r " % (ret))
        return ret



    def update(self, param):

        TokenClass.update(self, param)
        # The otplen is determined by the otpkey. So we
        # call the setOtpLen after the parents update, to overwrite
        # specified OTP lengths with the length of the password
        self.setOtpLen(0)

    def setOtpLen(self, otplen):
        '''
        sets the OTP length to the length of the password
        '''
        secretHOtp = self.token.getHOtpKey()
        sp = PasswordTokenClass.__secretPassword__(secretHOtp)
        pw_len = len(sp.getPassword())
        log.debug("[setOtpLen] setting otplen to %d" % pw_len)
        TokenClass.setOtpLen(self, pw_len)
        return


    def checkOtp(self, anOtpVal, counter, window, options=None):
        '''
        This checks the static password
        '''
        log.debug("checkOtp of PasswordToken")

        secretHOtp = self.token.getHOtpKey()
        sp = PasswordTokenClass.__secretPassword__(secretHOtp)
        res = sp.checkOtp(anOtpVal)

        return res

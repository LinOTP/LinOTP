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
"""This file containes the dynamic SPass token implementation:
              - SpassTokenClass
"""

import logging

from linotp.lib.util    import getParam
from linotp.lib.validate import check_pin

optional = True
required = False

from linotp.lib.tokenclass import TokenClass

log = logging.getLogger(__name__)




class SpassTokenClass(TokenClass):
    '''
    This is a simple pass token.
    It does have no OTP component. The OTP checking will always
    succeed. Of course, an OTP PIN can be used.
    '''
    def __init__(self, aToken):
        TokenClass.__init__(self, aToken)
        self.setType(u"spass")
        self.mode = ['authenticate']

    @classmethod
    def getClassType(cls):
        return "spass"

    @classmethod
    def getClassPrefix(cls):
        return "LSSP"

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
               'type'           : 'spass',
               'title'          : 'Simple Pass Token',
               'description'    : ('A token that allows the user to simply pass. Can be combined with the OTP PIN.'),
               'init'         : {'page' : {'html'      : 'spasstoken.mako',
                                            'scope'      : 'enroll', },
                                   'title'  : {'html'      : 'spasstoken.mako',
                                             'scope'     : 'enroll.title', },
                                   },
               'config'        : {},
               'selfservice'   :  {},
               'policy' : {},
               }

        # do we need to define the lost token policies here...
        if key is not None and res.has_key(key):
            ret = res.get(key)
        else:
            if ret == 'all':
                ret = res
        log.debug("[getClassInfo] end. Returned the configuration section: ret %r " % (ret))
        return ret

    def update(self, param):
        # cko: changed for backward compat
        getParam(param, "pin", optional)
        if not param.has_key('otpkey'):
            param['genkey'] = 1

        TokenClass.update(self, param)

    ## the spass token does not suport challenge response
    def is_challenge_request(self, passw, user, options=None):
        return False

    def is_challenge_response(self, passw, user, options=None, challenges=None):
        return False

    def authenticate(self, passw, user, options=None):
        '''
        in case of a wrong passw, we return a bad matching pin,
        so the result will be an invalid token
        '''
        otp_count = -1
        pin_match = check_pin(self, passw, user=user, options=options)
        if pin_match == True:
            otp_count = 0
        return (pin_match, otp_count, None)

## eof ########################################################################


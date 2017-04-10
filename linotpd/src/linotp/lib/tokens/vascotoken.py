# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
"""This file contains the dynamic Vasco token implementation:
              - VascoTokenClass (vasco)
"""

import logging

from linotp.lib.util import getParam

from linotp.lib.tokenclass import TokenClass
from linotp.lib.ImportOTP.vasco import vasco_otp_check
from linotp.lib.context import request_context as context

log = logging.getLogger(__name__)


###############################################
class VascoTokenClass(TokenClass):
    """
    Vasco Token Class - binding against the vasco dll
    """

    def __init__(self, aToken):
        TokenClass.__init__(self, aToken)
        self.setType(u"vasco")
        self.hKeyRequired = True

    @classmethod
    def getClassType(cls):
        '''
        return the generic token class identifier
        '''
        return "vasco"

    @classmethod
    def getClassPrefix(cls):
        return "vasco"

    @classmethod
    def getClassInfo(cls, key=None, ret='all'):
        '''
        getClassInfo - returns all or a subtree of the token definition

        :param key: subsection identifier
        :type key: string

        :param ret: default return value, if nothing is found
        :type ret: user defined

        :return: subsection if key exists or user defined
        :rtype : s.o.

        '''

        _ = context['translate']

        res = {
            'type': 'vasco',
            'title': _('Vasco Token'),
            'description':
                _('Vasco Digipass Token Class - proprietary timebased tokens'),
            'init': {},
            'config': {},
            'selfservice': {},
        }

        if key is not None and key in res:
            ret = res.get(key)
        else:
            if ret == 'all':
                ret = res

        return ret

    def update(self, param, reset_failcount=True):

        # check for the required parameters
        if self.hKeyRequired is True:
            getParam(param, "otpkey", optional=False)

        TokenClass.update(self, param, reset_failcount=False)

        for key in ["vasco_appl", "vasco_type", "vasco_auth"]:
            val = getParam(param, key, optional=True)
            if val is not None:
                self.addToTokenInfo(key, val)

    def reset(self):
        TokenClass.reset(self)

    def check_otp_exist(self, otp, window=10, user=None, autoassign=False):
        '''
        checks if the given OTP value is/are values of this very token.
        This is used to autoassign and to determine the serial number of
        a token.

        :param otp: The OTP value to search for
        :type otp: string
        :param window: In how many future OTP values the given OTP value
                       should be searched
        :type window: int

        :return: tuple of the result value and the data itself
        '''
        res = self.checkOtp(otp, 0, window)

        return res

    def checkOtp(self, anOtpVal, counter, window, options=None):
        '''
        Checks if the OTP value is valid.

        Therefore the vasco data blob is fetched from the database and this
        very blob and the otp value is passed to the vasco function
        vasco_otp_check.

        After that the modified vasco blob needs to be stored (updated) in the
        database again.
        '''

        secObject = self._get_secret_object()
        otpkey = secObject.getKey()

        # let vasco handle the OTP checking
        (res, otpkey) = vasco_otp_check(otpkey, anOtpVal)

        # update the vasco data blob
        self.update({"otpkey": otpkey})

        if res != 0:
            log.warning("[checkOtp] Vasco token failed to authenticate. "
                        "Vasco Error code: %d" % res)
            # TODO: Vasco gives much more detailed error codes. But at the
            # moment we do not handle more error codes!
            res = -1

        return res

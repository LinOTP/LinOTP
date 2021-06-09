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
""" This file containes the mOTP token implementation:
              - http://motp.sourceforge.net/ -
"""

from linotp.lib.crypto import SecretObj

from linotp.tokens.motp import mTimeOtp
from linotp.tokens.base import TokenClass
from linotp.lib.context import request_context as context
from linotp.lib.error import ParameterError
from linotp.tokens import tokenclass_registry

import logging

log = logging.getLogger(__name__)


###############################################
@tokenclass_registry.class_entry("motp")
@tokenclass_registry.class_entry("linotp.tokens.motptoken.MotpTokenClass")
class MotpTokenClass(TokenClass):
    """
    implementation of the mOTP token class
    - see: http://motp.sourceforge.net/
    """

    @classmethod
    def getClassType(cls):
        """
        static method to return the token class identifier

        :return: fixed string
        """

        return "motp"

    @classmethod
    def getClassPrefix(cls):
        return "LSMO"

    @classmethod
    def getClassInfo(cls, key=None, ret="all"):
        """
        getClassInfo - returns all or a subtree of the token definition

        :param key: subsection identifier
        :type key: string

        :param ret: default return value, if nothing is found
        :type ret: user defined

        :return: subsection if key exists or user defined
        :rtype : s.o.

        """

        res = {
            "type": "motp",
            "title": "mOTP Token",
            "description": ("mobile otp token"),
            "init": {
                "page": {
                    "html": "motp/motptoken.mako",
                    "scope": "enroll",
                },
                "title": {
                    "html": "motp/motptoken.mako",
                    "scope": "enroll.title",
                },
            },
            "config": {
                "page": {
                    "html": "motp/motptoken.mako",
                    "scope": "config",
                },
                "title": {
                    "html": "motp/motptoken.mako",
                    "scope": "config.title",
                },
            },
            "selfservice": {
                "enroll": {
                    "page": {
                        "html": "motp/motptoken.mako",
                        "scope": "selfservice.enroll",
                    },
                    "title": {
                        "html": "motp/motptoken.mako",
                        "scope": "selfservice.title.enroll",
                    },
                },
            },
        }

        if key and key in res:
            ret = res.get(key)
        else:
            if ret == "all":
                ret = res

        return ret

    def __init__(self, a_token):
        """
        constructor - create a token object

        :param a_token: instance of the orm db object
        :type a_token:  orm object
        """
        TokenClass.__init__(self, a_token)
        self.setType("mOTP")

        return

    def update(self, param, reset_failcount=True):
        """
        update - process initialization parameters

        :param param: dict of initialization parameters
        :type param: dict

        :return: nothing

        """

        if "otpkey" not in param:
            raise ParameterError("Missing parameter: 'otpkey'")

        # motp token specific
        try:
            otpPin = param["otppin"]
        except KeyError:
            raise ParameterError("Missing parameter: 'otppin'")

        self.setUserPin(otpPin)

        TokenClass.update(self, param, reset_failcount)

        return

    def checkOtp(self, anOtpVal, counter, window, options=None):
        """
        checkOtp - validate the token otp against a given otpvalue

        :param anOtpVal: the to be verified otpvalue
        :type anOtpVal:  string

        :param counter: the counter state, that shoule be verified
        :type counter: int

        :param window: the counter +window, which should be checked
        :type window: int

        :param options: the dict, which could contain token specific info
        :type options: dict

        :return: the counter state or -1
        :rtype: int

        """

        otplen = self.token.LinOtpOtpLen

        # otime contains the previous verification time
        # the new one must be newer than this!
        otime = self.token.LinOtpCount
        secObj = self._get_secret_object()
        window = self.token.LinOtpCountWindow
        key, iv = self.token.getUserPin()
        secPinObj = SecretObj(key, iv, hsm=context.get("hsm"))

        mtimeOtp = mTimeOtp(secObj, secPinObj, otime, otplen)
        res = mtimeOtp.checkOtp(anOtpVal, window, options=options)

        if res != -1:
            res = res - 1  # later on this will be incremented by 1
        if res == -1:
            msg = "verification failed"
        else:
            msg = "verifiction was successful"

        log.debug("[checkOtp] %s :res %r" % (msg, res))
        return res

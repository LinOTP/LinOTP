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
"""This file containes the dynamic SPass token implementation:
              - SpassTokenClass
"""

import logging

from linotp.tokens.base import TokenClass
from linotp.tokens import tokenclass_registry

from linotp.lib.auth.validate import check_pin


log = logging.getLogger(__name__)


@tokenclass_registry.class_entry("spass")
@tokenclass_registry.class_entry("linotp.tokens.spasstoken.SpassTokenClass")
class SpassTokenClass(TokenClass):
    """
    This is a simple pass token.
    It does have no OTP component. The OTP checking will always
    succeed. Of course, an OTP PIN can be used.
    """

    def __init__(self, aToken):
        TokenClass.__init__(self, aToken)
        self.setType("spass")
        self.mode = ["authenticate"]

    @classmethod
    def getClassType(cls):
        return "spass"

    @classmethod
    def getClassPrefix(cls):
        return "LSSP"

    @classmethod
    def getClassInfo(cls, key=None, ret="all"):
        """
        getClassInfo - returns a subtree of the token definition

        :param key: subsection identifier
        :type key: string

        :param ret: default return value, if nothing is found
        :type ret: user defined

        :return: subsection if key exists or user defined
        :rtype: s.o.

        """

        res = {
            "type": "spass",
            "title": "Simple Pass Token",
            "description": (
                "A token that allows the user to simply pass. Can be combined with the OTP PIN."
            ),
            "config": {},
            "selfservice": {},
            "policy": {},
        }

        # do we need to define the lost token policies here...
        if key is not None and key in res:
            ret = res.get(key)
        else:
            if ret == "all":
                ret = res
        return ret

    def update(self, param):

        if "otpkey" not in param:
            param["genkey"] = 1

        # mark this spass token as usable exactly once
        if "onetime" in param:
            self.count_auth_success_max = 1

        TokenClass.update(self, param)

    # the spass token does not suport challenge response
    def is_challenge_request(self, passw, user, options=None):
        return False

    def is_challenge_response(
        self, passw, user, options=None, challenges=None
    ):
        return False

    def authenticate(self, passw, user, options=None):
        """
        in case of a wrong passw, we return a bad matching pin,
        so the result will be an invalid token
        """
        otp_count = -1
        pin_match = check_pin(self, passw, user=user, options=options)
        if pin_match is True:
            otp_count = 0
            self.auth_info = {"auth_info": [("pin_length", len(passw))]}
        return (pin_match, otp_count, None)


# eof #

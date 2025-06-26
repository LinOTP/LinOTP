#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

"""This file containes PasswordTokenClass"""

import logging

from linotp.lib.crypto import utils
from linotp.lib.error import ParameterError
from linotp.tokens import tokenclass_registry
from linotp.tokens.base import TokenClass
from linotp.tokens.hmactoken import HmacTokenClass

log = logging.getLogger(__name__)

###############################################


@tokenclass_registry.class_entry("pw")
@tokenclass_registry.class_entry("linotp.tokens.passwordtoken.PasswordTokenClass")
class PasswordTokenClass(HmacTokenClass):
    """
    This Token does use a static Password as the OTP value.
    In addition, the OTP PIN can be used with this token.
    This Token can be used for a scenario like losttoken
    """

    def __init__(self, aToken):
        TokenClass.__init__(self, aToken)
        self.hKeyRequired = True
        self.setType("pw")

    @classmethod
    def getClassType(cls):
        return "pw"

    @classmethod
    def getClassPrefix(cls):
        return "kipw"

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
            "type": "pw",
            "title": "Password Token",
            "description": (
                "A token with a fixed password. Can be combined "
                "with the OTP PIN. Is used for the lost token "
                "scenario."
            ),
            "init": {
                "page": {
                    "html": "passwordtoken.mako",
                    "scope": "enroll",
                },
                "title": {
                    "html": "passwordtoken.mako",
                    "scope": "enroll.title",
                },
            },
            "config": {
                "page": {
                    "html": "passwordtoken.mako",
                    "scope": "config",
                },
                "title": {
                    "html": "passwordtoken.mako",
                    "scope": "config.title",
                },
            },
            "selfservice": {
                "enroll": {
                    "page": {
                        "html": "passwordtoken.mako",
                        "scope": "selfservice.enroll",
                    },
                    "title": {
                        "html": "passwordtoken.mako",
                        "scope": "selfservice.title.enroll",
                    },
                },
            },
            "policy": {},
        }

        if key and key in res:
            ret = res.get(key)
        else:
            if ret == "all":
                ret = res
        return ret

    def update(self, param):
        """
        update - the api, which is called during the token enrollment

        we have to make sure that the otpkey, which carries our password
        is encoded as utf-8 to not break the storing

        :raises: otpkey contains the password and is required therefore
                 otherewise raises ParameterError

        """

        if "otpkey" not in param:
            msg = "Missing Parameter 'otpkey'!"
            raise ParameterError(msg)

        # mark this pw token as usable exactly once
        if "onetime" in param:
            self.count_auth_success_max = 1

        TokenClass.update(self, param)

        TokenClass.setOtpLen(self, len(param["otpkey"]))

    def setOtpKey(self, otpKey, reset_failcount=True):
        """
        the seed / secret for the password token contains the unix hashed
        (hmac256) format of the password. the iv is used as indicator that
        we are using the new format, which is the ':1:' indicator

        :param otpKey: the token seed / secret
        :param reset_failcount: boolean, if the failcounter should be reseted
        """

        password_hash = utils.crypt_password(otpKey).encode("utf-8")

        self.token.set_encrypted_seed(
            password_hash, b":1:", reset_failcount=reset_failcount
        )

    def validate_seed(self, seed):
        """
        Accepts every seed because password token has no restrictions.
        This overrides the hmactoken's seed validation (only hex).

        :param seed: a string that should be checked for
        validity as a seed (aka otpkey)
        """

    def checkOtp(self, anOtpVal, counter, window, options=None):
        """
        checks the static password - using the secret object password
        comparison method

        :param anOtpVal: the password to be compared
        :param counter: - not used for the password token -
        :param window: - not used for the password token -
        :param options: - not used for the password token -

        :return: counter, which is 0 for success and -1 for failure
        """

        secObj = self._get_secret_object()

        if secObj.compare_password(anOtpVal):
            return 0

        return -1

    def check_otp_exist(self, otp, window=10, user=None, autoassign=False):
        return self.checkOtp(otp, counter=None, window=None)


# eof #

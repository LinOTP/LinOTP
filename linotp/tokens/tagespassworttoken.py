# -*- coding: utf-8 -*-
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
"""This file contains the dynamic tagespasswort token implementation:
- TagespasswortTokenClass   (DPW)"""

import logging
from datetime import datetime, timedelta
from hashlib import md5

from linotp.lib.context import request_context
from linotp.lib.crypto.utils import zerome
from linotp.lib.error import ParameterError, TokenAdminError
from linotp.tokens import tokenclass_registry
from linotp.tokens.base import TokenClass

log = logging.getLogger(__name__)


class dpwOtp:
    """
    using a context manager pattern to make sure that the secret is
    finally removed at the ending
    """

    def __init__(self, secObj, digits=6):
        self.secretObject = secObj
        self.digits = digits

    def __enter__(self):
        class dpwOtpImpl(object):
            """
            helper class for calculating day passwords. (Tagespasswort)
            """

            def __init__(self, secObj, digits=6):
                self.secretObject = secObj
                self.digits = digits
                self.key: bytes = self.secretObject.getKey()

            def _calc_otp(self, date_string):
                """
                the calculation of the day password should be moved into
                the secret object as a dedicated method

                :return: otp string of digits
                """

                input_data = self.key + date_string.encode("utf-8")

                md1 = md5(input_data).digest().hex()  # nosec B324
                md = md1[len(md1) - self.digits :]
                otp = int(md, 16)
                otp = str(otp)
                otp = otp[len(otp) - self.digits :]

                return (self.digits - len(otp)) * "0" + otp

            def cleanup(self):
                zerome(self.key)
                del self.key

            def checkOtp(self, anOtpVal, window=0, options=None):
                """
                verify the given otp value for the current day

                :param anOtpVal: the to be checked otp value
                :param window: -ignored-
                :param options: -ignored-
                :return: bool
                """

                if str(anOtpVal) == self.getOtp():
                    return 1

                return -1

            def getOtp(self, date_string=None):
                """
                return an otp for a given datetime string

                :param date_string: the datetime string in format %d%m%y
                :return: otp value
                """
                if date_string is None:
                    date_string = datetime.now().strftime("%d%m%y")

                return self._calc_otp(date_string)

        self.package_obj = dpwOtpImpl(self.secretObject, self.digits)
        return self.package_obj

    def __exit__(self, exc_type, exc_value, traceback):
        self.package_obj.cleanup()


# -------------------------------------------------------------------------- --


@tokenclass_registry.class_entry("dpw")
@tokenclass_registry.class_entry(
    "linotp.tokens.tagespassworttoken.TagespasswortTokenClass"
)
class TagespasswortTokenClass(TokenClass):
    """
    The Tagespasswort is a one time password that is calculated based on
    the day input.

    - the initial seed is appended with the day/month/year
    - some md5 and truncation will produce an 6 digits password

    - via getotp the set of next day passwords could be retrieved
    """

    def __init__(self, aToken):
        TokenClass.__init__(self, aToken)
        self.setType("DPW")

        self.hKeyRequired = True

    @classmethod
    def getClassType(cls):
        return "dpw"

    @classmethod
    def getClassPrefix(cls):
        return "DOTP"

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
            "type": "dpw",
            "title": "Tagespasswort Token",
            "description": ("A token uses a new password every day."),
            "init": {
                "page": {
                    "html": "tagespassworttoken.mako",
                    "scope": "enroll",
                },
                "title": {
                    "html": "tagespassworttoken.mako",
                    "scope": "enroll.title",
                },
            },
            "config": {},
            "selfservice": {},
            "policy": {},
        }

        # I don't think we need to define the lost token policies here...

        if key and key in res:
            ret = res.get(key)
        else:
            if ret == "all":
                ret = res
        return ret

    def update(self, param):
        # check for the required parameters
        if self.hKeyRequired is True:
            if "otpkey" not in param:
                raise ParameterError("Missing parameter: 'otpkey'", id=905)

        TokenClass.update(self, param)

    def reset(self):
        TokenClass.reset(self)

    def checkOtp(self, anOtpVal, counter, window, options=None):
        res = -1

        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError:
            return res

        secObj = self._get_secret_object()

        with dpwOtp(secObj, otplen) as dpw:
            res = dpw.checkOtp(anOtpVal, window=window)

        return res

    def getOtp(self, curTime=None):
        res = (-1, 0, 0, 0)

        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError:
            return res

        date_string = None

        if curTime:
            if isinstance(curTime, datetime):
                date_string = curTime.strftime("%d%m%y")
            elif isinstance(curTime, str):
                date_string = datetime.strptime(
                    curTime, "%Y-%m-%d %H:%M:%S.%f"
                ).strftime("%d%m%y")
            else:
                log.error(
                    "[getOtp] invalid curTime: %r. You need to "
                    "specify a datetime.datetime",
                    curTime,
                )

        secObj = self._get_secret_object()
        with dpwOtp(secObj, otplen) as dpw:
            otpval = dpw.getOtp(date_string)

        pin = self.getPin()
        combined = "%s%s" % (otpval, pin)

        if request_context["Config"].get("PrependPin") == "True":
            combined = "%s%s" % (pin, otpval)

        return (1, pin, otpval, combined)

    def get_multi_otp(self, count=0, epoch_start=0, epoch_end=0, curTime=None):
        """
        This returns a dictionary of multiple future OTP values of
        the Tagespasswort token

        parameter
            count    - how many otp values should be returned
            epoch_start    - time based tokens: start when
            epoch_end      - time based tokens: stop when

        return
            True/False
            error text
            OTP dictionary
        """

        otp_dict = {"type": "DPW", "otp": {}}
        ret = False
        error = "No count specified"
        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError as ex:
            log.error("[get_multi_otp] %r", ex)
            return (False, str(ex), otp_dict)

        if count > 0:
            now = datetime.now()
            if curTime:
                if isinstance(curTime, datetime):
                    now = curTime
                elif isinstance(curTime, str):
                    now = datetime.strptime(curTime, "%Y-%m-%d %H:%M:%S.%f")
                else:
                    raise TokenAdminError(
                        "[get_multi_otp] wrong curTime type:"
                        " %s (%s)" % (type(curTime), curTime),
                        id=2001,
                    )

            secObj = self._get_secret_object()
            with dpwOtp(secObj, otplen) as dpw:
                for i in range(count):
                    delta = timedelta(days=i)
                    date_string = (now + delta).strftime("%d%m%y")
                    otpval = dpw.getOtp(date_string=date_string)
                    otp_dict["otp"][
                        (now + delta).strftime("%y-%m-%d")
                    ] = otpval
                ret = True

        return (ret, error, otp_dict)


# eof #

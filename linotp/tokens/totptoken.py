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
"""This file containes the dynamic time based hmac token implementation"""

import datetime
import logging
import time
from typing import Union

from linotp.lib.config import getFromConfig
from linotp.lib.error import ParameterError
from linotp.lib.HMAC import HmacOtp
from linotp.lib.type_utils import boolean
from linotp.lib.util import generate_otpkey
from linotp.tokens import tokenclass_registry
from linotp.tokens.base import TokenClass
from linotp.tokens.hmactoken import HmacTokenClass

keylen = {"sha1": 20, "sha256": 32, "sha512": 64}

log = logging.getLogger(__name__)


"""
TOTP Algorithm

   This variant of the HOTP algorithm specifies the calculation of a
   one-time password value, based on a representation of the counter as
   a time factor.

4.1.  Notations

   - X represents the time step in seconds (default value X = 30
   seconds) and is a system parameter;

   - T0 is the Unix time to start counting time steps (default value is
   0, Unix epoch) and is also a system parameter.

4.2.  Description

   Basically, we define TOTP as TOTP = HOTP(K, T) where T is an integer
   and represents the number of time steps between the initial counter
   time T0 and the current Unix time (i.e. the number of seconds elapsed
   since midnight UTC of January 1, 1970).

   More specifically T = (Current Unix time - T0) / X where:

   - X represents the time step in seconds (default value X = 30
   seconds) and is a system parameter;

   - T0 is the Unix time to start counting time steps (default value is
   0, Unix epoch) and is also a system parameter;

   - The default floor function is used in the computation.  For
   example, with T0 = 0 and time step X = 30, T = 1 if the current Unix
   time is 59 seconds and T = 2 if the current Unix time is 60 seconds.

M'Raihi, et al.          Expires March 12, 2011                 [Page 5]

Internet-Draft                HOTPTimeBased               September 2010


"""


def time2counter(T0: Union[float, int], timeStepping: int) -> int:
    counter = int(T0 // timeStepping)
    return counter


def counter2time(counter, timeStepping):
    T0 = float(counter) * timeStepping
    return T0


###############################################


@tokenclass_registry.class_entry("totp")
@tokenclass_registry.class_entry("linotp.tokens.totptoken.TimeHmacTokenClass")
class TimeHmacTokenClass(HmacTokenClass):
    resyncDiffLimit = 3

    def __init__(self, aToken):
        """
        constructor - create a token object

        :param aToken: instance of the orm db object
        :type aToken:  orm object

        """

        TokenClass.__init__(self, aToken)
        self.setType("TOTP")
        self.hKeyRequired = True

        # timeStep defines the granularity:
        self._timeStep = getFromConfig("totp.timeStep", 30) or 30

        #  window size in seconds:
        #    30 seconds with as step width of 30 seconds results
        #    in a window of 1  which is one attempt

        self.timeWindow = getFromConfig("totp.timeWindow", 180) or 180

        # the time shift is specified in seconds  - and could be
        # positive and negative

        self.timeShift = getFromConfig("totp.timeShift", 0)

        # we support various hashlib methods, but only on create
        # which is effectively set in the update

        self.hashlibStr = getFromConfig("totp.hashlib", "sha1") or "sha1"

        self.otplen = int(self.token.LinOtpOtpLen)

        # ------------------------------------------------------------------ --

        # load token settings from the token info if available

        info = self.getTokenInfo()

        if info:
            self.hashlibStr = info.get("hashlib", self.hashlibStr) or "sha1"

            self.timeStepping = int(info.get("timeStep", self._timeStep) or 30)

            self.window = int(info.get("timeWindow", self.timeWindow) or 180)

            self.shift = int(info.get("timeShift", self.timeShift) or 0)

            log.debug(
                "[checkOTP] timestep: %i, timeWindow: %i, timeShift: %i",
                self.timeStepping,
                self.window,
                self.shift,
            )

        return

    @classmethod
    def getClassType(cls):
        """
        getClassType - return the token type shortname

        :return: 'totp'
        :rtype: string

        """
        return "totp"

    @classmethod
    def getClassPrefix(cls):
        return "TOTP"

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
            "type": "totp",
            "title": "HMAC Time Token",
            "description": ("time based otp token using the hmac algorithm"),
            "init": {
                "page": {
                    "html": "totptoken.mako",
                    "scope": "enroll",
                },
                "title": {
                    "html": "totptoken.mako",
                    "scope": "enroll.title",
                },
            },
            "config": {
                "page": {
                    "html": "totptoken.mako",
                    "scope": "config",
                },
                "title": {
                    "html": "totptoken.mako",
                    "scope": "config.title",
                },
            },
            "selfservice": {
                "enroll": {
                    "page": {
                        "html": "totptoken.mako",
                        "scope": "selfservice.enroll",
                    },
                    "title": {
                        "html": "totptoken.mako",
                        "scope": "selfservice.title.enroll",
                    },
                },
            },
            "policy": {
                "selfservice": {
                    "totp_timestep": {
                        "type": "int",
                        "value": [30, 60],
                        "desc": ("Specify the time step of the timebased OTP token."),
                    },
                    "totp_hashlib": {
                        "type": "int",
                        "value": [1, 2, 3],
                        "desc": (
                            "Specify the hashlib to be used. Can be "
                            "sha1 (1), sha256 (2) or sha512 (3)"
                        ),
                    },
                    "totp_otplen": {
                        "type": "int",
                        "value": [6, 8],
                        "desc": (
                            "Specify the otplen to be used. Can be 6 or 8 digits."
                        ),
                    },
                },
            },
        }

        if key is not None and key in res:
            ret = res.get(key)
        else:
            if ret == "all":
                ret = res
        return ret

    def update(self, param):
        """
        update - process the initialization parameters

        :param param: dict of initialization parameters
        :type param: dict

        :return: nothing
        """

        # check for the required parameters
        val = param.get("hashlib")
        if val is not None:
            self.hashlibStr = val
        else:
            self.hashlibStr = "sha1"

        otpKey = ""

        if self.hKeyRequired is True:
            genkey = int(param.get("genkey", 0))
            if 1 == genkey:
                # if hashlibStr not in keylen dict, this will raise an
                # Exception
                otpKey = generate_otpkey(keylen.get(self.hashlibStr))
                del param["genkey"]
            else:
                # genkey not set: check otpkey is given
                # this will raise an exception if otpkey is not present
                try:
                    otpKey = param["otpkey"]
                except KeyError:
                    raise ParameterError("Missing parameter: 'serial'")

        # finally set the values for the update

        param["otpkey"] = otpKey
        param["hashlib"] = self.hashlibStr

        val = param.get("otplen")
        if val is not None:
            self.setOtpLen(int(val))
        else:
            self.setOtpLen(getFromConfig("DefaultOtpLen"))

        val = param.get("timeStep")
        if val is not None:
            self._timeStep = val

        val = param.get("timeWindow")
        if val is not None:
            self.timeWindow = val

        val = param.get("timeShift")
        if val is not None:
            self.timeShift = val

        HmacTokenClass.update(self, param)

        if self.timeWindow is not None and self.timeWindow != "":
            self.addToTokenInfo("timeWindow", self.timeWindow)
        if self.timeShift is not None and self.timeShift != "":
            self.addToTokenInfo("timeShift", self.timeShift)
        if self._timeStep is not None and self._timeStep != "":
            self.addToTokenInfo("timeStep", self._timeStep)
        if self.hashlibStr:
            self.addToTokenInfo("hashlib", self.hashlibStr)

        return

    def check_otp_exist(self, otp, window=10, user=None, autoassign=False):
        """
        checks if the given OTP value is/are values of this very token.
        This is used to autoassign and to determine the serial number of
        a token.

        :param otp: the to be verified otp value
        :type otp: string

        :param window: the lookahead window for the counter
        :type window: int

        :return: counter or -1 if otp does not exist
        :rtype:  int

        """

        res = -1

        try:
            counter = int(self.token.LinOtpCount)
        except ValueError as ex:
            log.warning(
                "[check_otp_exist] a value error occurred while "
                "converting: counter %r : ValueError: %r ret: %r ",
                self.token.LinOtpCount,
                ex,
                res,
            )
            return res

        res = self.checkOtp(otp, counter, window=window)

        return res

    def time2float(self, curTime):
        """
        time2float - convert a datetime object or an datetime string into a float
        s. http://bugs.python.org/issue12750

        :param curTime: time in datetime format
        :type curTime: datetime object

        :return: time as float
        :rtype: float
        """

        dt = datetime.datetime.now()
        if isinstance(curTime, datetime.datetime):
            dt = curTime
        elif isinstance(curTime, str):
            if "." in curTime:
                tFormat = "%Y-%m-%d %H:%M:%S.%f"
            else:
                tFormat = "%Y-%m-%d %H:%M:%S"
            try:
                dt = datetime.datetime.strptime(curTime, tFormat)
            except Exception as ex:
                log.error("[time2float] Error during conversion of datetime: %r", ex)
                raise
        else:
            raise Exception(
                "[time2float] invalid curTime: %s. You need to specify a datetime.datetime"
                % type(curTime)
            )

        td = dt - datetime.datetime(1970, 1, 1)
        # for python 2.6 compatibility, we have to implement 2.7 .total_seconds()::
        # TODO: fix to float!!!!
        tCounter = (
            (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) * 1.0
        ) // 10**6

        return tCounter

    def checkOtp(self, anOtpVal, counter, window, options=None):
        """
        checkOtp - validate the token otp against a given otpvalue

        :param anOtpVal: the to be verified otpvalue
        @type anOtpVal:  string

        :param counter: the counter state, that should be verified
        :type counter: int

        :param window: the counter +window, which should be checked
        :type window: int

        :param options: the dict, which could contain token specific info
        :type options: dict

        :return: the counter state or -1
        :rtype: int

        """

        # convert the window counter into seconds
        totp_window = window * self.timeStepping

        T0 = time.time() + self.shift

        counter = time2counter(T0, timeStepping=self.timeStepping)

        # ------------------------------------------------------------------ --

        # setup the hmac object, which encapsulates the secret context

        secObj = self._get_secret_object()
        hmac2Otp = HmacOtp(
            secObj, counter, self.otplen, self.getHashlib(self.hashlibStr)
        )

        # ------------------------------------------------------------------ --

        otp_match_counter = hmac2Otp.checkOtp(
            anOtpVal, int(totp_window // self.timeStepping), symetric=True
        )

        # ------------------------------------------------------------------ --

        # protect against a replay

        # if the counter belonging to the provided otp is lower than the
        # stored counter (which is the next expected counter), then we deny
        # as it might be replay

        if otp_match_counter != -1 and otp_match_counter < self.getOtpCount():
            log.warning("a previous OTP value was used again!")
            return -1

        # ------------------------------------------------------------------ --

        # the otp might be out of the test window so we try to autosync:
        # look if two consecutive otps has been provided

        if otp_match_counter == -1:
            otp_match_counter = self.autosync(hmac2Otp, anOtpVal)

        if otp_match_counter == -1:
            log.debug("otp verification failed!")
            return -1

        # ------------------------------------------------------------------ --

        # on success, we have to save the timeshift and matching otp counter
        self.set_new_timeshift(otp_match_counter)

        # and the matching otp counter
        self.setOtpCount(otp_match_counter)

        log.debug("otp verification result was: res %r", otp_match_counter)
        return otp_match_counter

    @property
    def timeStep(self):
        return self.getFromTokenInfo("timeStep")

    @timeStep.setter
    def timeStep(self, value: int):
        """Totp token property setter for timeStep.

        :param value: the new timeStep value
        """
        if value not in [60, 30]:
            raise ValueError("timeStep for totp token must be either 30 or 60!")

        new_time_count = self.getOtpCount() * self.timeStepping // value
        self.setOtpCount(int(new_time_count))
        self.addToTokenInfo("timeStep", value)

    def set_new_timeshift(self, otp_match_counter):
        """
        calculate and set the new timeshift

        :param otp_match_counter: the counter that matches the given otp
        """

        new_shift = self._calculate_new_timeshift(
            otp_match_counter, self.getOtpCount(), self.timeStepping
        )

        self.addToTokenInfo("timeShift", new_shift)

    def autosync(self, hmac2Otp, anOtpVal):
        """
        auto - sync the token based on two otp values
        - internal method to realize the autosync within the
        checkOtp method

        :param hmac2Otp: the hmac object (with reference to the token secret)
        :type hmac2Otp: hmac object

        :param anOtpVal: the actual otp value
        :type anOtpVal: string

        :return: counter or -1 if otp does not exist
        :rtype:  int

        """

        if not boolean(getFromConfig("AutoResync", False)):
            log.info("autosync is not enabled")
            return -1

        info = self.getTokenInfo()
        syncWindow = self.getSyncWindow()

        # check if the otpval is valid in the sync scope
        otp_counter = hmac2Otp.checkOtp(anOtpVal, syncWindow, symetric=True)

        if otp_counter == -1:
            log.info("no valid otp in auto resync window")
            return -1

        # ------------------------------------------------------------------ --

        # protect against a replay

        # if the counter belonging to the provided otp is lower than the
        # stored counter (which is the next expected counter), then we deny
        # the resync as it might be replay

        if otp_counter < self.getOtpCount():
            log.info("otp before the last verified valid otp!")
            return -1

        # ------------------------------------------------------------------ --

        # taken from the tokeninfo:
        # check if we have the first otp for the auto resync

        if "otp1c" not in info:
            info["otp1c"] = otp_counter
            self.setTokenInfo(info)

            log.info("preserved the first otp counter for resync")
            return -1

        # ------------------------------------------------------------------ --

        # now we have 2 otps - the first from the former request,
        # the second otp from the current auto sync request

        otp1c = info["otp1c"]
        otp2c = otp_counter

        if otp2c <= otp1c:
            # the otps are not in right order
            log.info("OTP values are not in the right order!")
            return -1

        if (otp2c - otp1c) > self.resyncDiffLimit:
            # assert that the otps are not too far apart
            log.info("the otps are too far apart for resync!")

            # if so, we take the new one as the auto sync base
            info["otp1c"] = otp2c
            self.setTokenInfo(info)
            return -1

        # reset the resync info
        self.removeFromTokenInfo("otp1c")

        return otp_counter

    @staticmethod
    def _calculate_new_timeshift(new_counter, old_counter, timeStepping):
        """
        Calculate the time offset between token and server time

        Over time, the token's internal clock can drift away
        from the time it is supposed to represent. If the
        difference gets too big, the user may be locked out.

        In order to counteract this, we keep track of the
        difference between the token time and the server time.

        Well, we can't read that directly from the token, so
        we actually calculate the offset based on the time that
        we received the last otp value from the user, and
        compare that to the server time.

        Note that this works reasonably well as long as the
        server time is kept accurate by the sysadmin.

        :param new_counter: the new matching counter
        :param old_counter: the previous counter
        :patam timeStepping: the token timestep

        :return: the calculated difference in time shift
        """

        tokentime = counter2time(new_counter, timeStepping)
        tokenDt = datetime.datetime.fromtimestamp(float(tokentime))

        inow = int(time.time())
        nowDt = datetime.datetime.fromtimestamp(float(inow))

        # reverse time mapping:
        # from time to counter to timeStepping mapped timeslot

        lastauth = counter2time(old_counter, timeStepping)
        lastauthDt = datetime.datetime.fromtimestamp(float(lastauth))

        log.debug("[checkOTP] last auth : %r", lastauthDt)
        log.debug("[checkOTP] tokentime : %r", tokenDt)
        log.debug("[checkOTP] now       : %r", nowDt)
        log.debug("[checkOTP] delta     : %r", tokentime - inow)

        inow_counter = time2counter(inow, timeStepping)
        inow_token_time = counter2time(inow_counter, timeStepping)

        new_shift = tokentime - inow_token_time

        log.debug("New shift for counter %r: %r", new_counter, new_shift)

        return new_shift

    def resync(self, otp1, otp2, options=None):
        """
        resync the token based on two otp values
        - external method to do the resync of the token

        :param otp1: the first otp value
        :type otp1: string

        :param otp2: the second otp value
        :type otp2: string

        :param options: optional token specific parameters
        :type options:  dict or None

        :return: counter or -1 if otp does not exist
        :rtype:  int

        """

        ret = False

        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError:
            return ret

        secObj = self._get_secret_object()

        self.hashlibStr = self.getFromTokenInfo("hashlib", "sha1")
        hashlib = self.getHashlib(self.hashlibStr)
        time_step = int(self.getFromTokenInfo("timeStep", 30))
        time_shift = int(self.getFromTokenInfo("timeShift", 0))

        try:
            counter_window = int(self.token.LinOtpSyncWindow)
        except BaseException:
            counter_window = 10
        time_window = counter_window * time_step

        T0 = time.time() + time_shift
        counter_T0 = int(T0 // time_step)
        counter_token = self.getOtpCount()

        log.debug("[resync] current time T0: %i, counter: %i", T0, counter_T0)
        log.debug("[resync] current token counter: %r", counter_token)

        log.debug(
            "[resync] checking time_window: %s, time_step: %s, current token time_shift: %s",
            time_window,
            time_step,
            time_shift,
        )

        log.debug("[resync] checking otp2: %s", otp2)
        hmac2Otp = HmacOtp(secObj, counter_T0, otplen, hashlib)
        res2 = hmac2Otp.checkOtp(otp2, counter_window, symetric=True)
        log.debug("[resync] counter for given OTP: %r", res2)
        if res2 == -1:
            log.debug("[resync] no OTP match in the checked window.")

        log.debug("[resync] checking otp1: %s", otp1)
        hmac2Otp = HmacOtp(secObj, counter_T0 - 1, otplen, hashlib)
        res1 = hmac2Otp.checkOtp(otp1, counter_window, symetric=True)
        log.debug("[resync] counter for given OTP: %r", res1)
        if res1 == -1:
            log.debug("[resync] no OTP match in the checked window.")

        if res1 != -1 and res1 < counter_token:
            log.warning(
                "[resync] a previous OTP value was used again! "
                "current token counter: %i, presented counter: %i",
                counter_token,
                res1,
            )
            res1 = -1

        if res1 != -1 and res1 + 1 == res2:
            # here we calculate the new drift/shift between the server time and
            # the tokentime
            tokentime = (res2 + 0.5) * time_step
            currenttime = T0 - time_shift
            new_shift = tokentime - currenttime
            log.debug(
                "[resync] the counters %r and %r matched. New shift: %r",
                res1,
                res2,
                new_shift,
            )
            self.addToTokenInfo("timeShift", new_shift)

            # The OTP value that was used for resync must not be used again!
            self.setOtpCount(res2 + 1)

            ret = True

        if ret is True:
            msg = "resync was successful"
        else:
            msg = "resync was not successful"

        log.debug(msg)
        return ret

    def getSyncTimeOut(self):
        """
        get the token sync timeout value

        :return: timeout value in seconds
        :rtype:  int
        """

        timeOut = int(getFromConfig("AutoResyncTimeout", 5 * 60))
        return timeOut

    def getOtp(self, curTime=None):
        """
        get the next OTP value

        :return: next otp value
        :rtype: string
        """

        res = (-1, 0, 0, 0)

        otplen = int(self.token.LinOtpOtpLen)
        secObj = self._get_secret_object()

        self.hashlibStr = self.getFromTokenInfo("hashlib", "sha1") or "sha1"
        timeStepping = int(self.getFromTokenInfo("timeStep", 30) or 30)
        shift = int(self.getFromTokenInfo("timeShift", 0) or 0)

        hmac2Otp = HmacOtp(
            secObj,
            self.getOtpCount(),
            otplen,
            self.getHashlib(self.hashlibStr),
        )

        tCounter = self.time2float(datetime.datetime.utcnow())
        if curTime:
            tCounter = self.time2float(curTime)

        counter = int((tCounter - shift) // timeStepping)
        otpval = hmac2Otp.generate(counter=counter, inc_counter=False)

        pin = self.getPin()
        combined = "%s%s" % (otpval, pin)
        if getFromConfig("PrependPin") == "True":
            combined = "%s%s" % (pin, otpval)

        return (1, pin, otpval, combined)

    def get_multi_otp(self, count=0, epoch_start=0, epoch_end=0, curTime=None):
        """
        return a dictionary of multiple future OTP values of the HOTP/HMAC token

        :param count:   how many otp values should be returned
        :type count:    int

        :return:     tuple of status: boolean, error: text and the OTP dictionary

        """

        otp_dict = {"type": "TOTP", "otp": {}}
        ret = False
        error = "No count specified"
        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError:
            return ret

        secObj = self._get_secret_object()
        self.hashlibStr = self.getFromTokenInfo("hashlib", "sha1") or "sha1"
        timeStepping = int(self.getFromTokenInfo("timeStep", 30) or 30)
        shift = int(self.getFromTokenInfo("timeShift", 0) or 0)

        hmac2Otp = HmacOtp(
            secObj,
            self.getOtpCount(),
            otplen,
            self.getHashlib(self.hashlibStr),
        )

        tCounter = self.time2float(datetime.datetime.utcnow())
        if curTime:
            tCounter = self.time2float(curTime)

        counter = int((tCounter - shift) // timeStepping)

        otp_dict["shift"] = shift
        otp_dict["timeStepping"] = timeStepping

        if count > 0:
            for i in range(0, count):
                otpval = hmac2Otp.generate(counter=counter + i, inc_counter=False)
                timeCounter = ((counter + i) * timeStepping) + shift
                otp_dict["otp"][counter + i] = {
                    "otpval": otpval,
                    "time": datetime.datetime.utcfromtimestamp(timeCounter).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                }
            ret = True

        return (ret, error, otp_dict)

    def get_otp_detail(self, otp, window="24h"):
        """
        provide information belonging to one otp

        :param otp: the otp for which the timestamp is searched
        :param window: string, in human readable '2h' or iso8601 format 'PT2H'
        """

        from linotp.lib.type_utils import parse_duration

        window = parse_duration(window).total_seconds()

        # ------------------------------------------------------------------ --

        time_step = self.timeStepping

        T0 = time.time() + self.shift
        counter = time2counter(T0, timeStepping=time_step)

        # ------------------------------------------------------------------ --

        # prepare the hmac operation

        secObj = self._get_secret_object()
        hmac2Otp = HmacOtp(
            secObj, counter, self.otplen, self.getHashlib(self.hashlibStr)
        )
        matching_counter = hmac2Otp.checkOtp(
            otp, int(window // time_step), symetric=True
        )

        # ------------------------------------------------------------------ --

        # matching_counter =-1 : no otp found in the current time frame

        if matching_counter == -1:
            log.info("no matching otp found in window: %r", window)
            return False, None

        # ------------------------------------------------------------------ --

        # do not provide information of otps in the future

        if matching_counter >= counter:
            log.info("otp is in future - no info for future otps")
            return False, None

        # ------------------------------------------------------------------ --

        # all fine - now return the time stamp and the utc time format

        time_stamp = counter2time(matching_counter, timeStepping=time_step)

        time_info = datetime.datetime.utcfromtimestamp(time_stamp)

        return True, {
            "serial": self.getSerial(),
            "otp": otp,
            "counter": matching_counter,
            "time": time_info.isoformat(),
            "seconds": int(time_stamp),
            "span": time_step,
        }

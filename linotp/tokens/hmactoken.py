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
"""This file containes the dynamic hmac token implementation:
- HmacTokenClas   (HOTP)
"""

import logging
import string
import time
from datetime import datetime

from Cryptodome.Hash import SHA1, SHA256, SHA512
from flask_babel import gettext as _

from linotp.lib.apps import NoOtpAuthTokenException, create_google_authenticator
from linotp.lib.auth.validate import check_otp, check_pin
from linotp.lib.config import getFromConfig
from linotp.lib.HMAC import HmacOtp
from linotp.lib.reply import create_img
from linotp.tokens import tokenclass_registry
from linotp.tokens.base import InvalidSeedException, TokenClass

log = logging.getLogger(__name__)


keylen = {
    "sha1": SHA1.digest_size,
    "sha256": SHA256.digest_size,
    "sha512": SHA512.digest_size,
}


@tokenclass_registry.class_entry("hmac")
@tokenclass_registry.class_entry("linotp.tokens.hmactoken.HmacTokenClass")
class HmacTokenClass(TokenClass):
    """
    hotp token class implementation
    """

    @classmethod
    def getClassType(cls):
        """
        getClassType - return the token type shortname

        :return: 'hmac'
        :rtype: string

        """
        return "hmac"

    @classmethod
    def getClassPrefix(cls):
        return "oath"

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
            "type": "hmac",
            "title": "HMAC Event Token",
            "description": ("event based otp token using the hmac algorithm"),
            "selfservice": {
                "enroll": {}  # keep for dynamic policy definitions
            },
            "init": {
                "page": {
                    "html": "hmactoken.mako",
                    "scope": "enroll",
                },
                "title": {
                    "html": "hmactoken.mako",
                    "scope": "enroll.title",
                },
            },
            "config": {
                "page": {
                    "html": "hmactoken.mako",
                    "scope": "config",
                },
                "title": {
                    "html": "hmactoken.mako",
                    "scope": "config.title",
                },
            },
            "policy": {
                "selfservice": {
                    "hmac_hashlib": {
                        "type": "int",
                        "value": [1, 2, 3],
                        "desc": (
                            "Specify the hashlib to be used. Can be "
                            "sha1 (1), sha256 (2) or sha512 (3)"
                        ),
                    },
                    "hmac_otplen": {
                        "type": "int",
                        "value": [6, 8],
                        "desc": _(
                            "Specify the otplen to be used. Can be 6 or 8 digits."
                        ),
                    },
                }
            },
        }

        if key is not None and key in res:
            ret = res.get(key)
        elif ret == "all":
            ret = res
        return ret

    def __init__(self, a_token):
        """
        constructor - create a token object

        :param aToken: instance of the orm db object
        :type aToken:  orm object

        """

        TokenClass.__init__(self, a_token)
        self.setType("HMAC")
        self.hKeyRequired = True
        self.authenticated = None

        # we support various hashlib methods, but only on create
        # which is effectively set in the update

        self.hashlibStr = self.getFromTokenInfo(
            "hashlib", getFromConfig("hotp.hashlib", "sha1")
        )

    def update(self, param, reset_failcount=True):
        """
        update - process the initialization parameters

        :param param: dict of initialization parameters
        :type param: dict

        :return: nothing
        """

        # Remark: the otpKey is handled in the parent class

        self.hashlibStr = param.get("hashlib", "sha1") or "sha1"

        # check if the key_size id provided
        # if not, we could derive it from the hashlib
        key_size = param.get("key_size")
        if not key_size and self.hashlibStr in keylen:
            key_size = keylen.get(self.hashlibStr)

        param["key_size"] = key_size
        param["hashlib"] = self.hashlibStr
        self.addToTokenInfo("hashlib", self.hashlibStr)

        # ------------------------------------------------------------------ --

        # for usability reason we can accept otpkeys with white spaces or
        # separators like '-', we just replace them before storing it

        if "otpkey" in param:
            otpkey = param["otpkey"]
            param["otpkey"] = otpkey.replace(" ", "").replace("-", "")

        # ------------------------------------------------------------------ --

        TokenClass.update(self, param, reset_failcount)

    def validate_seed(self, seed):
        """
        Check if the seed string contains only hexadecimal characters.

        :param seed: a string that should be checked for
        validity as a seed (aka otpkey)
        :raises InvalidSeedException: if the seed contains
        invalid characters
        """
        is_hexadecimal = all(c in string.hexdigits for c in seed)
        if not is_hexadecimal:
            message = "The provided token seed contains non-hexadecimal characters"
            raise InvalidSeedException(message)

    # challenge interfaces starts here

    def is_challenge_request(self, passw, user, options=None):
        """
        check, if the request would start a challenge

        - default: if the passw contains only the pin, this request would
        trigger a challenge

        - in this place as well the policy for a token is checked

        :param passw: password, which might be pin or pin+otp
        :param options: dictionary of additional request parameters

        :return: returns true or false
        """

        trigger_challenge = False
        pin_match = check_pin(self, passw, user=user, options=options)
        if pin_match is True:
            trigger_challenge = True

        return trigger_challenge

    def is_challenge_response(self, passw, user, options=None, challenges=None):
        """
        This method checks, if this is a request, that is the response to
        a previously sent challenge.

        The default behaviour to check if this is the response to a
        previous challenge is simply by checking if the request contains
        a parameter ``state`` or ``transactionid`` i.e. checking if the
        ``options`` parameter contains a key ``state`` or ``transactionid``.

        This method does not try to verify the response itself!
        It only determines, if this is a response for a challenge or not.

        :param passw: password, which might be pin or pin+otp
        :type passw: string
        :param user: the requesting user
        :type user: User object
        :param options: dictionary of additional request parameters
        :type options: (dict)
        :param challenges: A list of challenges for this token. These
                           challenges may be used, to identify if this request
                           is a response for a challenge.

        :return: true or false
        """

        if "state" in options or "transactionid" in options:
            return True

        pin_match, otp_counter, reply = self.authenticate(
            passw=passw, user=user, options=options
        )

        if otp_counter >= 0:
            self.authenticated = pin_match, otp_counter, reply
            return True

        return False

    def checkResponse4Challenge(self, user, passw, options=None, challenges=None):
        """
        verify the response of a previous challenge

        :param user:     the requesting user
        :param passw:    the to be checked pass (pin+otp)
        :param options:  options an additional argument, which could be token
                          specific
        :param challenges: the list of challenges, where each challenge is
                            described as dict
        :return: tuple of (otpcounter and the list of matching challenges)

        """

        # fetch the transactionid
        transid = options.get("transactionid", options.get("state", None))

        # in case of no transaction id, we do a direct authentication
        if not transid and self.authenticated is not None:
            _pin_match, otp_counter, _reply = self.authenticated
            return otp_counter, []

        if not challenges:
            return -1, []

        # otherwise we autheticate by the transaction id / challenges
        otp_counter = -1
        matching_challenges = []

        for challenge in challenges:
            _otp_counter = check_otp(self, passw, options=options)
            if _otp_counter >= 0:
                matching_challenges.append(challenge)

                # ensure that a positive otp_counter is preserved
                otp_counter = _otp_counter

        return otp_counter, matching_challenges

    def createChallenge(self, state, options=None):
        """
        create a challenge, which is submitted to the user

        :param state: the state/transaction id
        :param options: the request context parameters / data
        :return: tuple of (bool, message and data)
                 message is submitted to the user
                 data is preserved in the challenge
                 attributes are additional attributes, which could be returned
        """
        message = self.getChallengePrompt(default="Please enter your otp value: ")

        data = {
            "serial": self.token.getSerial(),
            "date": f"{datetime.now()}",
        }

        return (True, message, data, None)

    def checkOtp(self, anOtpVal, counter, window, options=None):
        """
        checkOtp - validate the token otp against a given otpvalue

        :param anOtpVal: the to be verified otpvalue
        :type anOtpVal:  string

        :param counter: the counter state, that should be verified
        :type counter: int

        :param window: the counter +window, which should be checked
        :type window: int

        :param options: the dict, which could contain token specific info
        :type options: dict

        :return: the counter state or -1
        :rtype: int

        """
        res = -1

        try:
            otplen = int(self.getOtpLen())
        except ValueError as ex:
            log.error(
                "[checkOtp] failed to initialize otplen: ValueError %r %r",
                ex,
                self.token.LinOtpOtpLen,
            )
            raise

        try:
            self.hashlibStr = self.getFromTokenInfo("hashlib", "sha1")
        except Exception as ex:
            log.error("[checkOtp] failed to initialize hashlibStr: %r", ex)
            raise

        secObj = self._get_secret_object()

        hmac2Otp = HmacOtp(secObj, counter, otplen, self.getHashlib(self.hashlibStr))
        res = hmac2Otp.checkOtp(anOtpVal, window)

        if res == -1:
            res = self.autosync(hmac2Otp, anOtpVal)

        return res

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
            otplen = int(self.token.LinOtpOtpLen)
            counter = int(self.token.LinOtpCount)
        except ValueError as ex:
            log.warning(
                "[check_otp_exist] a value error occurred while converting: "
                "otplen %r, counter %r : ValueError: %r ret: %r ",
                self.token.LinOtpOtpLen,
                self.token.LinOtpCount,
                ex,
                res,
            )
            return res

        self.hashlibStr = self.getFromTokenInfo("hashlib", "sha1")

        secObj = self._get_secret_object()
        hmac2Otp = HmacOtp(secObj, counter, otplen, self.getHashlib(self.hashlibStr))
        res = hmac2Otp.checkOtp(otp, window)

        if res >= 0:
            # As usually the counter is increased in auth.validate.checkUserPass, we
            # need to do this manually here:
            self.incOtpCounter(res)
        if res == -1:
            _msg = f"otp counter {otp!r} was not found"
        else:
            _msg = f"otp counter {otp!r} was found"
        return res

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

        res = -1
        autosync = False

        # get autosync from config or use False as default
        setting = getFromConfig("AutoResync", False)
        # TODO: nasty:
        # The SQLite database returns AutoResync as a boolean and not as a string.
        # So the boolean has no .lower()
        if isinstance(setting, bool):
            autosync = setting
        elif setting.lower() == "true":
            autosync = True
        elif setting.lower() == "false":
            autosync = False
        else:
            autosync = False

        # if autosync is enabled
        if not autosync:
            log.debug("[autosync] end. autosync is not enabled : res %r", res)
            return res

        info = self.getTokenInfo()
        syncWindow = self.getSyncWindow()

        # check if the otpval is valid in the sync scope
        res = hmac2Otp.checkOtp(anOtpVal, syncWindow)

        # if yes:
        if res != -1:
            # if former is defined
            if "otp1c" in info:
                # check if this is consecutive
                otp1c = info.get("otp1c")
                otp2c = res

                if (otp1c + 1) != otp2c:
                    res = -1

                if "dueDate" in info:
                    dueDate = info.get("dueDate")
                    now = int(time.time())
                    if dueDate <= now:
                        res = -1
                else:
                    res = -1

                # now clean the resync data
                del info["dueDate"]
                del info["otp1c"]
                self.setTokenInfo(info)

            else:
                info["otp1c"] = res
                info["dueDate"] = int(time.time()) + self.getSyncTimeOut()
                self.setTokenInfo(info)

                res = -1

        _msg = "call was not successful" if res == -1 else "call was successful"

        return res

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
        except ValueError as ex:
            log.debug("[resync] otplen ValueError: %r ret: %r ", ex, ret)
            raise

        self.hashlibStr = self.getFromTokenInfo("hashlib", "sha1")

        secObj = self._get_secret_object()
        counter = self.token.getOtpCounter()
        syncWindow = self.token.getSyncWindow()
        # log.debug("serial: %s",serialNum)
        hmac2Otp = HmacOtp(secObj, counter, otplen, self.getHashlib(self.hashlibStr))
        counter = hmac2Otp.checkOtp(otp1, syncWindow)

        if counter == -1:
            log.debug("[resync] exit. First counter (-1) not found ret: %r", ret)
            return ret

        nextOtp = hmac2Otp.generate(counter + 1)

        if nextOtp != otp2:
            log.debug(
                "[resync] exit. Failed to verify second otp: nextOtp:"
                " %r != otp2: %r ret: %r",
                nextOtp,
                otp2,
                ret,
            )
            return ret

        ret = True
        self.incOtpCounter(counter + 1, True)

        log.debug("Resync was successful")
        return ret

    def getSyncTimeOut(self):
        """
        get the token sync timeout value

        :return: timeout value in seconds
        :rtype:  int
        """
        try:
            timeOut = int(getFromConfig("AutoResyncTimeout", 5 * 60))
        except Exception as ex:
            log.warning(
                "[getSyncTimeOut] AutoResyncTimeout: value error %r - reset to 5*60",
                ex,
            )
            timeOut = 5 * 60

        return timeOut

    def getOtp(self, curTime=None):
        """
        get the next OTP value

        :return: next otp value
        :rtype: string
        """

        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError as exx:
            log.error("[getOtp]: Could not convert otplen - value error %r ", exx)
            raise

        self.hashlibStr = self.getFromTokenInfo("hashlib", "sha1")
        secObj = self._get_secret_object()

        hmac2Otp = HmacOtp(
            secObj,
            self.getOtpCount(),
            otplen,
            self.getHashlib(self.hashlibStr),
        )
        otpval = hmac2Otp.generate(inc_counter=False)

        pin = self.getPin()
        combined = f"{otpval}{pin}"

        if getFromConfig("PrependPin") == "True":
            combined = f"{pin}{otpval}"

        return (1, pin, otpval, combined)

    def get_multi_otp(self, count=0, epoch_start=0, epoch_end=0, curTime=None):
        """
        return a dictionary of multiple future OTP values of the HOTP/HMAC token

        :param count:   how many otp values should be returned
        :type count:    int

        :return:     tuple of status: boolean, error: text and the OTP dictionary

        """

        otp_dict = {"type": "HMAC", "otp": {}}
        ret = False
        error = "No count specified"
        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError as exx:
            log.error(
                "[get_multi_otp]: Could not convert otplen - value error %r ",
                exx,
            )
            raise
        s_count = self.getOtpCount()
        secObj = self._get_secret_object()
        hmac2Otp = HmacOtp(secObj, s_count, otplen, self.getHashlib(self.hashlibStr))

        if count > 0:
            for i in range(count):
                otpval = hmac2Otp.generate(s_count + i, inc_counter=False)
                otp_dict["otp"][s_count + i] = otpval
            ret = True

        return (ret, error, otp_dict)

    def getInitDetail(self, params, user=None):
        """
        to complete the token normalisation, the response of the initialiastion
        should be build by the token specific method, the getInitDetails
        """
        response_detail = {}

        info = self.getInfo()
        response_detail.update(info)
        response_detail["serial"] = self.getSerial()

        otpkey = None
        if "otpkey" in info:
            otpkey = info.get("otpkey")

        if otpkey is not None:
            response_detail["otpkey"] = {
                "order": "1",
                "description": _("OTP seed"),
                "value": f"seed://{otpkey}",
                "img": create_img(otpkey, width=200),
            }
            try:
                p = {}
                p.update(params)
                p["otpkey"] = otpkey
                p["serial"] = self.getSerial()
                # label
                enrollment_url = create_google_authenticator(p, user=user)

                enrollment_url_detail = {
                    "order": "0",
                    "description": _("OTPAuth Url"),
                    "value": enrollment_url,
                    "img": create_img(enrollment_url, width=250),
                }
                # add enrollment_url_detail to both `enrollment_url` and soon to be deprecated `googleurl`
                response_detail["enrollment_url"] = enrollment_url_detail
                response_detail["googleurl"] = enrollment_url_detail

            except NoOtpAuthTokenException as exx:
                log.warning(exx)

        return response_detail

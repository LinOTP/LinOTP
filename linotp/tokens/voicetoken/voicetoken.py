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

import datetime
import binascii

from linotp.lib.HMAC import HmacOtp

from linotp.lib.user import getUserDetail

from linotp.lib.auth.validate import check_pin
from linotp.lib.auth.validate import check_otp
from linotp.lib.auth.validate import split_pin_otp

from linotp.lib.config import getFromConfig

from linotp.lib.token import get_token_owner

from linotp.lib.policy.action import get_action_value
from linotp.lib.policy import getPolicy, get_client_policy
from linotp.lib.policy import trigger_phone_call_on_empty_pin
from linotp.provider import loadProviderFromPolicy

from linotp.lib.context import request_context as context
from linotp.lib.error import ParameterError

from linotp.tokens.hmactoken import HmacTokenClass
from linotp.tokens import tokenclass_registry

import logging

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- --


def get_voice_message(user="", realm=""):
    """
    This function returns the voice message as defined in the policy
    authentication/voice_message. If no such policy is defined, the
    function returns the fallback message "{otp}"

    :return: string
    """

    voice_text = "{otp}"

    pol = get_client_policy(
        context["Client"],
        scope="authentication",
        realm=realm,
        user=user,
        action="voice_message",
    )

    if len(pol) > 0:
        voice_text = get_action_value(
            pol, scope="authentication", action="voice_message", default=""
        )

        log.debug("[get_voice_message] got the voice_message = %s", voice_text)

    return voice_text


# --------------------------------------------------------------------------- --


def get_voice_language(user="", realm=""):
    """
    This function returns the voice language as defined in the policy
    authentication/voice_language. If no such policy is defined, the
    function returns the fallback message "en"

    :return: string
    """

    voice_language = "en"

    pol = get_client_policy(
        context["Client"],
        scope="authentication",
        realm=realm,
        user=user,
        action="voice_language",
    )

    voice_language = get_action_value(
        pol, scope="authentication", action="voice_language", default=""
    )

    log.debug(
        "[get_voice_language] got the voice_language = %s", voice_language
    )

    return voice_language


# --------------------------------------------------------------------------- --


@tokenclass_registry.class_entry("voice")
@tokenclass_registry.class_entry("linotp.tokens.voicetoken.VoicetokenClass")
class VoiceTokenClass(HmacTokenClass):
    """
    Voice token class implementation

    challenge is triggered and otp comes via phone call to the user
    """

    def __init__(self, token_obj):
        """
        Constructor for VoiceToken
        :param token_obj: instance of the orm db object
        :type token_obj:  orm object
        """

        HmacTokenClass.__init__(self, token_obj)

        self.setType("voice")

        self.hashlibStr = "sha256"

        # the token support only challenge based authentication

        self.mode = ["challenge"]

    @classmethod
    def getClassType(cls):
        """
        getClassType - return the token type shortname

        :return: 'voice'
        """
        return "voice"

    @classmethod
    def getClassPrefix(cls):
        # OATH standard compliant prefix: XXYY XX= vendor, YY - token type
        return "KIVO"

    # ---------------------------------------------------------------------- --

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

        log.debug(
            "[getClassInfo] begin. Get class render info for section: "
            "key %r, ret %r ",
            key,
            ret,
        )

        _ = context["translate"]

        res = {
            "type": "voice",
            "title": "Voice Token",
            "description": "A voice token.",
            "init": {
                "page": {
                    "html": "voicetoken/voicetoken.mako",
                    "scope": "enroll",
                },
                "title": {
                    "html": "voicetoken/voicetoken.mako",
                    "scope": "enroll.title",
                },
            },
            "config": {
                "title": {
                    "html": "voicetoken/voicetoken.mako",
                    "scope": "config.title",
                },
                "page": {
                    "html": "voicetoken/voicetoken.mako",
                    "scope": "config",
                },
            },
            "policy": {
                "authentication": {
                    "voice_language": {
                        "type": "str",
                        "desc": _(
                            "Define the language which should be used"
                            "to render the voice message."
                        ),
                    },
                    "voice_message": {
                        "type": "str",
                        "desc": _(
                            "Define the message which will be send"
                            "to the voice service for the phone"
                            "call."
                        ),
                    },
                    "voice_dynamic_mobile_number": {
                        "type": "bool",
                        "desc": _(
                            "If set, a new mobile number will be "
                            "retrieved from the user info instead "
                            "of the token"
                        ),
                    },
                }
            },
        }

        if key and key in res:
            ret = res.get(key)
        else:
            if ret == "all":
                ret = res

        log.debug("Returned the configuration section: ret %r ", ret)

        return ret

    # ---------------------------------------------------------------------- --

    def update(self, param, reset_fail_count=True):
        """
        token initialization with user parameters

        :param param: dict of initialization parameters
        :param reset_fail_count : boolean if the fail count should be reset

        :return: nothing
        """

        # ------------------------------------------------------------------ --

        # set the required phone / mobile number

        if "phone" not in param:
            raise ParameterError("Missing parameter: 'phone'")

        self.set_phone(param["phone"])

        # ------------------------------------------------------------------ --

        # lower layer should generate the token seed and
        # use the sha256 for the hmac operations

        param["genkey"] = 1
        param["hashlib"] = "sha256"

        # ------------------------------------------------------------------ --

        # call update method of parent class

        HmacTokenClass.update(self, param, reset_fail_count)

    # --------------------------------------------------------------------------- --

    def is_challenge_response(
        self, passw, user, options=None, challenges=None
    ):
        """
        check if the request contains the result of a challenge

        :param passw: password, which might be pin or pin+otp
        :param user: the requesting user
        :param options: dictionary of additional request parameters
        :param challenges: Not used in this method #TODO
        :return: returns true or false
        """

        if "state" in options or "transactionid" in options:
            return True

        # LEGACY: some client applications can not process transaction ids.
        # to support them, we provide a workaround heuristic with pin+otp
        # during the verification that

        (policy_type, pin, otp_val) = split_pin_otp(
            self, passw, user=user, options=options
        )

        if policy_type >= 0 and len(otp_val) == self.getOtpLen():
            return check_pin(self, pin, user=user, options=options)

        return False

    def is_challenge_request(self, passw, user, options=None):
        """
        check if the request would start a challenge

        - default: if the passw contains only the pin, this request would
                   trigger a challenge

        - in this place as well the policy for a token is checked

        :param passw: password, which might be pin or pin+otp
        :param options: dictionary of additional request parameters

        :return: returns true or false
        """

        return check_pin(self, passw, user=user, options=options)

    # ---------------------------------------------------------------------- --

    def initChallenge(self, transaction_id, challenges=None, options=None):
        """
        initialize the challenge

        :param transaction_id: the id of the new challenge
        :param challenges: the challenges list.
        :param options: the request parameters

        :return: tuple of
                success - bool
                trans_id - the best transaction id for this request context
                message - which is shown to the user
                attributes - further info (dict) shown to the user
        """

        success = True
        trans_id = transaction_id
        message = "challenge init ok"
        attributes = {}

        now = datetime.datetime.now()
        blocking_time = int(getFromConfig("VoiceBlockingTimeout", 60))

        # reuse challenge
        for challenge in challenges:

            if not challenge.is_open():
                continue

            # TODO: clarify, if blocking should be supported?

            start = challenge.get("timestamp")
            expiry = start + datetime.timedelta(seconds=blocking_time)

            # check if there is already a challenge underway
            if now <= expiry:
                trans_id = challenge.getTransactionId()
                message = "voice call with otp already submitted"
                success = False

                attributes = {
                    "info": "challenge already submitted",
                    "state": trans_id,
                }
                break

        return success, trans_id, message, attributes

    def createChallenge(self, transaction_id, options=None):
        """
        create a challenge which is submitted to the user

        Create a random counter and return it to the challenge dict,
        as well to the submit method which creates an otp for the phone
        call based on this counter.

        :param transaction_id: the id of this challenge
        :param options: the request context parameters / data
        :return: tuple of (bool, message and data)
                 bool, whether submit was successful
                 message is submitted to the user
                 data is preserved in the challenge
                 attributes - additional attributes, which are added in to the
                              challenge dict (in the method which calls this
                              method)
        """

        # use a random number as counter which will be stored in the
        # challenge context to verify the otp.
        random_int = self._get_rand_int(length=8)

        # send calculated otp to user via voice provider
        otp_value = self._calc_otp(random_int)

        success, info = self._submit_to_provider(otp_value)

        options["state"] = transaction_id

        if success is True:
            message = "voice call triggered"
        else:
            attributes = {"state": ""}
            message = "triggering voice call failed"
            if info:
                message = info

        # prepare parameter to return
        data = {"counter": str(random_int)}
        # add state to attributes which will be set to a challenges dict
        # after this method. Radius will send the transactionID in the
        # state parameter, so this is for radius compatibility
        attributes = {"state": transaction_id}

        return success, message, data, attributes

    # Todo: move into a more reasonable place (hsm_object?)
    @staticmethod
    def _get_rand_int(length=8):
        """
        Create random integer based on hsm objects random method.

        :param length: length in bytes
        :return: random number with length of len bytes
        """
        hsm_obj = context.get("hsm", {}).get("obj")
        random_bytes = hsm_obj.random(len=length)
        return int(binascii.hexlify(random_bytes), 16)

    # --------------------------------------------------------------------------- --

    def checkResponse4Challenge(
        self, user, passw, options=None, challenges=None
    ):
        """
        verify the response of a previous challenge

        :param user:     requesting user
        :param passw:    to be checked pass (pin+otp)
        :param options:  an additional argument, which could be token
                         specific
        :param challenges: list of challenges, where each challenge is
                           described as dict
        :return: tuple containing a) otp counter and b) the list of matching
                 challenges: (a,b)

        do the standard check for the response of the challenge +
        change the tokeninfo data of the last challenge
        """

        if len(passw) != self.getOtpLen():
            _pin_pass, otp_val = self.splitPinPass(passw)
        else:
            otp_val = passw

        for challenge in challenges:

            otp_input_data = int(challenge.get("data").get("counter"))

            challenge_otp = self._calc_otp(otp_input_data)

            if challenge_otp == otp_val:

                return 1, [challenge]

        return -1, []

    def get_mobile_number(self, user=None):
        """
        get the mobile number
            - from the token info or
            - if the policy allowes it, from the user info
        """

        if not user:
            return self.get_phone()

        pol = get_client_policy(
            context["Client"],
            scope="authentication",
            user=user,
            action="voice_dynamic_mobile_number",
        )

        if not pol:
            return self.get_phone()

        get_dynamic = get_action_value(
            pol,
            scope="authentication",
            action="voice_dynamic_mobile_number",
            default=False,
        )

        if not get_dynamic:
            return self.get_phone()

        user_detail = getUserDetail(user)
        return user_detail.get("mobile", self.get_phone())

    def _submit_to_provider(self, otp_value):
        """
        submit the voice message - former method name was checkPin

        :param otp_value: One time password to transfer to voice provider
        :return: Tuple of success and result message
        """

        owner = get_token_owner(self)

        message = get_voice_message(owner, owner.realm)
        language = get_voice_language(owner, owner.realm)

        voice_provider = loadProviderFromPolicy(
            provider_type="voice", realm=owner.realm, user=owner
        )

        success, result = voice_provider.submitVoiceMessage(
            calleeNumber=self.get_mobile_number(owner),
            messageTemplate=message,
            otp=otp_value,
            locale=language,
        )

        return success, result

    def getOtp(self, curTime=None):
        """
        :raises NotImplementedError
        """
        raise NotImplemented("method getOtp is not implemented for VoiceToken")

    def _calc_otp(self, input_data):
        """
        Calculates an otp by using an hmac algorithm with seed and
        input_data

        :param input_data: data used in hmac

        :return: otp value
        """

        # get otp length from stored token in database
        try:
            otp_length = int(self.token.LinOtpOtpLen)
        except ValueError as value_error_ex:
            log.error(
                "[getOTP]: Could not convert otplen - value error " "%r",
                value_error_ex,
            )
            raise value_error_ex

        # get otp for data using secret object and hotp algorithm
        secret_object = self._get_secret_object()
        hmac_otp_obj = HmacOtp(
            secret_object,
            input_data,
            otp_length,
            self.getHashlib(self.hashlibStr),
        )
        otp_value = hmac_otp_obj.generate(inc_counter=False)

        return otp_value

    def checkOtp(self, otp_value, counter, window, options=None):
        """
        checkOtp - validate the token otp against a given otpvalue

        :param otp_value: the to be verified otpvalue
        :type otp_value:  string

        :param counter: the counter state, that should be verified
        :type counter: int

        :param window: the counter +window, which should be checked
        :type window: int

        :param options: the dict, which could contain token specific info
        :type options: dict

        :return: the counter state or -1
        """

        success = -1

        # TODO
        # as we don not rely on the token counter, we have to iterate through
        # all challenges and extract the random counter for verification.

        if otp_value == self._calc_otp(counter):
            success = 1

        if success >= 0:
            msg = "otp verification was successful!"
        else:
            msg = "otp verification failed!"

        log.debug(msg)

        return success

    # in the voice token we use the generic TokenInfo
    # to store the phone number
    def set_phone(self, phone):
        """
        setter for the phone number

        :param phone: phone number
        :type phone:  string
        """
        self.addToTokenInfo("phone", phone)

    # todo as @property
    def get_phone(self):
        """
        getter for the phone number

        :return:  phone number
        :rtype:  string
        """

        return self.getFromTokenInfo("phone")

    def getInitDetail(self, params, user=None):
        """
        Returns additional details upon initialisation of the token
        """

        response_detail = {"serial": self.getSerial()}
        return response_detail


# eof #

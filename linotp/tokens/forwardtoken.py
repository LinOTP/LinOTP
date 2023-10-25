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
"""This file file contains the Forward token class"""

import logging

from flask_babel import gettext as _

from linotp.lib.auth.validate import check_pin, split_pin_otp
from linotp.lib.context import request_context as context
from linotp.lib.policy import getPolicy
from linotp.lib.token import get_token_owner, getTokenRealms
from linotp.tokens import tokenclass_registry
from linotp.tokens.base import TokenClass

log = logging.getLogger(__name__)

###############################################


def do_forward_failcounter(token):
    """
    this function checks the for the policy

        scope=authentication,
        action=forwardtoken:no_failcounter_forwarding

    defining if the target token failcounter should be incremented / reseted

    :param serial: the token serial number, which allows to derive the
                   realm(s) and owner from
    :return: boolean
    """
    boolean = True

    owner = get_token_owner(token)
    if owner and owner.realm:
        realms = [owner.realm]
    else:
        realms = getTokenRealms(token.getSerial())

    if not realms:
        realms = ["*"]

    for realm in realms:
        params = {
            "scope": "authentication",
            "realm": realm,
            "action": "forwardtoken:no_failcounter_forwarding",
        }

        if owner and owner.login:
            params["user"] = owner.login

        pol = getPolicy(params)

        if pol:
            boolean = False
            break

    return boolean


@tokenclass_registry.class_entry("forward")
@tokenclass_registry.class_entry(
    "linotp.tokens.forwardtoken.ForwardTokenClass"
)
class ForwardTokenClass(TokenClass):
    """
    The Forward token forwards an authentication request to another token.
    specified by a serial number. The PIN is only checked local.

    Using the Forward token you can assign one physical token to many
    different users.
    """

    def __init__(self, aToken):
        """
        constructor - create a token class object with it's db token binding

        :param aToken: the db bound token
        """
        TokenClass.__init__(self, aToken)
        self.setType("forward")

        self.forwardSerial = None
        self.mode = ["authenticate", "challenge"]

        self.targetToken = None
        self.target_otp_count = -1

    @classmethod
    def getClassType(cls):
        """
        return the class type identifier
        """
        return "forward"

    @classmethod
    def getClassPrefix(cls):
        """
        return the token type prefix
        """
        return "LSFW"

    @classmethod
    def getClassInfo(cls, key=None, ret="all"):
        """
        getClassInfo - returns a subtree of the token definition

        :param key: subsection identifier
        :param ret: default return value, if nothing is found
        :return: subsection if key exists or user defined

        """

        res = {
            "type": "forward",
            "title": "Forward Token",
            "description": (
                "Forward token to forward the"
                " otp authentication request to another token"
            ),
            "init": {
                "page": {
                    "html": "forwardtoken.mako",
                    "scope": "enroll",
                },
                "title": {
                    "html": "forwardtoken.mako",
                    "scope": "enroll.title",
                },
            },
            "selfservice": {},
            "policy": {
                "authentication": {
                    "forwardtoken:no_failcounter_forwarding": {
                        "type": "bool",
                        "desc": _(
                            "Specify if the target token fail counter"
                            " should be incremented / resets or not"
                        ),
                    },
                },
            },  # end of policy
        }

        if key is not None and key in res:
            ret = res.get(key)
        else:
            if ret == "all":
                ret = res

        return ret

    # setter and getter to dynamically query the offline support of the
    # target token

    @property
    def supports_offline_mode(self):
        """getter - to check if the target token supports offline support"""
        forwardSerial = self.getFromTokenInfo("forward.serial") or ""
        targetToken = self._getTargetToken(forwardSerial)
        return targetToken.supports_offline_mode

    @supports_offline_mode.setter
    def supports_offline_mode(self, value):
        """setter - if there is a getter, a setter must be implemented"""
        return

    def update(self, param):
        """
        second phase of the init process - updates token specific parameters

        :param param: the request parameters
        :return: - nothing -
        """

        self.forwardSerial = param["forward.serial"]

        # get the otplen of the target token
        targetToken = self._getTargetToken(self.forwardSerial)

        TokenClass.update(self, param)

        self.setOtpLen(targetToken.getOtpLen())
        self.addToTokenInfo("forward.serial", self.forwardSerial)

        return

    def authenticate(self, passw, user, options=None):
        """
        do the authentication on base of password / otp and serial and
        options, the request parameters.

        :param passw: the password / otp
        :param user: the requesting user
        :param options: the additional request parameters

        :return: tupple of (success, otp_count - 0 or -1, reply)

        """

        otp_count = -1
        reply = None

        # we do a local pin check
        _res, pin, otpval = split_pin_otp(self, passw, user, options=options)

        res = check_pin(self, pin, user, options)
        if res is False:
            return res, otp_count, reply

        res, otp_count, reply = self.do_request(otpval, user=user)
        return res, otp_count, reply

    def is_challenge_request(self, passw, user, options=None):
        """
        This method checks, if this is a request, that triggers a challenge.
        The pin is checked locally only

        :param passw: password, which might be pin or pin+otp
        :param user: The user from the authentication request
        :param options: dictionary of additional request parameters

        :return: true or false
        """

        request_is_valid = False

        pin_match = check_pin(self, passw, user=user, options=options)
        if pin_match is True:
            request_is_valid = True

        return request_is_valid

    def createChallenge(self, transactionid, options=None):
        """
        create a challenge if the target token does support this
        """
        forwardSerial = self.getFromTokenInfo("forward.serial")
        targetToken = self._getTargetToken(forwardSerial)

        if "challenge" in targetToken.mode:

            # create the challenge for the target token

            (success, message, data, attributes) = targetToken.createChallenge(
                transactionid, options
            )

            # extend the challenge response (via the attributes) to contain
            # information about the forwarded token
            if attributes is None:
                attributes = {}
            attributes.update(self._get_target_info())

            return success, message, data, attributes

        return (False, "", "", None)

    def _get_target_info(self):
        """small helper to build response detail of the target token"""
        forwardSerial = self.getFromTokenInfo("forward.serial")
        targetToken = self._getTargetToken(forwardSerial)

        prefix = "linotp_forward_"
        return {
            prefix + "tokenserial": forwardSerial,
            prefix + "tokendescription": targetToken.getDescription(),
            prefix + "tokentype": targetToken.getType(),
        }

    def check_challenge_response(self, challenges, user, passw, options=None):
        """
        reply the challenges of the target token

        we are a proxy for the challenge handling:
        - we have to inform the target token that it has to deal with the
          challenges of the forward token and
        - on the reply, we have to replace the target token lists with
          ourself
        only the matching challenges are derived from the target token but
        with the option above should be our ones :)

        """
        forwardSerial = self.getFromTokenInfo("forward.serial")
        targetToken = self._getTargetToken(forwardSerial)
        options["forwarded"] = self.getSerial()

        result = targetToken.check_challenge_response(
            challenges, user, passw, options
        )
        if len(targetToken.valid_token) > 0:
            self.valid_token.append(self)
        if len(targetToken.challenge_token) > 0:
            self.challenge_token.append(self)
        if len(targetToken.pin_matching_token) > 0:
            self.pin_matching_token.append(self)
        if len(targetToken.invalid_token) > 0:
            self.invalid_token.append(self)

        self.matching_challenges = targetToken.matching_challenges
        return result

    def do_request(self, passw, transactionid=None, user=None):
        """
        run the http request against the forward host

        :param passw: the password which should be checked on the forward host
        :param transactionid: provided,  if this is a challenge response
        :param user: the requesting user - used if no forward serial or forward
                     user is provided

        :return: Tuple of (success, otp_count= -1 or 0, reply=forward response)
        """

        forwardSerial = self.getFromTokenInfo("forward.serial") or ""

        log.debug(
            "checking OTP len:%r  for target serial: %r",
            len(passw),
            forwardSerial,
        )

        targetToken = self._getTargetToken(forwardSerial)

        counter = targetToken.getOtpCount()
        window = targetToken.getOtpCountWindow()

        # the push token expects passw to be a dict with accept or reject
        if targetToken.type == "push" and not isinstance(passw, dict):
            return (False, self.target_otp_count, None)

        self.target_otp_count = targetToken.checkOtp(passw, counter, window)
        res = self.target_otp_count >= 0

        return (res, self.target_otp_count, None)

    def _getTargetToken(self, forwardSerial):
        """
        helper - to get the target token
        """
        if self.targetToken:
            return self.targetToken

        from linotp.lib.token import get_tokens

        tokens = get_tokens(serial=forwardSerial)

        if not tokens:
            raise Exception(
                "no target token with serial %r found" % forwardSerial
            )

        self.targetToken = tokens[0]
        return self.targetToken

    def checkResponse4Challenge(
        self, user, passw, options=None, challenges=None
    ):
        """
        This method verifies if the given ``passw`` matches any
        existing ``challenge`` of the token.

        It then returns the new otp_counter of the token and the
        list of the matching challenges.

        In case of success the otp_counter needs to be >= 0.
        The matching_challenges is passed to the method
        :py:meth:`~linotp.tokens.base.TokenClass.challenge_janitor`
        to clean up challenges.

        :param user: the requesting user
        :param passw: the password (pin+otp)
        :param options:  additional arguments from the request, which could
                         be token specific
        :param challenges: A sorted list of valid challenges for this token.
        :return: tuple of (otpcounter and the list of matching challenges)

        """
        if not challenges:
            return -1, []

        otp_counter = -1
        matching_challenges = []

        for challenge in challenges:
            res, _otp_counter, _reply = self.do_request(passw, user=user)
            # everything is ok, we mark the challenge as a matching one
            if res is True and _otp_counter >= 0:
                matching_challenges.append(challenge)

                # ensure that a positive otp_counter is preserved
                otp_counter = _otp_counter

        return otp_counter, matching_challenges

    def getOfflineInfo(self):
        """interface the offline capability of the target token"""

        forwardSerial = self.getFromTokenInfo("forward.serial") or ""
        targetToken = self._getTargetToken(forwardSerial)

        offline_info = targetToken.getOfflineInfo() or {}
        offline_info.update(self._get_target_info())
        return offline_info

    def statusValidationSuccess(self):
        """
        with this hook we
        * increment the target token otp count to prevent replay and
        * optionally reset the target token failcounter
        """
        forwardSerial = self.getFromTokenInfo("forward.serial") or ""
        targetToken = self._getTargetToken(forwardSerial)

        # we have to increment the target token otp counter here, as none
        # else is involved, using the preserved matching otp counter
        targetToken.incOtpCounter(self.target_otp_count)

        if not do_forward_failcounter(self):
            return

        targetToken.reset()

    def statusValidationFail(self):
        """
        with this hook we
        * increment the target token otp count to prevent replay and
        * optionally increment the target fail count
        """

        if not do_forward_failcounter(self):
            return

        forwardSerial = self.getFromTokenInfo("forward.serial") or ""
        targetToken = self._getTargetToken(forwardSerial)
        targetToken.incOtpFailCounter()


# eof ########################################################################

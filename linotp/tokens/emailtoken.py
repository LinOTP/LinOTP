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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""
This file contains the e-mail token implementation:
              - EmailTokenClass   (HOTP)
"""
import datetime
import logging

from flask_babel import gettext as _

from linotp.lib.auth.validate import check_pin, split_pin_otp
from linotp.lib.challenges import Challenges
from linotp.lib.config import getFromConfig
from linotp.lib.context import request_context as context
from linotp.lib.HMAC import HmacOtp
from linotp.lib.policy import get_client_policy
from linotp.lib.policy.action import get_action_value
from linotp.lib.token import get_token_owner
from linotp.lib.user import getUserDetail
from linotp.provider import loadProviderFromPolicy
from linotp.provider.emailprovider import DEFAULT_MESSAGE
from linotp.tokens import tokenclass_registry
from linotp.tokens.hmactoken import HmacTokenClass

optional = True
required = False

LOG = logging.getLogger(__name__)


def is_email_editable(user=""):
    """
    this function checks the policy scope=selfservice, action=edit_email
    This is a int policy, while the '0' is a deny
    """

    realm = user.realm
    login = user.login

    policies = get_client_policy(
        client=context["Client"],
        scope="selfservice",
        action="edit_email",
        realm=realm,
        user=login,
    )

    edit_email = get_action_value(
        policies, scope="selfservice", action="edit_email", default=1
    )

    if edit_email == 0:
        return False

    return True


@tokenclass_registry.class_entry("email")
@tokenclass_registry.class_entry("linotp.tokens.emailtoken.EmailTokenClass")
class EmailTokenClass(HmacTokenClass):
    """
    E-mail token (similar to SMS token)
    """

    EMAIL_ADDRESS_KEY = "email_address"
    DEFAULT_EMAIL_PROVIDER = "linotp.provider.emailprovider.SMTPEmailProvider"
    DEFAULT_EMAIL_BLOCKING_TIMEOUT = 120

    def __init__(self, aToken):
        HmacTokenClass.__init__(self, aToken)
        self.setType("email")
        self.hKeyRequired = False

        # we support various hashlib methods, but only on create
        # which is effectively set in the update
        self.hashlibStr = getFromConfig("hotp.hashlib", "sha1")
        self.mode = ["challenge"]

    @property
    def _email_address(self):
        return self.getFromTokenInfo(self.EMAIL_ADDRESS_KEY)

    @_email_address.setter
    def _email_address(self, value):
        self.addToTokenInfo(self.EMAIL_ADDRESS_KEY, value)

    @classmethod
    def getClassType(cls):
        return "email"

    @classmethod
    def getClassPrefix(cls):
        return "LSEM"

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
        LOG.debug(
            "[getClassInfo] begin. Get class render info for section: "
            "key %r, ret %r " % (key, ret)
        )

        res = {
            "type": "email",
            "title": "E-mail Token",
            "description": "An e-mail token.",
            "init": {
                "page": {
                    "html": "emailtoken.mako",
                    "scope": "enroll",
                },
                "title": {
                    "html": "emailtoken.mako",
                    "scope": "enroll.title",
                },
            },
            "config": {
                "title": {
                    "html": "emailtoken.mako",
                    "scope": "config.title",
                },
                "page": {
                    "html": "emailtoken.mako",
                    "scope": "config",
                },
            },
            "selfservice": {
                "enroll": {
                    "page": {
                        "html": "emailtoken.mako",
                        "scope": "selfservice.enroll",
                    },
                    "title": {
                        "html": "emailtoken.mako",
                        "scope": "selfservice.title.enroll",
                    },
                },
            },
            "policy": {
                "selfservice": {
                    "edit_email": {
                        "type": "int",
                        "value": [0, 1],
                        "desc": _(
                            "define if the user should be allowed"
                            " to define the email address"
                        ),
                    }
                },
                "authentication": {
                    "emailtext": {
                        "type": "str",
                        "desc": _(
                            "The text that will be send via email "
                            "for an email token. Use <otp> "
                            "and <serial> as parameters."
                        ),
                    },
                    "emailsubject": {
                        "type": "str",
                        "desc": _(
                            "The subject that will be send via email "
                            "for an email token. Use <otp> "
                            "and <serial> as parameters."
                        ),
                    },
                    "dynamic_email_address": {
                        "type": "bool",
                        "desc": _(
                            "if set, a new email address will be "
                            "retrieved from the user info instead "
                            "of the token"
                        ),
                    },
                },
            },
        }

        # do we need to define the lost token policies here...
        # [comment copied from sms token]
        if key is not None and key in res:
            ret = res.get(key)
        else:
            if ret == "all":
                ret = res
        LOG.debug(
            "[getClassInfo] end. Returned the configuration section:"
            " ret %r " % ret
        )
        return ret

    def update(self, param, reset_failcount=True):
        """
        update - process initialization parameters

        :param param: dict of initialization parameters
        :type param: dict

        :return: nothing

        """
        LOG.debug(
            "[update] begin. adjust the token class with: param %r", param
        )

        # specific - e-mail
        self._email_address = param[self.EMAIL_ADDRESS_KEY]

        # in scope selfservice - check if edit_email is allowed
        # if not allowed to edit, check if the email is the same
        # as from the user data
        if param.get("::scope::", {}).get("selfservice", False):
            user = param["::scope::"]["user"]
            if not is_email_editable(user):
                u_info = getUserDetail(user)
                u_email = u_info.get("email", None)
                if u_email.strip() != self._email_address.strip():
                    raise Exception(
                        _("User is not allowed to set email address")
                    )

        # in case of the e-mail token, only the server must know the otpkey
        # thus if none is provided, we let create one (in the TokenClass)
        if "genkey" not in param and "otpkey" not in param:
            param["genkey"] = 1

        HmacTokenClass.update(self, param, reset_failcount)

        LOG.debug("[update] end. all token parameters are set.")
        return

    def _getNextOtp(self):
        """
        access the nex valid otp

        :return: otpval
        :rtype: string
        """
        LOG.debug("[getNextOtp] begin. starting to look for the next otp")

        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError as ex:
            LOG.error("[getNextOtp] ValueError %r", ex)
            raise Exception(ex)

        secObj = self._get_secret_object()
        counter = self.token.getOtpCounter()

        hmac2otp = HmacOtp(secObj, counter, otplen)
        nextotp = hmac2otp.generate(counter + 1)

        LOG.debug(
            "[getNextOtp] end. got the next otp value: nextOtp %r", nextotp
        )
        return nextotp

    def initChallenge(self, transactionid, challenges=None, options=None):
        """
        initialize the challenge -
        This method checks if the creation of a new challenge (identified by
        transactionid) should proceed or if an old challenge should be used
        instead.

        :param transactionid: the id of the new challenge
        :param options: the request parameters

        :return: tuple of
                success - bool
                transactionid_to_use - the best transaction id for this
                                       request context
                message - which is shown to the user
                attributes - further info (dict) shown to the user
        """
        success = True
        transactionid_to_use = transactionid
        message = "challenge init ok"
        attributes = {}

        now = datetime.datetime.now()
        blocking_time = int(
            getFromConfig(
                "EmailBlockingTimeout", self.DEFAULT_EMAIL_BLOCKING_TIMEOUT
            )
        )

        for challenge in challenges:

            # only care about open challenges
            if not challenge.is_open():
                continue

            challenge_timestamp = challenge.get("timestamp")
            block_timeout = challenge_timestamp + datetime.timedelta(
                seconds=blocking_time
            )
            # check if there is a challenge that is blocking
            # the creation of new challenges
            if now <= block_timeout:
                transactionid_to_use = challenge.getTransactionId()
                message = "e-mail with otp already submitted"
                success = False
                attributes = {
                    "info": "challenge already submitted",
                    "state": transactionid_to_use,
                }
                break

        return success, transactionid_to_use, message, attributes

    def createChallenge(self, transactionid, options=None):
        """
        create a challenge, which is submitted to the user

        :param transactionid: the id of this challenge
        :param options: the request context parameters / data
        :return: tuple of (bool, message, data and attributes)
                 bool, if submit was successful
                 message is status-info submitted to the user
                 data is preserved in the challenge
                 attributes - additional attributes, which are displayed in the
                    output
        :rtype: bool, string, dict, dict
        :raises: Exceptions will not be catched therefore any exception will be passed
        to the upper calling method
        """

        attributes = {}
        counter = self.getOtpCount() + 1
        data = {"counter_value": "%s" % counter}

        try:
            success, status_message = self._sendEmail()
            if success:
                attributes = {"state": transactionid}
                prompt_message = self.getChallengePrompt(
                    default=status_message
                )
                return success, prompt_message, data, attributes
            return False, status_message, data, {}

        finally:
            self.incOtpCounter(counter, reset=False)

    def _get_email_address(self, user=None):
        """
        get the email address
            - from the token info or
            - if the policy allowes it, from the user info
        """

        if not user:
            return self._email_address

        pol = get_client_policy(
            context["Client"],
            scope="authentication",
            user=user,
            action="dynamic_email_address",
        )

        if not pol:
            return self._email_address

        get_dynamic = get_action_value(
            pol,
            scope="authentication",
            action="dynamic_email_address",
            default="",
        )

        if not get_dynamic:
            return self._email_address

        user_detail = getUserDetail(user)
        return user_detail.get("email", self._email_address)

    def _getEmailMessage(self, user=""):
        """
        Could be used to implement some more complex logic similar to the
        SMS token where the SMS text is read from a policy.

        :return: The message that is sent to the user. It should contain
            at least the placeholder <otp>
        :rtype: string
        """
        message = DEFAULT_MESSAGE

        if not user:
            return message

        realm = user.realm
        login = user.login

        policies = get_client_policy(
            context["Client"],
            scope="authentication",
            realm=realm,
            user=login,
            action="emailtext",
        )

        message = get_action_value(
            policies,
            scope="authentication",
            action="emailtext",
            default=message,
        )

        return message

    def _getEmailSubject(self, user=""):
        """
        Could be used to implement some more complex logic similar to the
        SMS token where the SMS text is read from a policy.

        :return: The message that is sent to the user. It should contain
            at least the placeholder <otp>
        :rtype: string
        """
        subject = ""

        if not user:
            return subject

        realm = user.realm
        login = user.login

        policies = get_client_policy(
            context["Client"],
            scope="authentication",
            realm=realm,
            user=login,
            action="emailsubject",
        )

        subject = get_action_value(
            policies,
            scope="authentication",
            action="emailsubject",
            default=subject,
        )

        return subject

    def _sendEmail(self):
        """
        Prepares the e-mail by gathering all relevant information and
        then sends it out.

        :return: A tuple of success and status_message
        :rtype: bool, string
        """

        otp = self._getNextOtp()
        owner = get_token_owner(self)

        email_address = self._get_email_address(owner)
        if not email_address:
            raise Exception("No e-mail address was defined for this token.")

        message = self._getEmailMessage(user=owner)
        subject = self._getEmailSubject(user=owner)

        replacements = {}
        replacements["otp"] = otp
        replacements["serial"] = self.getSerial()

        # ------------------------------------------------------------------ --

        # add user detail to replacements, so we are aware of surename++

        if owner and owner.login:
            user_detail = owner.getUserInfo()
            if "cryptpass" in user_detail:
                del user_detail["cryptpass"]

            replacements.update(user_detail)

        # ------------------------------------------------------------------ --

        try:

            email_provider = loadProviderFromPolicy(
                provider_type="email", user=owner
            )

            status, status_message = email_provider.submitMessage(
                email_address,
                subject=subject,
                message=message,
                replacements=replacements,
            )

        except Exception as exx:
            LOG.error("Failed to submit EMail: %r", exx)
            raise

        return status, status_message

    def is_challenge_response(
        self, passw, user, options=None, challenges=None
    ):
        """
        Checks if the request is a challenge response.

        With the e-mail token every request has to be either a challenge
        request or a challenge response.

        Normally the client is unable to generate OTP values for this token
        himself (because the seed is generated on the server and not published)
        and has to wait to get it by e-mail. Therefore he either makes a
        challenge-request (triggering the e-mail) or he makes a challenge-
        response (sending the OTP value he received).

        :return: Is this a challenge response?
        :rtype: bool
        """
        challenge_response = False
        if options and ("state" in options or "transactionid" in options):
            challenge_response = True
        elif not self.is_challenge_request(passw, user, options):
            # If it is not a request then it is a response
            challenge_response = True

        return challenge_response

    def checkResponse4Challenge(
        self, user, passw, options=None, challenges=None
    ):
        """
        verify the response of a previous challenge

        There are two possible cases:

        1) The 'transaction_id' (also know as 'state', which has the same
           value) is available in options
        2) No 'transaction_id'

        In the first case we can safely assume that the passw only contains
        the OTP (no pin). In the second case passw will contain both and we
        split to get the OTP.

        :param user:     the requesting user
        :param passw:    the to be checked pass (pin+otp)
        :param options:  options an additional argument, which could be token
                          specific
        :param challenges: the list of challenges, where each challenge is
                            described as dict
        :return: tuple of (otpcounter and the list of matching challenges)

        """
        if not challenges:
            return -1, []

        transaction_id = options and options.get(
            "transactionid", options.get("state", None)
        )

        if transaction_id:
            otp = passw
            # if the transaction_id is set we can assume that we have only
            # received a single challenge with that transaction_id thanks to
            # linotp.lib.validate.ValidateToken.get_challenges()
            assert len(challenges) == 1
        else:
            # If no transaction_id is set the request came through the WebUI
            # and we have to check all challenges
            split_status, pin, otp = split_pin_otp(self, passw, user, options)
            if split_status < 0:
                raise Exception("Could not split passw")
            if not check_pin(self, pin, user, options):
                return -1, []

        window = self.getOtpCountWindow()

        otp_counter = -1
        matching_challenges = []

        for challenge in challenges:
            challenge_data = challenge.getData()
            stored_counter = int(challenge_data.get("counter_value", -1))
            _otp_counter = self.checkOtp(otp, stored_counter, window, options)

            if _otp_counter > 0 and _otp_counter == stored_counter:
                matching_challenges.append(challenge)

                # ensure that a positive otp_counter is preserved
                otp_counter = _otp_counter

        return otp_counter, matching_challenges

    def authenticate(self, passw, user, options=None):
        """
        The e-mail token only supports challenge response mode therefore when
        a 'normal' authenticate' request arrives we return false.

        :return: pin_match, otp_counter, reply
        :rtype: bool, int, string
        """
        pin_match = False
        otp_counter = -1
        reply = None
        return pin_match, otp_counter, reply

    def getInitDetail(self, params, user=None):
        """
        to complete the token normalisation, the response of the initialiastion
        should be build by the token specific method, the getInitDetails
        """
        response_detail = {}

        info = self.getInfo()
        response_detail["serial"] = self.getSerial()

        return response_detail

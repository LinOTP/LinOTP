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

"""This file containes the dynamic sms token implementation:
          - SMSTokenClass (sms)

the SMS Token is an challenge - response token, by the means, that there is
a first request, which triggers the challenge (=sending of sms message)
and a second request, which refers to the initial request by the
transactionid and verifies the otp value:

/validate/check_s

with params
 :param serial: the token serialnumber [required]
 :param pass: the token pin or
              if the token belongs to an user, the user pin/password
              (s. otppin policy) [required]
:param data: the message, that will contain the otp value [optional]
             * In the message, the strings <otp>, <serial> and
               <transactionid> will be replaced
             * if no data is provided, the smstext - policy value will be
               evaluated. Fallback is the message "<otp>"
:param message: alternative name for the data parameter

:return: json result wit tansaction an message, that will be displayed to
         the user

            {
                "detail": {
                    "transactionid": "172682842808",
                    "message": "sms submitted",
                    "state": "172682842808"
                },
                "version": "LinOTP 2.7.2.1",
                "jsonrpc": "2.0",
                "result": {
                    "status": true,
                    "value": false
                },
                "id": 0

            }

for the validation of the sms request now the controller method

/validate/check_t

could be used with the parameters

:param pass: received otp value
:param transactionid: the transactionid, which referes, that the pin
                      has been verified and checked

alternativly the controller method

/validate/check_s

could be used as well, by providing the combination of the pin+otp
in the pass parameter:

:param serial: serial number of the token
:param pass: the password consisting of fixed part and the otp part

:return: json response

{
    "version": "LinOTP 2.7.2.1",
    "jsonrpc": "2.0",
    "result": {
        "status": true,
        "value": true
    },
    "id": 0
}


"""

import datetime
import logging
import time

from flask_babel import gettext as _

from linotp.lib.auth.validate import check_otp, check_pin, split_pin_otp
from linotp.lib.config import getFromConfig
from linotp.lib.context import request_context as context
from linotp.lib.error import ParameterError
from linotp.lib.HMAC import HmacOtp
from linotp.lib.policy import (
    get_auth_AutoSMSPolicy,
    get_client_policy,
    getPolicy,
    trigger_sms,
)
from linotp.lib.policy.action import get_action_value
from linotp.lib.resources import AllResourcesUnavailable, ResourceScheduler
from linotp.lib.token import get_token_owner
from linotp.lib.user import get_user_from_options, getUserDetail
from linotp.provider import (
    ProviderNotAvailable,
    get_provider_from_policy,
    loadProvider,
)
from linotp.tokens import tokenclass_registry
from linotp.tokens.hmactoken import HmacTokenClass

log = logging.getLogger(__name__)

try:
    from linotp.provider.smsprovider import getSMSProviderClass  # noqa: F401

    SMSPROVIDER_IMPORTED = True
except ImportError as exx:
    log.warning("Failed to import SMSProvider %s", exx)
    SMSPROVIDER_IMPORTED = False

keylen = {
    "sha1": 20,
    "sha256": 32,
    "sha512": 64,
}


##################################################################
def get_auth_smstext(user="", realm=""):
    """
    this function checks the policy scope=authentication, action=smstext
    This is a string policy
    The function returns the tuple (bool, string),
        bool: If a policy is defined
        string: the string to use
    """
    pol = get_client_policy(
        context["Client"],
        scope="authentication",
        realm=realm,
        user=user,
        action="smstext",
    )

    smstext = get_action_value(
        pol, scope="authentication", action="smstext", default="<otp>"
    )

    log.debug("[get_auth_smstext] got the smstext = %s", smstext)

    return (smstext != "<otp>"), smstext


def enforce_smstext(user="", realm=""):
    """
    this function checks the boolean policy
                            scope=authentication,
                            action=enforce_smstext

    The function returns true if the smstext should be used instead of the
    challenge data
    :return: bool
    """
    pol = get_client_policy(
        context["Client"],
        scope="authentication",
        realm=realm,
        user=user,
        action="enforce_smstext",
    )

    enforce_smstext = get_action_value(
        pol, scope="authentication", action="enforce_smstext", default=False
    )
    log.debug("got enforce_smstext = %r", enforce_smstext)

    return enforce_smstext


def is_phone_editable(user=""):
    """
    this function checks the policy scope=selfservice, action=edit_sms
    This is a int policy, while the '0' is a deny
    """
    # the default string is the OTP value
    _ret = True
    realm = user.realm
    login = user.login

    policies = getPolicy(
        {
            "scope": "selfservice",
            "realm": realm,
            "action": "edit_sms",
            "user": login,
        }
    )

    edit_sms = get_action_value(
        policies, scope="selfservice", action="edit_sms", default=1
    )

    return edit_sms != 0


@tokenclass_registry.class_entry("sms")
@tokenclass_registry.class_entry("linotp.tokens.smstoken.SmsTokenClass")
class SmsTokenClass(HmacTokenClass):
    """
    implementation of the sms token class
    """

    def __init__(self, aToken):
        HmacTokenClass.__init__(self, aToken)
        self.setType("sms")
        self.hKeyRequired = False

        # we support various hashlib methods, but only on create
        # which is effectively set in the update
        self.hashlibStr = getFromConfig("hotp.hashlib", "sha1")
        self.mode = ["challenge"]

    @classmethod
    def getClassType(cls):
        """
        return the generic token class identifier
        """
        return "sms"

    @classmethod
    def getClassPrefix(cls):
        return "LSSM"

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
            "type": "sms",
            "title": _("SMS Token"),
            "description": _("sms challenge-response token - hmac event based"),
            "init": {
                "title": {
                    "html": "smstoken.mako",
                    "scope": "enroll.title",
                },
                "page": {
                    "html": "smstoken.mako",
                    "scope": "enroll",
                },
            },
            "config": {
                "title": {
                    "html": "smstoken.mako",
                    "scope": "config.title",
                },
                "page": {
                    "html": "smstoken.mako",
                    "scope": "config",
                },
            },
            "selfservice": {
                "enroll": {
                    "title": {
                        "html": "smstoken.mako",
                        "scope": "selfservice.title.enroll",
                    },
                    "page": {
                        "html": "smstoken.mako",
                        "scope": "selfservice.enroll",
                    },
                },
            },
            "policy": {
                "selfservice": {
                    "edit_sms": {
                        "type": "int",
                        "value": [0, 1],
                        "desc": _(
                            "define if the user should be allowed to define the sms"
                        ),
                    }
                },
                "authentication": {
                    "sms_dynamic_mobile_number": {
                        "type": "bool",
                        "desc": _(
                            "if set, a new mobile number will be "
                            "retrieved from the user info instead "
                            "of the token"
                        ),
                    },
                },
            },
        }

        if key and key in res:
            ret = res.get(key)
        elif ret == "all":
            ret = res

        return ret

    def update(self, param, reset_failcount=True):
        """
        update - process initialization parameters

        :param param: dict of initialization parameters
        :type param: dict

        :return: nothing

        """

        # specific - phone
        try:
            phone = param["phone"]
        except KeyError as exx:
            msg = "Missing parameter: 'phone'"
            raise ParameterError(msg) from exx

        # in scope selfservice - check if edit_sms is allowed
        # if not allowed to edit, check if the phone is the same
        # as from the user data
        if param.get("::scope::", {}).get("selfservice", False):
            user = param["::scope::"]["user"]
            if not is_phone_editable(user):
                u_info = getUserDetail(user)
                u_phone = u_info.get("mobile", u_info.get("phone", None))
                if u_phone != phone:
                    raise Exception(_("User is not allowed to set phone number"))

        self.setPhone(phone)

        # in case of the sms token, only the server must know the otpkey
        # thus if none is provided, we let create one (in the TokenClass)
        if "genkey" not in param and "otpkey" not in param:
            param["genkey"] = 1

        HmacTokenClass.update(self, param, reset_failcount)

    def is_challenge_response(self, passw, user, options=None, challenges=None):
        """
        check, if the request contains the result of a challenge

        :param passw: password, which might be pin or pin+otp
        :param user: the requesting user
        :param options: dictionary of additional request parameters

        :return: returns true or false
        """

        if "state" in options or "transactionid" in options:
            return True

        # it as well might be a challenge response,
        # if the passw is longer than the pin
        (res, pin, otpval) = split_pin_otp(self, passw, user=user, options=options)
        if res >= 0:
            otp_counter = check_otp(self, otpval, options=options)
            if otp_counter >= 1:
                pin_match = check_pin(self, pin, user=user, options=options)
                if not pin_match:
                    return False
            if otp_counter >= 0:
                return True

        return False

    # ## challenge interfaces starts here
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

        request_is_valid = False
        # do we need to call the
        # (res, pin, otpval) = split_pin_otp(self, passw, user, options=options)
        # if policy to send sms on emtpy pin is set, return true
        realms = self.token.getRealmNames()
        if trigger_sms(realms):  # noqa: SIM102
            if "check_s" in options.get("scope", {}) and "challenge" in options:
                request_is_valid = True
                return request_is_valid

        # if its a challenge, the passw contains only the pin
        pin_match = check_pin(self, passw, user=user, options=options)
        if pin_match is True:
            request_is_valid = True

        return request_is_valid

    #
    # !!! this function is to be called in the sms controller !!!
    #
    def submitChallenge(self, options=None):
        """
        submit the sms message - former method name was checkPin

        :param options: the request options context

        :return: tuple of success and message
        """

        res = 0

        fallback_realm = (self.getRealms() or [None])[0]
        login, realm = get_user_from_options(
            options,
            fallback_user=get_token_owner(self),
            fallback_realm=fallback_realm,
        )

        message = options.get("challenge", "<otp>")
        result = _("sending sms failed")

        # it is configurable, if sms should be triggered by a valid pin
        send_by_PIN = getFromConfig("sms.sendByPin") or True

        # if the token is not active or there is no pin triggered sending, we
        # leave
        if not (self.isActive() is True and send_by_PIN is True):
            return res, result

        counter = self.getOtpCount()
        log.debug("[submitChallenge] counter=%r", counter)

        # At this point we MUST NOT bail out in case of an
        # Gateway error, since checkPIN is successful, as the bail
        # out would cancel the checking of the other tokens
        try:
            sms_ret = False
            new_message = None

            sms_ret, new_message = get_auth_smstext(user=login, realm=realm)
            if sms_ret:
                message = new_message

            # ---------------------------------------------------------- --

            # if there is a data or message part in the request, it might
            # overrule the given smstext

            if "data" in options or "message" in options:
                # if there is an enforce policy
                # we do not allow the owerwrite

                enforce = enforce_smstext(user=login, realm=realm)

                if not enforce:
                    message = options.get("data", options.get("message", "<otp>"))

            # ---------------------------------------------------------- --

            # fallback if no message is defined

            if not message:
                message = "<otp>"

            # ---------------------------------------------------------- --

            # submit the sms message

            transactionid = options.get("transactionid", None)
            res, result = self.sendSMS(message=message, transactionid=transactionid)

            self.info["info"] = f"SMS sent: {res!r}"
            log.debug("SMS sent: %s", result)

            return res, result

        except Exception as exx:
            # The PIN was correct, but the SMS could not be sent.
            self.info["info"] = str(exx)
            info = f"The SMS could not be sent: {exx!r}"
            log.warning("[submitChallenge] %s", info)
            return False, info

        finally:
            # we increment the otp in any case, independend if sending
            # of the sms was sucsessful
            self.incOtpCounter(counter, reset=False)

    def initChallenge(self, transactionid, challenges=None, options=None):
        """
        initialize the challenge -
        in the linotp server a challenge object has been allocated and
        this method is called to confirm the need of a new challenge
        or if for the challenge request, there is an already outstanding
        challenge to which then could be referred (s. ticket #2986)

        :param transactionid: the id of the new challenge
        :param options: the request parameters

        :return: tuple of
                success - bool
                transid - the best transaction id for this request context
                message - which is shown to the user
                attributes - further info (dict) shown to the user
        """

        success = True
        transid = transactionid
        message = "challenge init ok"
        attributes = {}

        now = datetime.datetime.now()
        blocking_time = int(getFromConfig("SMSBlockingTimeout", 60))

        for challenge in challenges:
            if not challenge.is_open():
                continue
            start = challenge.get("timestamp")
            expiry = start + datetime.timedelta(seconds=blocking_time)
            # # check if there is already a challenge underway
            if now <= expiry:
                transid = challenge.getTransactionId()
                message = "sms with otp already submitted"
                success = False
                attributes = {
                    "info": "challenge already submitted",
                    "state": transid,
                }
                break

        return (success, transid, message, attributes)

    def createChallenge(self, transactionid, options=None):
        """
        create a challenge, which is submitted to the user

        :param transactionid: the id of this challenge
        :param options: the request context parameters / data
        :return: tuple of (bool, message and data)
                 bool, if submit was successful
                 message is submitted to the user
                 data is preserved in the challenge
                 attributes - additional attributes, which are displayed in the
                    output
        """
        if options is None:
            options = {}

        message = self.getChallengePrompt(default="sms submitted")

        attributes = {"state": transactionid}

        options["state"] = transactionid
        success, sms = self.submitChallenge(options=options)

        if success is True:
            self.setValidUntil()
        else:
            attributes = {"state": ""}
            message = "sending sms failed"

            if sms:
                message = sms

        # after submit set validity time in readable
        # datetime format in the storeing data
        timeScope = self.loadLinOtpSMSValidTime()
        expiryDate = datetime.datetime.now() + datetime.timedelta(seconds=timeScope)
        data = {"valid_until": f"{expiryDate}"}

        return (success, message, data, attributes)

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

        do the standard check for the response of the challenge +
        change the tokeninfo data of the last challenge
        """

        _tok = super()
        counter = self.getOtpCount()
        window = self.getOtpCountWindow()

        _now = datetime.datetime.now()
        _timeScope = self.loadLinOtpSMSValidTime()

        otp_val = passw

        # # fallback: do we have pin+otp ??
        (res, pin, otp) = split_pin_otp(self, passw, user=user, options=options)

        if res >= 0:
            res = check_pin(self, pin, user=user, options=options)
            if res is True:
                otp_val = otp

        if otp_val and not challenges:
            otp_count = self.checkOtp(otp_val, counter, window, options=options)
            return otp_count, []

        otp_count = -1
        matching = []

        for challenge in challenges:
            _otp_count = self.checkOtp(otp_val, counter, window, options=options)
            if _otp_count > 0:
                matching.append(challenge)

                # ensure that a positive otp_counter is preserved
                otp_count = _otp_count

        return (otp_count, matching)

    def checkOtp(self, anOtpVal, counter, window, options=None):
        """
        checkOtp - check the otpval of a token against a given counter
        in the + window range

        :param passw: the to be verified passw/pin
        :type passw: string

        :return: counter if found, -1 if not found
        :rtype: int
        """

        if not options:
            options = {}

        ret = HmacTokenClass.checkOtp(self, anOtpVal, counter, window)
        if ret != -1 and self.isValid() is False:
            ret = -1

        if ret >= 0 and get_auth_AutoSMSPolicy():
            user = None
            message = "<otp>"
            realms = self.getRealms()
            if realms:
                _sms_ret, message = get_auth_smstext(realm=realms[0])

            if "user" in options:
                user = options.get("user")
                if user:
                    _sms_ret, message = get_auth_smstext(realm=user.realm)
            realms = self.getRealms()

            if "data" in options or "message" in options:
                message = options.get("data", options.get("message", "<otp>"))

            try:
                _success, message = self.sendSMS(message=message)
            except Exception as exx:
                log.error(exx)
            finally:
                self.incOtpCounter(ret, reset=False)
        if ret >= 0:
            msg = "otp verification was successful!"
        else:
            msg = "otp verification failed!"
        log.debug(msg)
        return ret

    def getNextOtp(self):
        """
        access the nex validf otp

        :return: otpval
        :rtype: string
        """

        try:
            # ## TODO - replace tokenLen
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError as ex:
            log.error("[getNextOtp] ValueError %r", ex)
            raise ex

        secObj = self._get_secret_object()
        counter = self.token.getOtpCounter()

        hmac2otp = HmacOtp(secObj, counter, otplen)
        nextotp = hmac2otp.generate(counter + 1)

        return nextotp

    # in the SMS token we use the generic TokenInfo
    # to store the phone number
    def setPhone(self, phone):
        """
        setter for the phone number

        :param phone: phone number
        :type phone:  string

        :return: nothing
        """
        self.setSMSInfo("phone", phone)

    def setUntil(self, until):
        """
        This is the time the sent OTP value is valid/can be used.
                                                        (internal function)

        :param until: until time in unix time sec
        :type until:  int

        :return: nothing
        """

        self.setSMSInfo("until", until)

    def _getPhone(self):
        """
        getter for the phone number

        :return:  phone number
        :rtype:  string
        """

        (phone, _till) = self.getSMSInfo()
        return phone

    def get_mobile_number(self, user=None):
        """
        get the mobile number
            - from the token info or
            - if the policy allowes it, from the user info
        """

        if not user:
            return self._getPhone()

        pol = get_client_policy(
            context["Client"],
            scope="authentication",
            user=user,
            action="sms_dynamic_mobile_number",
        )

        get_dynamic = get_action_value(
            pol,
            scope="authentication",
            action="sms_dynamic_mobile_number",
            default=False,
        )

        if not get_dynamic:
            return self._getPhone()

        user_detail = getUserDetail(user)
        return user_detail.get("mobile", self._getPhone())

    def getUntil(self):
        """
        getter for the until time definition

        :return:  until time definition of unix time sec
        :rtype:  int
        """

        (_phone, until) = self.getSMSInfo()

        # # suport for direct verification
        if until == 0:
            timeScope = self.loadLinOtpSMSValidTime()
            until = int(time.time()) + timeScope
        return until

    def setSMSInfo(self, key, value):
        """
        generic method to set the sms infos like phone or validity in the
        tokeninfo (json) entry

        :param key: name of the hash key
        :type key:  string
        :param value: value of the entry
        :type value: any

        :return: nothing
        """
        self.addToTokenInfo(key, value)

    def getSMSInfo(self):
        """
        retrieve the phone number and the validity scope

        :return: tuple of phone number and validity time in unix lifetime sec
        """

        info = self.getTokenInfo()
        phone = info.get("phone", "")
        until = info.get("until", 0)

        return (phone, until)

    # we take the countWindow.column to store the time
    #  in int format (cut off the .2 from the time() )

    def setValidUntil(self):
        """
        adjust the timeframe of validity

        :return: nothing
        """
        timeScope = self.loadLinOtpSMSValidTime()
        dueDate = int(time.time()) + timeScope
        self.setUntil(dueDate)
        # self.token.setCountWindow(dueDate)

        return dueDate

    def isValid(self):
        """
        check if sms challenge is still valid

        :return: True or False
        :rtype: boolean
        """
        ret = False
        dueDate = self.getUntil()
        now = int(time.time())
        if dueDate >= now:
            ret = True
        if ret is True:
            _msg = "the sms challenge is still valid"
        else:
            _msg = "the sms challenge is no more valid"
        return ret

    def sendSMS(self, message=None, transactionid=None):
        """
        send sms

        :param message: the sms submit message - could contain placeholders
         like <otp> or <serial>
        :type message: string

        :return: submitted message
        :rtype: string

        """

        success = None

        if not message:
            message = "<otp>"

        if not SMSPROVIDER_IMPORTED:
            msg = (
                "The SMSProvider could not be imported. Maybe you "
                "didn't install the package (Debian "
                "linotp-smsprovider or PyPI SMSProvider)"
            )
            raise Exception(msg)

        # we require the token owner to get the phone number and the provider
        owner = get_token_owner(self)

        phone = self.get_mobile_number(owner)

        otp = self.getNextOtp()
        serial = self.getSerial()

        if "<otp>" not in message:
            log.error("Message unconfigured: prepending <otp> to message")
            if isinstance(message, str):
                message = f"<otp> {message}"
            else:
                message = f"<otp> {message!r}"

        message = message.replace("<otp>", otp)
        message = message.replace("<serial>", serial)

        if transactionid:
            message = message.replace("<transactionid>", transactionid)

        log.debug("[sendSMS] sending SMS to phone number %s ", phone)

        realm = None
        realms = self.getRealms()
        if realms:
            realm = realms[0]

        # we require the token owner to get the phone number and the provider
        owner = get_token_owner(self)
        if not owner or not owner.login:
            log.warning("[sendSMS] Missing required token owner")

        # ------------------------------------------------------------------ --

        # load providers for the user

        providers = get_provider_from_policy("sms", realm=realm, user=owner)

        # remember if at least one provider could be accessed
        available = False

        res_scheduler = ResourceScheduler(tries=1, uri_list=providers)
        for provider_name in next(res_scheduler):
            sms_provider = loadProvider("sms", provider_name=provider_name)

            if not sms_provider:
                log.error("Unable to load provider %r", provider_name)
                log.error("Please verify your provider configuration!")
                msg = "unable to load provider"
                raise Exception(msg)

            try:
                success = sms_provider.submitMessage(phone, message)
                available = True

                log.info("SMS successfully submitted by provider: %r", provider_name)
                break

            except ProviderNotAvailable:
                log.warning("Provider not available %r", provider_name)
                res_scheduler.block(provider_name, delay=30)

        if not available:
            log.error("all providers are not available %r", providers)
            msg = f"unable to connect to any SMSProvider {providers!r}"
            raise AllResourcesUnavailable(msg)

        log.info("[sendSMS] message submitted")

        # # after submit set validity time
        self.setValidUntil()

        return success, message

    def loadLinOtpSMSValidTime(self):
        """
        get the challenge time is in the specified range

        :return: the defined validation timeout in seconds
        :rtype:  int
        """
        try:
            timeout = int(getFromConfig("SMSProviderTimeout", 5 * 60))
        except Exception as ex:
            log.warning("SMSProviderTimeout: value error %r - reset to 5*60", ex)
            timeout = 5 * 60

        return timeout

    def getInitDetail(self, params, user=None):
        """
        to complete the token normalisation, the response of the initialiastion
        should be build by the token specific method, the getInitDetails
        """
        response_detail = {}

        response_detail["serial"] = self.getSerial()

        return response_detail


# eof #

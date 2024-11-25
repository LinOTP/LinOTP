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
"""validation processing logic"""

import binascii
import copy
import json
import logging
from datetime import datetime
from hashlib import sha256

from flask import g

from linotp.flap import config as env
from linotp.lib.auth.finishtokens import FinishTokens
from linotp.lib.challenges import Challenges
from linotp.lib.context import request_context as context
from linotp.lib.error import ParameterError
from linotp.lib.policy import (
    delete_on_authentication_exceed,
    disable_on_authentication_exceed,
    get_auth_forward,
    get_auth_forward_on_no_token,
    get_auth_passOnNoToken,
    get_auth_passthru,
    get_pin_policies,
    supports_offline,
)
from linotp.lib.policy.forward import ForwardServerPolicy
from linotp.lib.realm import getDefaultRealm
from linotp.lib.resolver import getResolverObject
from linotp.lib.token import (
    TokenHandler,
    add_last_accessed_info,
    add_last_verified_info,
    get_token_owner,
    get_tokens,
)
from linotp.lib.user import User, getUserId, getUserInfo
from linotp.lib.util import modhex_decode
from linotp.tokens import tokenclass_registry

log = logging.getLogger(__name__)


def _get_otppin_mode(pin_policies):
    """
    helper to get the otppin operational mode from policies
    """

    if 0 in pin_policies or "token_pin" in pin_policies:
        return 0

    elif 1 in pin_policies or "password" in pin_policies:
        return 1

    elif 2 in pin_policies or "only_otp" in pin_policies:
        return 2

    elif 3 in pin_policies or "ignore_pin" in pin_policies:
        return 3

    return 0


def check_pin(token, passw, user=None, options=None):
    """
    check the provided pin w.r.t. the policy definition

    :param passw: the to be checked pass
    :param user: if otppin==1, this is the user, which resolver should
                 be checked
    :param options: the optional request parameters

    :return: boolean, if pin matched True
    """
    res = False

    otppin_mode = _get_otppin_mode(get_pin_policies(user))

    if otppin_mode == 1:
        # We check the Users Password as PIN
        log.debug("pin policy=1: checking the users password as pin")
        # this should not be the case
        if not options:
            options = {}

        selfservice_state = context.get("selfservice", {}).get("state", "")
        if selfservice_state in [
            "credentials_verified",
            "challenge_triggered",
        ]:
            return True

        if "pin_match" not in options:
            options["pin_match"] = {}

        hashed_passw = sha256(passw.encode("utf-8")).hexdigest()

        # if password already found, we can return result again
        if hashed_passw in options["pin_match"]:
            log.debug(
                "check if password already checked! %r ",
                options["pin_match"][hashed_passw],
            )
            return options["pin_match"][hashed_passw]

        # if a password already matched, this one will fail
        if "found" in options["pin_match"]:
            log.debug("check if password already found but its not this one!")
            return False

        if user is None or not user.login:
            log.info("fail for pin policy == 1 with user = None")
            res = False
        else:
            (uid, _resolver, resolver_class) = getUserId(user)
            resolver = getResolverObject(resolver_class)
            if resolver.checkPass(uid, passw):
                log.debug("Successfully authenticated user %r.", uid)
                res = True
            else:
                log.info("user %r failed to authenticate.", uid)

        # we register our result
        key = sha256(passw.encode("utf-8")).hexdigest()
        options["pin_match"][key] = res
        # and register the success, to shorten lookups after
        # already one positive was found
        if res:
            options["pin_match"]["found"] = True

        return res

    elif otppin_mode == 2:
        # NO PIN should be entered atall
        log.debug("[__checkToken] pin policy=2: checking no pin")
        return len(passw) == 0

    elif otppin_mode == 3:
        # ignore pin or password

        log.debug("[__checkToken] pin policy=3: ignoreing pin")

        if token.type in ["spass"]:
            return token.checkPin(passw, options=options)

        return True

    else:
        # old stuff: We check The fixed OTP PIN
        log.debug("[__checkToken] pin policy=0: checkin the PIN")
        return token.checkPin(passw, options=options)


def check_otp(token, otpval, options=None):
    """
    check the otp value

    :param token: the corresponding token
    :param otpval: the to be checked otp value
    :param options: the additional request parameters

    :return: result of the otp check, which is
            the matching otpcounter or -1 if not valid
    """

    counter = token.getOtpCount()
    window = token.getOtpCountWindow()

    # ---------------------------------------------------------------------- --

    res = token.checkOtp(otpval, counter, window, options=options)
    return res


def split_pin_otp(token, passw, user=None, options=None):
    """
    split the pin and the otp from the given password

    :param token: the corresponding token
    :param passw: the to be split password
    :param user: the token user
    :param options: currently not used, but might be forwarded to the
                    token.splitPinPass
    :return: tuple of (split status, pin and otpval)
    """

    otppin_mode = _get_otppin_mode(get_pin_policies(user))

    if otppin_mode == 0:
        # old stuff: We check The fixed OTP PIN
        log.debug("pin policy=0: checking the PIN")
        (pin, otp) = token.splitPinPass(passw)
        return 0, pin, otp

    elif otppin_mode == 1:
        log.debug("pin policy=1: checking the users password as pin")
        # split the passw into password and otp value
        (pin, otp) = token.splitPinPass(passw)
        return 1, pin, otp

    elif otppin_mode == 2:
        # NO PIN should be entered at all
        log.debug("pin policy=2: checking no pin")
        (pin, otp) = ("", passw)
        token.auth_info = {"auth_info": [("pin_length", 0), ("otp_length", len(passw))]}
        return 2, pin, otp

    elif otppin_mode == 3:
        # no pin should be checked
        log.debug("pin policy=3: ignoring the pin")
        (pin, otp) = token.splitPinPass(passw)

        return 3, pin, otp


class ValidationHandler(object):
    def check_by_transactionid(self, transid, passw, options=None):
        """
        check the passw against the open transaction

        :param transid: the transaction id
        :param passw: the pass parameter
        :param options: the additional optional parameters

        :return: tuple of boolean and detail dict
        """

        challenges = Challenges.lookup_challenges(transid=transid)
        serials = [challenge.tokenserial for challenge in challenges]

        if not serials:
            reply = {
                "value": False,
                "failure": "No challenge for transaction %r found" % transid,
            }
            return False, reply

        ok = False
        reply = {"value": False, "failcount": 0, "token_type": ""}

        token_type = options.get("token_type") if options else None

        for serial in serials:
            tokens = get_tokens(
                serial=serial, token_type=token_type, read_for_update=True
            )

            if not tokens and token_type:
                continue

            if not tokens and not token_type:
                raise Exception("tokenmismatch for token serial: %r" % serial)

            # there could be only one
            token = tokens[0]
            owner = get_token_owner(token)

            (ok, opt) = self.checkTokenList(tokens, passw, user=owner, options=options)
            if opt:
                reply.update(opt)

            reply.update(
                {
                    "value": ok,
                    "token_type": token.getType(),
                    "failcount": token.getFailCount(),
                    "serial": token.getSerial(),
                }
            )

            if ok:
                break

        return ok, reply

    def checkSerialPass(self, serial, passw, options=None, user=None):
        """
        This function checks the otp for a given serial

        :attention: the parameter user must be set, as the pin policy==1 will
                    verify the user pin
        """

        token_type = options.get("token_type", None)

        tokenList = get_tokens(
            None, serial, token_type=token_type, read_for_update=True
        )

        if passw is None:
            # other than zero or one token should not happen, as serial is
            # unique
            if len(tokenList) == 1:
                theToken = tokenList[0]
                tok = theToken.token
                realms = tok.getRealmNames()
                if realms is None or len(realms) == 0:
                    realm = getDefaultRealm()
                elif len(realms) > 0:
                    realm = realms[0]
                userInfo = getUserInfo(
                    tok.LinOtpUserid,
                    tok.LinOtpIdResolver,
                    tok.LinOtpIdResClass,
                )
                user = User(login=userInfo.get("username"), realm=realm)
                user.info = userInfo

                if theToken.is_challenge_request(passw, user, options=options):
                    (res, opt) = Challenges.create_challenge(theToken, options)
                    res = False
                else:
                    raise ParameterError("Missing parameter: pass", id=905)

            else:
                raise Exception(
                    "No token found: unable to create challenge for %s" % serial
                )

        else:
            (res, opt) = self.checkTokenList(
                tokenList, passw, user=user, options=options
            )

        return (res, opt)

    def do_request(self):
        return

    def check_status(
        self,
        transid=None,
        user=None,
        serial=None,
        password=None,
        use_offline=False,
    ):
        """
        check for open transactions - for polling support

        :param transid: the transaction id where we request the status from
        :param user: the token owner user
        :param serial: or the serial we are searching for
        :param password: the pin/password for authorization of the request
        :param use_offline: on success, the offline info is returned (applicable to token types that use `support_offline` policy)

        :return: tuple of success and detail dict
        """

        expired, challenges = Challenges.get_challenges(token=None, transid=transid)

        # remove all expired challenges
        if expired:
            Challenges.delete_challenges(None, expired)

        if not challenges:
            return False, None

        # there is only one challenge per transaction id
        # if not multiple challenges, where transaction id is the parent one
        transactions = {}
        for ch in challenges:
            # is the requester authorized
            challenge_serial = ch.getTokenSerial()
            if serial and challenge_serial != serial:
                continue

            tokens = get_tokens(serial=challenge_serial)
            if not tokens:
                continue

            # as one challenge belongs exactly to only one token,
            # we take this one as the token
            token = tokens[0]
            owner = get_token_owner(token)
            if user and user != owner:
                continue

            # we only check the user password / token pin if the user
            # paranmeter is given
            if user and owner:
                pin_match = check_pin(token, password, user=owner, options=None)
            else:
                pin_match = token.checkPin(password)

            if not pin_match:
                continue

            trans_dict = {
                "received_count": ch.received_count,
                "received_tan": ch.received_tan,
                "valid_tan": ch.valid_tan,
                "message": ch.getChallenge(),
                "status": ch.getStatus(),
            }

            # -------------------------------------------------------------- --

            # extend the check status with the accept or deny of a transaction

            challenge_session = ch.getSession()

            if challenge_session:
                challenge_session_dict = json.loads(challenge_session)

                if "accept" in challenge_session_dict:
                    trans_dict["accept"] = challenge_session_dict["accept"]

                if "reject" in challenge_session_dict:
                    trans_dict["reject"] = challenge_session_dict["reject"]

            # -------------------------------------------------------------- --

            token_dict = {"serial": token.getSerial(), "type": token.type}

            # 1. check if token supports offline at all
            supports_offline_at_all = token.supports_offline_mode

            # 2. check if policy allows to use offline authentication
            if user and user.login and user.realm:
                realms = [user.realm]
            else:
                realms = token.getRealms()

            offline_is_allowed = supports_offline(realms, token)

            if (
                not ch.is_open()
                and ch.valid_tan
                and supports_offline_at_all
                and use_offline
            ):
                if offline_is_allowed:
                    token_dict["offline_info"] = token.getOfflineInfo()
                else:
                    log.info(
                        f"Token {token.getSerial()} (type={token.type}) is not "
                        "allowed by support_offline policy in current realm"
                    )

            trans_dict["token"] = token_dict
            transactions[ch.transid] = trans_dict

        reply = {"transactions": transactions} if transactions else {}

        return len(reply) > 0, reply

    def checkUserPass(self, user, passw, options=None):
        """
        :param user: the to be identified user
        :param passw: the identification pass
        :param options: optional parameters, which are provided
                    to the token checkOTP / checkPass

        :return: tuple of True/False and optional information
        """

        # the upper layer will catch / at least should ;-)

        opt = None
        serial = None
        resolverClass = None
        uid = None
        user_exists = False

        if user:
            # the upper layer will catch / at least should
            try:
                (uid, _resolver, resolverClass) = getUserId(user, check_existance=True)
                user_exists = True
            except Exception as _exx:
                pass_on = context.get("Config").get("linotp.PassOnUserNotFound", False)
                if pass_on and pass_on.lower() == "true":
                    g.audit["action_detail"] = "authenticated by PassOnUserNotFound"
                    return (True, opt)
                else:
                    g.audit["action_detail"] = "User not found"
                    return (False, opt)

        # if we have an user, check if we forward the request to another server
        if user_exists and not get_auth_forward_on_no_token(user):
            servers = get_auth_forward(user)
            if servers:
                log.info(
                    "forwarding auth request for user {} to {}".format(user, servers)
                )
                res, opt = ForwardServerPolicy.do_request(
                    servers, env, user, passw, options
                )
                log.info(
                    "result of auth request for user {}: ({}, {})".format(
                        user, res, opt
                    )
                )
                g.audit["action_detail"] = "Forwarded, result {}".format(res)
                return res, opt
            else:
                log.info(
                    "NOT forwarding auth request for user {} (no servers)".format(user)
                )
                g.audit["action_detail"] = "Not forwarded (no servers)"
        else:
            log.info(
                "NOT forwarding auth request for user {} "
                "(get_auth_forward_on_no_token returned False)".format(user)
            )

        # ------------------------------------------------------------------ --

        th = TokenHandler()

        # ------------------------------------------------------------------ --

        # auto asignement with otp only if user has no active token

        auto_assign_otp_return = th.auto_assign_otp_only(
            otp=passw, user=user, options=options
        )

        if auto_assign_otp_return:
            return (True, None)

        # ------------------------------------------------------------------ --

        token_type = None
        if options:
            token_type = options.get("token_type", None)

        # ------------------------------------------------------------------ --

        # if there is a serial provided in the parameters, it overwrites the
        # token selection by user

        query_user = user
        if options and "serial" in options and options["serial"]:
            serial = options["serial"]
            query_user = None

        # ------------------------------------------------------------------ --

        tokenList = get_tokens(
            query_user, serial, token_type=token_type, read_for_update=True
        )

        if len(tokenList) == 0:
            g.audit["action_detail"] = "User has no tokens assigned"

            # here we check if we should to autoassign and try to do it
            auto_assign_return = th.auto_assignToken(passw, user)
            if auto_assign_return:
                # We can not check the token, as the OTP value is already used!
                # but we will auth the user....
                return (True, opt)

            auto_enroll_return, opt = th.auto_enrollToken(passw, user, options=options)
            if auto_enroll_return:
                # we always have to return a false, as
                # we have a challenge tiggered
                return (False, opt)

            pass_on = context.get("Config").get("linotp.PassOnUserNoToken", False)
            if pass_on and pass_on.lower() == "true":
                g.audit["action_detail"] = "authenticated by PassOnUserNoToken"
                return (True, opt)

            # Check if there is an authentication policy passthru

            if get_auth_passthru(user):
                log.debug(
                    "user %r has no token. Checking for passthru in realm %r",
                    user.login,
                    user.realm,
                )
                y = getResolverObject(resolverClass)
                g.audit["action_detail"] = "Authenticated against Resolver"
                if y.checkPass(uid, passw):
                    return (True, opt)

            # Check alternatively if there is an authentication
            # policy passOnNoToken
            elif get_auth_passOnNoToken(user):
                log.info("user %r has not token. PassOnNoToken set - authenticated!")
                g.audit["action_detail"] = "Authenticated by passOnNoToken policy"
                return (True, opt)

            # if we have an user, check if we forward the request to another
            # server
            elif get_auth_forward_on_no_token(user):
                servers = get_auth_forward(user)
                if servers:
                    log.info(
                        "forwarding auth request for user {} to {}".format(
                            user, servers
                        )
                    )
                    res, opt = ForwardServerPolicy.do_request(
                        servers, env, user, passw, options
                    )
                    log.info(
                        "result of auth request for user {}: ({}, {})".format(
                            user, res, opt
                        )
                    )
                    g.audit["action_detail"] = "Forwarded, result {}".format(res)
                    return res, opt
                else:
                    log.info(
                        "NOT forwarding auth request for user {} (no servers)".format(
                            user
                        )
                    )
                    g.audit["action_detail"] = "Not forwarded (no servers)"

            return False, opt

        if passw is None:
            raise ParameterError("Missing parameter:pass", id=905)

        (res, opt) = self.checkTokenList(tokenList, passw, user, options=options)

        return (res, opt)

    def checkTokenList(self, tokenList, passw, user=User(), options=None):
        """
        identify a matching token and test, if the token is valid, locked ..
        This function is called by checkSerialPass and checkUserPass to

        :param tokenList: list of identified tokens
        :param passw: the provided passw (mostly pin+otp)
        :param user: the identified use - as class object
        :param options: additional parameters, which are passed to the token

        :return: tuple of boolean and optional response
        """
        reply = None

        #  add the user to the options, so that every token could see the user
        if not options:
            options = {}

        options["user"] = user

        # if there has been one token in challenge mode, we only handle
        # challenges

        # if we got a validation against a sub_challenge, we extend this to
        # be a validation to all challenges of the transaction id
        check_options = copy.deepcopy(options)
        transid = check_options.get("state", check_options.get("transactionid", ""))
        if transid and "." in transid:
            transid = transid.split(".")[0]
            if "state" in check_options:
                check_options["state"] = transid
            if "transactionid" in check_options:
                check_options["transactionid"] = transid

        # -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --

        # transaction id optimization - part 1:
        #
        # if we have a transaction id, we check only those tokens
        # that belong to this transaction id:

        challenges = []
        # -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --

        audit_entry = {"action_detail": "no token found!"}

        challenge_tokens = []
        pin_matching_tokens = []
        invalid_tokens = []
        valid_tokens = []
        related_challenges = []

        # we have to preserve the result / reponse for token counters
        validation_results = {}

        for token in tokenList:
            audit_entry.update(
                {"serial": token.getSerial(), "token_type": token.getType()}
            )

            # preselect: the token must be in the same realm as the user
            if user is not None:
                t_realms = token.token.getRealmNames()
                u_realm = user.realm
                if t_realms and u_realm and u_realm.lower() not in t_realms:
                    audit_entry["action_detail"] = "Realm mismatch for token and user"

                    continue

            # check if the token is the list of supported tokens
            # if not skip to the next token in list
            typ = token.getType()
            if typ.lower() not in tokenclass_registry:
                log.error(
                    "token typ %r not found in tokenclasses: %r",
                    typ,
                    list(tokenclass_registry.keys()),
                )
                audit_entry["action_detail"] = "Unknown Token type"
                continue

            if not token.isActive():
                audit_entry["action_detail"] = "Token inactive"
                continue

            if token.getFailCount() >= token.getMaxFailCount():
                audit_entry["action_detail"] = "Failcounter exceeded"
                token.incOtpFailCounter()
                continue

            # ---------------------------------------------------------------------- --

            # check for restricted path usage

            path = context["Path"].strip("/").partition("/")[0]
            token_path = token.getFromTokenInfo("scope", {}).get("path", [])

            if token_path and path not in token_path:
                continue

            # -------------------------------------------------------------- --

            # token validity handling

            if token.is_not_yet_valid():
                audit_entry["action_detail"] = (
                    "Authentication validity period mismatch!"
                )
                token.incOtpFailCounter()
                continue

            if not token.is_valid():
                if token.has_exceeded_usage():
                    msg = "Authentication counter exceeded"
                elif token.has_exceeded_success():
                    msg = "Authentication sucess counter exceeded"
                elif token.is_expired():
                    msg = "Authentication validity period exceeded"
                else:
                    raise Exception("Validity check failed without reason")

                audit_entry["action_detail"] = msg
                token.incOtpFailCounter()

                # what should happen with exceeding tokens
                t_realms = (
                    token.token.getRealmNames()
                    if not user.login and not user.realm
                    else None
                )

                if disable_on_authentication_exceed(user, realms=t_realms):
                    token.enable(False)

                if delete_on_authentication_exceed(user, realms=t_realms):
                    token.deleteToken()

                continue

            # -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --

            # gather all open challenges for this token
            if transid:
                _expired, challenges = Challenges.get_challenges(
                    token=token, transid=transid, filter_open=True
                )

            else:
                # if there is no transaction id given we check all challenges
                # related to the given token

                _expired, challenges = Challenges.get_challenges(
                    token=token, filter_open=True, options=check_options
                )

            # -------------------------------------------------------------- --

            # finally we check the token

            try:
                (ret, reply) = token.check_token(
                    passw, user, options=check_options, challenges=challenges
                )

            except Exception as exx:
                # in case of a failure during checking token, we log the error
                # and continue with the next one
                log.error("checking token %r failed: %r", token, exx)
                ret = -1
                reply = "%r" % exx
                audit_entry["action_detail"] = "checking token %r failed: %r" % (
                    token,
                    exx,
                )

                audit_entry["info"] = audit_entry.get("info", "") + "%r" % exx

                continue
            finally:
                validation_results[token.getSerial()] = (ret, reply)

            (cToken, pToken, iToken, vToken) = token.get_verification_result()
            related_challenges.extend(token.related_challenges)

            challenge_tokens.extend(cToken)
            pin_matching_tokens.extend(pToken)
            invalid_tokens.extend(iToken)
            valid_tokens.extend(vToken)

        valid_tokens = list(set(valid_tokens))
        invalid_tokens = list(set(invalid_tokens))
        pin_matching_tokens = list(set(pin_matching_tokens))
        challenge_tokens = list(set(challenge_tokens))

        # end of token verification loop
        matching_challenges = [
            challenge
            for token in valid_tokens
            for challenge in token.matching_challenges
        ]
        matching_challenges = list(set(matching_challenges))

        # if there are related / sub challenges, we have to call their janitor
        Challenges.handle_related_challenge(matching_challenges)

        # now we finalize the token validation result
        fh = FinishTokens(
            valid_tokens,
            challenge_tokens,
            pin_matching_tokens,
            invalid_tokens,
            validation_results,
            user,
            options,
            audit_entry=audit_entry,
        )

        (res, reply) = fh.finish_checked_tokens()

        # ------------------------------------------------------------------ --

        # add to all tokens the last accessed time stamp

        add_last_accessed_info(
            set(valid_tokens + pin_matching_tokens + challenge_tokens + invalid_tokens)
        )

        # add time stamp to all valid tokens

        add_last_verified_info(valid_tokens)

        # ------------------------------------------------------------------ --

        # now we care for all involved tokens and their challenges

        for token in set(
            valid_tokens + pin_matching_tokens + challenge_tokens + invalid_tokens
        ):
            expired, _valid = Challenges.get_challenges(token)
            if expired:
                Challenges.delete_challenges(None, expired)

        log.debug(
            "Number of valid tokens found (validTokenNum): %d",
            len(valid_tokens),
        )

        return (res, reply)

    def checkYubikeyPass(self, passw):
        """
        Checks the password of a yubikey in Yubico mode (44,48), where
        the first 12 or 16 characters are the tokenid

        :param passw: The password that consist of the static yubikey prefix
                        and the otp
        :type passw: string

        :return: True/False and the User-Object of the token owner
        :rtype: dict
        """

        opt = None
        res = False

        # strip the yubico OTP and the PIN
        modhex_serial = passw[:-32][-16:]
        try:
            hex_serial = modhex_decode(modhex_serial)
            serialnum = "UBAM" + binascii.unhexlify(hex_serial).decode("utf-8")
        except TypeError as exx:
            log.error("Failed to convert serialnumber: %r", exx)
            return res, opt

        #  build list of possible yubikey tokens
        serials = [f"{serialnum}_{i}" for i in range(3)]
        serials.insert(0, serialnum)

        tokenList = [
            token
            for serial in serials
            for token in get_tokens(serial=serial, read_for_update=True)
        ]

        if not tokenList:
            g.audit["action_detail"] = "The serial %s could not be found!" % serialnum
            return res, opt

        # FIXME if the Token has set a PIN and the User does not want to enter
        # the PIN for authentication, we need to do something different here...
        #  and avoid PIN checking in __checkToken.
        #  We could pass an "option" to __checkToken.
        (res, opt) = self.checkTokenList(tokenList, passw)

        # Now we need to get the user
        if res is not False and "serial" in g.audit:
            serial = g.audit["serial"]
            if serial is not None:
                user = get_token_owner(tokenList[0])
                g.audit["user"] = user.login
                g.audit["realm"] = user.realm
                opt = {"user": user.login, "realm": user.realm}

        return res, opt


# eof###########################################################################

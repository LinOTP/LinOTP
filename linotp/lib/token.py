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
""" contains several token api functions"""

import binascii
import datetime
import json
import logging
import os
import string
from typing import List

from flask_babel import gettext as _
from sqlalchemy import and_, func, or_
from sqlalchemy.exc import ResourceClosedError

from flask import g

import linotp
import linotp.lib.policy
from linotp.lib.challenges import Challenges
from linotp.lib.config import getFromConfig
from linotp.lib.context import request_context as context
from linotp.lib.error import ParameterError, TokenAdminError
from linotp.lib.realm import createDBRealm, getRealmObject, realm2Objects
from linotp.lib.type_utils import DEFAULT_TIMEFORMAT, parse_duration
from linotp.lib.user import (
    User,
    get_authenticated_user,
    getUserId,
    getUserInfo,
    getUserRealms,
)
from linotp.lib.util import generate_password
from linotp.model import db
from linotp.model.realm import Realm
from linotp.model.token import Token, createToken
from linotp.model.tokenRealm import TokenRealm
from linotp.provider.notification import NotificationException, notify_user
from linotp.tokens import tokenclass_registry

log = logging.getLogger(__name__)

optional = True
required = False

ENCODING = "utf-8"


###############################################


class TokenHandler(object):
    def initToken(self, param, user, tokenrealm=None):
        """
        initToken - create a new token or update a token

        :param param: the list of provided parameters
                      in the list the serialnumber is required,
                      the token type default ist hmac
        :param user:  the token owner
        :param tokenrealm: the realms, to which the token belongs

        :return: tuple of success and token object
        """

        token = None

        # if we get a undefined tokenrealm , we create a list
        if tokenrealm is None:
            tokenrealm = []
        # if we get a tokenrealm as string, we make an array out of this
        elif isinstance(tokenrealm, str):
            tokenrealm = [tokenrealm]
        # if there is a realm as parameter, we assign the token to this realm
        if "realm" in param:
            # # and append our parameter realm
            tokenrealm.append(param.get("realm"))

        typ = param.get("type")
        if typ is None:
            typ = "hmac"

        serial = param.get("serial", None)
        if serial is None:
            prefix = param.get("prefix", None)
            serial = self.genSerial(typ, prefix)

        # if a token was initialized for a user, the param "realm" might
        # be contained. otherwise - without a user the param tokenrealm could
        # be contained.
        log.debug("Initializing token %r for user %r ", serial, user.login)

        #  create a list of the found db tokens - no token class objects
        toks = get_raw_tokens(None, serial)
        tokenNum = len(toks)

        if tokenNum == 0:  # create new a one token
            #  check if this token is in the list of available tokens
            if typ.lower() not in tokenclass_registry:
                log.error(
                    "Token type %r not found. Available types are: %r",
                    typ,
                    list(tokenclass_registry.keys()),
                )
                raise TokenAdminError(
                    "[initToken] failed: unknown token type %r" % typ,
                    id=1610,
                )
            token = createToken(serial)

        elif tokenNum == 1:  # update if already there
            token = toks[0]

            # prevent from changing the token type
            old_typ = token.LinOtpTokenType
            if old_typ.lower() != typ.lower():
                msg = (
                    "token %r already exist with type %r. Can not "
                    "initialize token with new type %r"
                    % (serial, old_typ, typ)
                )
                log.error("[initToken] %s", msg)
                raise TokenAdminError("initToken failed: %s" % msg)

            #  prevent update of an unsupported token type
            if typ.lower() not in tokenclass_registry:
                log.error(
                    "Token type %r not found. Available types are: %r",
                    typ,
                    list(tokenclass_registry.keys()),
                )
                raise TokenAdminError(
                    "[initToken] failed: unknown token type %r" % typ,
                    id=1610,
                )

        else:  # something wrong
            if tokenNum > 1:
                raise TokenAdminError(
                    "multiple tokens found - cannot init!", id=1101
                )
            else:
                raise TokenAdminError("cannot init! Unknown error!", id=1102)

        # get the RealmObjects of the user and the tokenrealms
        realms = getRealms4Token(user, tokenrealm)
        token.setRealms(realms)

        #  on behalf of the type, the class is created
        tokenObj = createTokenClassObject(token, typ)

        if tokenNum == 0:
            # if this token is a newly created one, we have to setup the
            # defaults, which lateron might be overwritten by the
            # tokenObj.update(params)
            tokenObj.setDefaults()

        tokenObj.update(param)

        if user is not None and user.login != "":
            tokenObj.setUser(user, report=True)

        try:
            token.storeToken()
        except Exception as exx:
            log.error("Could not create token")
            raise TokenAdminError("token create failed %r" % exx, id=1112)

        log.debug("Token object %r was created", tokenObj)
        return (True, tokenObj)

    def auto_enrollToken(self, passw, user, options=None):
        """
        This function is called to auto_enroll a token:
        - when the user has no token assigned and enters his password (without
          otppin=1 policy), a new email or sms token is created and will be
          assigned to the user. Finaly a challenge otp for this user will be
          created that he will receive by email or sms.

        :param passw: password of the user - to checked against
                      the user resolver
        :param user: user object of login name and realm
        :param options: optional parameters used during challenge creation
        :return: tuple of auth success and challenge output
        """

        # check if auto enrollment is configured
        try:
            auto, token_types = linotp.lib.policy.get_auto_enrollment(user)
        except Exception as exx:
            log.error("%r", exx)
            raise Exception("[auto_enrollToken] %r" % exx)

        if not auto:
            msg = "no auto_enrollToken configured"
            log.debug(msg)
            return False, None

        uid, res, resc = getUserId(user)
        u_info = getUserInfo(uid, res, resc)

        # enroll token for user
        desc = "auto enrolled for %s@%s" % (user.login, user.realm)
        token_init = {"genkey": 1, "description": desc[:80]}

        email = u_info.get("email", None)
        mobile = u_info.get("mobile", None)

        # check if token type is in defined set of types
        if not token_types:
            msg = (
                "auto_enrollment for user %s failed: unknown token type %r"
                % (user, token_types)
            )
            log.warning(msg)
            return False, {"error": msg}

        if not email and not mobile:
            msg = (
                "auto_enrollment for user %s failed: "
                "missing sms or email!" % user
            )
            log.warning(msg)
            return False, {"error": msg}

        # for sms token we require a valid phone number of the user
        if token_types == ["sms"]:
            if not mobile:
                msg = (
                    "auto_enrollment for user %s failed: missing "
                    "mobile number!" % user
                )
                log.warning(msg)
                return False, {"error": msg}

            token_init["type"] = "sms"
            token_init["phone"] = mobile

        # for email token we require a valid email address of the user
        elif token_types == ["email"]:
            if not email:
                msg = (
                    "auto_enrollment for user %s failed: missing email!" % user
                )
                log.warning(msg)
                return False, {"error": msg}

            token_init["type"] = "email"
            token_init["email_address"] = email

        # if email or sms, at least one of email or sms is required
        elif token_types == ["email", "sms"]:
            if email:
                token_init["type"] = "email"
                token_init["email_address"] = email
            else:
                token_init["type"] = "sms"
                token_init["phone"] = mobile

        # if sms or email, at least one of sms or email is required
        elif token_types == ["sms", "email"] or token_types == ["*"]:
            if mobile:
                token_init["type"] = "sms"
                token_init["phone"] = mobile
            else:
                token_init["type"] = "email"
                token_init["email_address"] = email

        authUser = get_authenticated_user(user.login, user.realm, passw)
        if authUser is None:
            msg = "User %r@%r failed to authenticate against userstore" % (
                user.login,
                user.realm,
            )
            log.error(msg)
            return False, {"error": msg}

        # if the passw is correct we use this as an initial pin
        # to prevent otp spoof from email or sms
        token_init["pin"] = passw

        (res, tokenObj) = self.initToken(token_init, user)
        if res is False:
            msg = (
                "Failed to create token for user %s@%s during"
                " autoenrollment" % (user.login, user.realm)
            )
            log.error(msg)
            return False, {"error": msg}

        initDetail = tokenObj.getInitDetail(token_init, user)

        # ------------------------------------------------------------------ --

        # auto enrollment notification:

        # in case of the autoenrollment notification, we can set a new pin
        # but only if the user received the enrollment notification
        # containing the pin message

        try:

            new_pin = linotp.lib.policy.createRandomPin(user, min_pin_length=6)

            message = (
                "A new ${tokentype} token (${serial}) "
                "with pin '${Pin}' "
                "for ${givenname} ${surname} has been enrolled."
            )
            info = {
                "message": message,
                "Subject": "New %s token enrolled" % tokenObj.type,
                "Pin": new_pin,
                "tokentype": tokenObj.type,
            }

            info.update(initDetail)

            notified = notify_user(user, "autoenrollment", info, required=True)

            if notified:
                tokenObj.setPin(new_pin)

        except NotificationException:
            log.error("Failed to autoenroll notify user!")

        # ------------------------------------------------------------------ --

        # now trigger a challenge so the user can login

        # we have to use a try except as challenge creation might raise
        # exception and we have to drop the created token

        try:
            # trigger challenge for user
            (_res, reply) = Challenges.create_challenge(
                tokenObj, options=options
            )
            if _res is not True:
                error = (
                    "failed to create challenge for user %s@%s during "
                    "autoenrollment" % (user.login, user.realm)
                )
                log.error(error)
                raise Exception(error)

        except Exception as exx:
            log.error("Failed to create challenge!")

            # we have to commit our token delete as the rollback
            # on exception does not :-(

            db.session.delete(tokenObj.token)
            db.session.commit()
            raise exx

        return (True, reply)

    def losttoken(self, serial, new_serial=None, password=None, param=None):
        """
        This is the workflow to handle a lost token

        :param serial: Token serial number
        :param new_serial: new serial number
        :param password: new password
        :param param: additional arguments for the password, email or sms token
            as dict

        :return: result dictionary
        """

        res = {}

        if param is None:
            param = {"type": "password"}

        owner = self.getTokenOwner(serial)
        log.info(
            "lost token for serial %r and owner %r@%r",
            serial,
            owner.login,
            owner.realm,
        )

        if owner.login == "" or owner.login is None:
            err = "You can only define a lost token for an assigned token."
            log.warning(err)
            raise Exception(err)

        client = context["Client"]

        if not new_serial:
            new_serial = "lost%s" % serial

        res["serial"] = new_serial
        init_params = {
            "type": "pw",
            "serial": new_serial,
            "description": "temporary replacement for %s" % serial,
        }

        if "type" in param:
            if param["type"] == "password":
                init_params["type"] = "pw"

            elif param["type"] == "email":
                email = param.get("email", owner.info.get("email", None))
                if email:
                    init_params["type"] = "email"
                    init_params["genkey"] = 1
                    init_params["email_address"] = email
                else:
                    log.warning(
                        "No email address found for %r. Falling back "
                        "to password token.",
                        owner.login,
                    )

            elif param["type"] == "sms":
                phone = param.get("mobile", owner.info.get("mobile", None))
                if phone:
                    init_params["type"] = "sms"
                    init_params["genkey"] = 1
                    init_params["phone"] = phone
                else:
                    log.warning(
                        "No mobile number found for %r. Falling back "
                        "to password token.",
                        owner.login,
                    )

        if init_params["type"] == "pw":

            pol = linotp.lib.policy.get_client_policy(
                client,
                scope="enrollment",
                action="lostTokenPWLen",
                realm=owner.realm,
                user=owner.login,
                userObj=owner,
            )

            pw_len = linotp.lib.policy.action.get_action_value(
                pol, scope="enrollment", action="lostTokenPWLen", default=10
            )

            pol = linotp.lib.policy.get_client_policy(
                client,
                scope="enrollment",
                action="lostTokenPWContents",
                realm=owner.realm,
                user=owner.login,
                userObj=owner,
            )

            contents = linotp.lib.policy.action.get_action_value(
                pol,
                scope="enrollment",
                action="lostTokenPWContents",
                default="",
            )

            character_pool = "%s%s%s" % (
                string.ascii_lowercase,
                string.ascii_uppercase,
                string.digits,
            )
            if contents != "":
                character_pool = ""
                if "c" in contents:
                    character_pool += string.ascii_lowercase
                if "C" in contents:
                    character_pool += string.ascii_uppercase
                if "n" in contents:
                    character_pool += string.digits
                if "s" in contents:
                    character_pool += "!#$%&()*+,-./:;<=>?@[]^_"

            if not password:
                password = generate_password(
                    size=pw_len, characters=character_pool
                )

            init_params["otpkey"] = password

        # now we got all info and can enroll the replacement token
        (ret, tokenObj) = self.initToken(
            param=init_params, user=User("", "", "")
        )

        res["init"] = ret
        if ret is True:
            # copy the assigned user
            res["user"] = self.copyTokenUser(serial, new_serial)

            # copy the pin, except for spass
            # (because the pin is the spass password, and the user lost it)
            if getTokenType(serial) not in ["spass"]:
                res["pin"] = self.copyTokenPin(serial, new_serial)

            # ------------------------------------------------------------- --

            # set the validity of the temporary token
            pol = linotp.lib.policy.get_client_policy(
                client,
                scope="enrollment",
                action="lostTokenValid",
                realm=owner.realm,
                user=owner.login,
                userObj=owner,
            )

            validity = linotp.lib.policy.action.get_action_value(
                pol, scope="enrollment", action="lostTokenValid", default=-1
            )

            end_date = _calculate_validity_end(validity)

            tokenObj.validity_period_end = end_date

            # ------------------------------------------------------------- --

            # fill results
            res["valid_to"] = "xxxx"
            if init_params["type"] == "pw":
                res["password"] = password
            elif init_params["type"] == "email":
                res["password"] = "Please check your emails"
            elif init_params["type"] == "sms":
                res["password"] = "Please check your phone"
            res["end_date"] = end_date

            # we need to return the token type, so we can modify the
            # response according
            res["token_typ"] = init_params["type"]

            # disable token
            res["disable"] = self.enableToken(False, User("", "", ""), serial)

        return res

    def isTokenOwner(self, serial, user):
        """
        verify that user is the token owner

        :param serial: the token serial
        :param user: the given user
        :return: boolean - True on success
        """

        # ----------------------------------------------------------------- --

        # handle the given user

        if not user:
            raise TokenAdminError("no user found %r" % user, id=1104)

        (userid, idResolver, idResolverClass) = getUserId(user)

        # special case for the sqlresolver with uid column defined as int
        if isinstance(userid, int):
            userid = "%d" % userid

        if not (userid and idResolver and idResolverClass):
            raise TokenAdminError("no user found %s" % user.login, id=1104)

        # ----------------------------------------------------------------- --

        # handle the token owner

        toks = get_tokens(None, serial)

        if len(toks) > 1:
            raise TokenAdminError("multiple tokens found!", id=1101)
        if len(toks) == 0:
            raise TokenAdminError("no token found!", id=1102)

        token = toks[0]

        (token_userid, _idResolver, token_idResolverClass) = token.getUser()

        # ----------------------------------------------------------------- --

        # compare the user with the owner

        if token_idResolverClass == idResolverClass and token_userid == userid:
            return True

        return False

    def hasOwner(self, serial):
        """
        returns true if the token is owned by any user

        :param serial: the token serial number
        :return: boolean - True if it has an owner
        """

        toks = get_tokens(None, serial)

        if len(toks) > 1:
            raise TokenAdminError("multiple tokens found!", id=1101)
        if len(toks) == 0:
            raise TokenAdminError("no token found!", id=1102)

        token = toks[0]

        (uuserid, uidResolver, uidResolverClass) = token.getUser()

        if uuserid and uidResolver and uidResolverClass:
            return True

        return False

    def getTokenOwner(self, serial):
        """
        returns the user object, to which the token is assigned.
        the token is idetified and retirved by it's serial number

        :param serial: serial number of the token
        :return: user object
        """
        token = None

        toks = get_tokens(None, serial)
        if len(toks) > 0:
            token = toks[0]

        user = get_token_owner(token)

        return user

    def check_serial(self, serial):
        """
        This checks, if a serial number is already contained.

        The function returns a tuple:
            (result, new_serial)

        If the serial is already contained a new, modified serial new_serial
        is returned.

        result: bool: True if the serial does not already exist.
        """
        # serial does not exist, yet
        result = True
        new_serial = serial

        i = 0
        while len(get_tokens(None, new_serial)) > 0:
            # as long as we find a token, modify the serial:
            i = i + 1
            result = False
            new_serial = "%s_%02i" % (serial, i)

        return (result, new_serial)

    def auto_assign_otp_only(self, otp, user, options=None):
        """
        This function is called to auto_assign a token, when the
        user enters an OTP value of an not assigned token.
        """
        if options is None:
            options = {}

        auto = linotp.lib.policy.get_autoassignment_without_pass(user)
        if not auto:
            log.debug("no autoassigment configured")
            return False

        # only auto assign if no token exists

        tokens = get_tokens(user)
        if len(tokens) > 0:
            log.debug(
                "No auto_assigment for user %r@%r. User already has"
                " some tokens.",
                user.login,
                user.realm,
            )
            return False

        token_src_realm = linotp.lib.policy.get_autoassignment_from_realm(user)

        if not token_src_realm:
            token_src_realm = user.realm

        # get all tokens of the users realm, which are not assigned
        token_type = options.get("token_type", None)

        # List of (token, pin) pairs
        matching_tokens = []

        tokens = self.getTokensOfType(
            typ=token_type, realm=token_src_realm, assigned="0"
        )
        for token in tokens:

            token_exists = token.check_otp_exist(
                otp=otp, window=token.getOtpCountWindow()
            )

            if token_exists >= 0:
                matching_tokens.append(token)

        if len(matching_tokens) != 1:
            log.warning(
                "[auto_assignToken] %d tokens with "
                "the given OTP value found.",
                len(matching_tokens),
            )
            return False

        token = matching_tokens[0]
        serial = token.getSerial()

        # if found, assign the found token to the user.login
        try:
            self.assignToken(serial, user, pin="")
            g.audit["serial"] = serial
            g.audit["info"] = "Token with otp auto assigned"
            g.audit["token_type"] = token.getType()
            return True
        except Exception as exx:
            log.error("Failed to assign token: %r", exx)
            return False

        return False

    def auto_assignToken(self, passw, user, _pin="", param=None):
        """
        This function is called to auto_assign a token, when the
        user enters an OTP value of an not assigned token.
        """
        ret = False
        auto = False

        if param is None:
            param = {}

        try:
            auto = linotp.lib.policy.get_autoassignment(user)
        except Exception as exx:
            log.error("[auto_assignToken] %r", exx)

        # check if autoassignment is configured
        if not auto:
            log.debug("[auto_assignToken] not autoassigment configured")
            return False

        # check if user has a token
        # TODO: this may dependend on a policy definition
        tokens = get_tokens(user, "")
        if len(tokens) > 0:
            log.debug(
                "[auto_assignToken] no auto_assigment for user %r@%r. "
                "User already has some tokens.",
                user.login,
                user.realm,
            )
            return False

        # List of (token, pin) pairs
        matching_pairs = []

        # get all tokens of the users realm, which are not assigned

        tokens = self.getTokensOfType(typ=None, realm=user.realm, assigned="0")
        for token in tokens:

            token_exists = -1
            from linotp.lib import policy

            if policy.autoassignment_forward(user) and token.type == "remote":
                ruser = User(user.login, user.realm)
                token_exists = token.check_otp_exist(
                    otp=passw,
                    window=token.getOtpCountWindow(),
                    user=ruser,
                    autoassign=True,
                )
                (pin, otp) = token.splitPinPass(passw)
            else:
                (pin, otp) = token.splitPinPass(passw)
                token_exists = token.check_otp_exist(
                    otp=otp, window=token.getOtpCountWindow()
                )

            if token_exists >= 0:
                matching_pairs.append((token, pin))

        if len(matching_pairs) != 1:
            log.warning(
                "[auto_assignToken] %d tokens with "
                "the given OTP value found.",
                len(matching_pairs),
            )
            return False

        token, pin = matching_pairs[0]
        serial = token.getSerial()

        authUser = get_authenticated_user(user.login, user.realm, pin)
        if authUser is None:
            log.error(
                "[auto_assignToken] User %r@%r failed to authenticate "
                "against userstore",
                user.login,
                user.realm,
            )
            return False

        # should the password of the autoassignement be used as pin??
        if True == linotp.lib.policy.ignore_autoassignment_pin(user):
            pin = None

        # if found, assign the found token to the user.login
        try:
            self.assignToken(serial, user, pin)
            g.audit["serial"] = serial
            g.audit["info"] = "Token auto assigned"
            g.audit["token_type"] = token.getType()
            ret = True
        except Exception as exx:
            log.error("[auto_assignToken] Failed to assign token: %r", exx)
            return False

        return ret

    def assignToken(self, serial, user, pin, param=None):
        """
        assignToken - used to assign and to unassign token
        """
        if param is None:
            param = {}

        toks = get_tokens(None, serial)
        # toks  = Session.query(Token).filter(
        #  Token.LinOtpTokenSerialnumber == serial)

        if len(toks) > 1:
            raise TokenAdminError("multiple tokens found!", id=1101)
        if len(toks) == 0:
            raise TokenAdminError("no token %r found!" % serial, id=1102)

        token = toks[0]
        if user.login == "":
            report = False
        else:
            report = True

        token.setUser(user, report)

        #  set the Realms of the Token
        realms = getRealms4Token(user)
        token.setRealms(realms)

        if pin is not None:
            token.setPin(pin, param)

        #  reset the OtpCounter
        token.setFailCount(0)

        try:
            token.storeToken()
        except Exception as exx:
            log.error("[assign Token] update Token DB failed: %r", exx)
            raise TokenAdminError(
                "Token assign failed for %s/%s : %r"
                % (user.login, serial, exx),
                id=1105,
            )

        log.debug(
            "[assignToken] successfully assigned token with serial "
            "%r to user %r",
            serial,
            user.login,
        )
        return True

    def unassignToken(self, serial, user=None, pin=None):
        """
        unassignToken - used to assign and to unassign token
        """
        toks = get_tokens(None, serial)
        # toks  = Session.query(Token).filter(
        #               Token.LinOtpTokenSerialnumber == serial)

        if len(toks) > 1:
            raise TokenAdminError("multiple tokens found!", id=1101)
        if len(toks) == 0:
            raise TokenAdminError("no token found!", id=1102)

        token = toks[0]
        no_user = User("", "", "")
        token.setUser(no_user, True)
        if pin:
            token.setPin(pin)

        #  reset the OtpCounter
        token.setFailCount(0)

        try:
            token.storeToken()
        except Exception as exx:
            raise TokenAdminError(
                "Token unassign failed for %r/%r: %r" % (user, serial, exx),
                id=1105,
            )

        log.debug(
            "[unassignToken] successfully unassigned token with serial %r",
            serial,
        )
        return True

    def get_serial_by_otp(
        self,
        token_list=None,
        otp="",
        window=10,
        typ=None,
        realm=None,
        assigned=None,
    ):
        """
        Returns the serial for a given OTP value and the user
        (serial, user)

        :param otp:      -  the otp value to be searched
        :param window:   -  how many OTPs should be calculated per token
        :param typ:      -  The tokentype
        :param realm:    -  The realm in which to search for the token
        :param assigned: -  search either in assigned (1) or
                            not assigend (0) tokens

        :return: the serial for a given OTP value and the user
        """
        serial = ""
        username = ""
        resolverClass = ""

        token = self.get_token_by_otp(
            token_list, otp, window, typ, realm, assigned
        )

        if token is not None:
            serial = token.getSerial()
            uid, resolver, resolverClass = token.getUser()
            userInfo = getUserInfo(uid, resolver, resolverClass)
            username = userInfo.get("username", "")

        return serial, username, resolverClass

    # local
    def get_token_by_otp(
        self,
        token_list=None,
        otp="",
        window=10,
        typ="HMAC",
        realm=None,
        assigned=None,
    ):
        """
        method
            get_token_by_otp    - from the given token list this function returns
                                  the token, that generates the given OTP value
        :param token_list:        - the list of token objects to be investigated
        :param otpval:            - the otp value, that needs to be found
        :param window:            - the window of search
        :param assigned:          - or unassigned tokens (1/0)

        :return:         returns the token object.
        """
        result_token = None

        validation_results = []
        log.debug("Searching appropriate token for otp %r", otp)

        if token_list is None:
            token_list = self.getTokensOfType(typ, realm, assigned)

        for token in token_list:
            r = token.check_otp_exist(otp=otp, window=window)
            if r >= 0:
                validation_results.append(token)

        if len(validation_results) == 1:
            result_token = validation_results[0]
        elif len(validation_results) > 1:
            raise TokenAdminError(
                "get_token_by_otp: multiple tokens are "
                "matching this OTP value!",
                id=1200,
            )

        return result_token

    # local method
    def getTokensOfType(self, typ=None, realm=None, assigned=None):
        """
        This function returns a list of token objects of the following type.

        here we need to create the token list.
           1. all types (if typ==None)
           2. realms
           3. assigned or unassigned tokens (1/0)
        TODO: rename function to "getTokens"
        """
        tokenList = []
        sqlQuery = Token.query
        if typ is not None:
            # filter for type
            sqlQuery = sqlQuery.filter(
                func.lower(Token.LinOtpTokenType) == typ.lower()
            )
        if assigned is not None:
            # filter if assigned or not
            if "0" == str(assigned):
                sqlQuery = sqlQuery.filter(
                    or_(Token.LinOtpUserid == None, Token.LinOtpUserid == "")
                )
            elif "1" == str(assigned):
                sqlQuery = sqlQuery.filter(func.length(Token.LinOtpUserid) > 0)
            else:
                log.warning(
                    "[getTokensOfType] assigned value not in [0,1] %r",
                    assigned,
                )

        if realm is not None:
            # filter for the realm
            sqlQuery = sqlQuery.filter(
                and_(
                    func.lower(Realm.name) == realm.lower(),
                    TokenRealm.realm_id == Realm.id,
                    TokenRealm.token_id == Token.LinOtpTokenId,
                )
            ).distinct()

        for token in sqlQuery:
            # the token is the database object, but we want
            # an instance of the tokenclass!
            tokenList.append(createTokenClassObject(token))

        log.debug("[getTokensOfType] retrieved matching tokens: %r", tokenList)
        return tokenList

    def removeToken(self, user=None, serial=None):
        """
        delete a token from database

        :param user: the tokens of the user
        :param serial: the token with this serial number

        :return: the number of deleted tokens
        """
        if not user and not serial:
            raise ParameterError("Parameter user or serial required!", id=1212)

        tokenList = get_raw_tokens(user, serial)

        serials = set()
        tokens = set()
        token_ids = set()
        try:

            for token in tokenList:
                ser = token.getSerial()
                serials.add(ser)
                token_ids.add(token.LinOtpTokenId)
                tokens.add(token)

            #  we cleanup the challenges
            challenges = set()
            for serial in serials:
                challenges.update(Challenges.lookup_challenges(serial=serial))

            for chall in challenges:
                db.session.delete(chall)

            #  due to legacy SQLAlchemy it could happen that the
            #  foreign key relation could not be deleted
            #  so we do this manualy

            for t_id in set(token_ids):
                TokenRealm.query.filter(TokenRealm.token_id == t_id).delete()

            db.session.commit()

            for token in tokens:
                db.session.delete(token)

        except Exception as exx:
            raise TokenAdminError(
                "removeToken: Token update failed: %r" % exx, id=1132
            )

        return len(serials)

    def setCounterWindow(self, countWindow, user, serial):

        if user is None and serial is None:
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug(
            "[setCounterWindow] setting count window for serial %r", serial
        )
        tokenList = get_tokens(user, serial)

        for token in tokenList:
            token.setCounterWindow(countWindow)
            token.addToSession()

        return len(tokenList)

    def setDescription(self, description, user=None, serial=None):

        if user is None and serial is None:
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug("[setDescription] setting description for serial %r", serial)
        tokenList = get_tokens(user, serial)

        for token in tokenList:
            token.setDescription(description)
            token.addToSession()

        return len(tokenList)

    def setHashLib(self, hashlib, user, serial):
        """
        sets the Hashlib in the tokeninfo
        """
        if user is None and serial is None:
            raise ParameterError("Parameter user or serial required!", id=1212)

        tokenList = get_tokens(user, serial)

        for token in tokenList:
            token.setHashLib(hashlib)
            token.addToSession()

        return len(tokenList)

    def setMaxFailCount(self, maxFail, user, serial):

        if (user is None) and (serial is None):
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug("[setMaxFailCount] for serial: %r, user: %r", serial, user)
        tokenList = get_tokens(user, serial)

        for token in tokenList:
            token.setMaxFail(maxFail)
            token.addToSession()

        return len(tokenList)

    def setSyncWindow(self, syncWindow, user, serial):

        if user is None and serial is None:
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug("[setSyncWindow] setting syncwindow for serial %r", serial)
        tokenList = get_tokens(user, serial)

        for token in tokenList:
            token.setSyncWindow(syncWindow)
            token.addToSession()

        return len(tokenList)

    def setOtpLen(self, otplen, user, serial):

        if (user is None) and (serial is None):
            raise ParameterError("Parameter user or serial required!", id=1212)

        tokenList = get_tokens(user, serial)

        for token in tokenList:
            token.setOtpLen(otplen)
            token.addToSession()

        return len(tokenList)

    def enableToken(self, enable, user, serial):
        """
        switch the token status to active or inactive
        :param enable: True::active or False::inactive
        :param user: all tokens of this owner
        :param serial: the serial number of the token

        :return: number of changed tokens
        """
        if (user is None) and (serial is None):
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug(
            "[enableToken] enable=%r, user=%r, serial=%r", enable, user, serial
        )
        tokenList = get_tokens(user, serial)

        for token in tokenList:
            token.enable(enable)
            token.addToSession()

        return len(tokenList)

    def copyTokenPin(self, serial_from, serial_to):
        """
        This function copies the token PIN from one token to the other token.
        This can be used for workflows like lost token.

        In fact the PinHash and the PinSeed need to be transferred

        returns:
            1 : success
            -1: no source token
            -2: no destination token
        """
        log.debug(
            "[copyTokenPin] copying PIN from token %r to token %r",
            serial_from,
            serial_to,
        )
        tokens_from = get_tokens(None, serial_from)
        tokens_to = get_tokens(None, serial_to)
        if len(tokens_from) != 1:
            log.error("[copyTokenPin] not a unique token to copy from found")
            return -1
        if len(tokens_to) != 1:
            log.error("[copyTokenPin] not a unique token to copy to found")
            return -2
        import linotp.tokens.base

        linotp.tokens.base.TokenClass.copy_pin(tokens_from[0], tokens_to[0])
        return 1

    def copyTokenUser(self, serial_from, serial_to):
        """
        This function copies the user from one token to the other
        This can be used for workflows like lost token

        returns:
            1: success
            -1: no source token
            -2: no destination token
        """
        log.debug(
            "[copyTokenUser] copying user from token %r to token %r",
            serial_from,
            serial_to,
        )
        tokens_from = get_tokens(None, serial_from)
        tokens_to = get_tokens(None, serial_to)
        if len(tokens_from) != 1:
            log.error("[copyTokenUser] not a unique token to copy from found")
            return -1
        if len(tokens_to) != 1:
            log.error("[copyTokenUser] not a unique token to copy to found")
            return -2
        uid, ures, resclass = tokens_from[0].getUser()
        tokens_to[0].setUid(uid, ures, resclass)

        self.copyTokenRealms(serial_from, serial_to)
        return 1

    # local
    def copyTokenRealms(self, serial_from, serial_to):
        realmlist = getTokenRealms(serial_from)
        setRealms(serial_to, realmlist)

    def addTokenInfo(self, info, value, user, serial):
        """
        sets an abitrary Tokeninfo field
        """
        if user is None and serial is None:
            raise ParameterError("Parameter user or serial required!", id=1212)

        tokenList = get_tokens(user, serial)

        for token in tokenList:
            token.addToTokenInfo(info, value)
            token.addToSession()

        return len(tokenList)

    def resyncToken(self, otp1, otp2, user, serial, options=None):
        """
        resync a token by its consecutive otps

        :param user: the token owner
        :param serial: the serial number of the token
        :param options: the additional command parameters for specific token
        :return: Success by a boolean
        """
        ret = False

        if (user is None) and (serial is None):
            raise ParameterError("Parameter user or serial required!", id=1212)

        log.debug("[resyncToken] resync token with serial %r", serial)
        tokenList = get_tokens(user, serial)

        for token in tokenList:
            res = token.resync(otp1, otp2, options)
            if res is True:
                ret = True
            token.addToSession()
        return ret

    def genSerial(self, tokenType=None, prefix=None):
        """
        generate a serial number similar to the one generated in the
        manage web gui

        :param tokenType: the token type prefix is done by
                          a lookup on the tokens
        :return: serial number
        """
        if tokenType is None:
            tokenType = "LSUN"

        if prefix is None:
            prefix = tokenType.upper()
            if tokenType.lower() in tokenclass_registry:
                token_cls = tokenclass_registry.get(tokenType.lower())
                prefix = token_cls.getClassPrefix().upper()

        #  now search the number of ttypes in the token database
        tokennum = Token.query.filter_by(
            LinOtpTokenType="" + tokenType
        ).count()

        serial = _gen_serial(prefix, tokennum + 1)

        #  now test if serial already exists
        while True:
            numtokens = Token.query.filter_by(
                LinOtpTokenSerialnumber="" + serial
            ).count()
            if numtokens == 0:
                #  ok, there is no such token, so we're done
                break
            #  else - rare case:
            #  we add the numtokens to the number of existing tokens
            # with serial
            serial = _gen_serial(prefix, tokennum + numtokens)

        return serial

    def __llast(self):
        pass


# local


def createTokenClassObject(token: Token, token_type: string = None):
    """
    createTokenClassObject - create a token class object from a given type

    :param token:       a raw token as retrieved from the database
    :type  token:       Token
    :param token_type:  type of the token object to be created
    :type  token_type:  string

    :return: a token instance with type-specific behavior
    :rtype:  subclass of TokenClass
    """

    # if type is not given, we take it out of the token database object
    if token_type is None:
        token_type = token.LinOtpTokenType

    if token_type == "":
        token_type = "hmac"

    token_type = token_type.lower()

    token_class = None
    from linotp.tokens.base import TokenClass

    # search which tokenclass should be created and create it!
    if token_type.lower() in tokenclass_registry:
        try:
            constructor = tokenclass_registry.get(token_type)
            token_class: TokenClass = constructor(token)

        except Exception as exx:
            raise TokenAdminError(
                "createTokenClassObject failed:  %r" % exx, id=1609
            )

    else:

        # we try to use the parent class, which is able to handle most
        # of the administrative tasks. This will allow to unassigen and
        # disable or delete this 'abandoned token'

        log.error(
            "Token type %r not found. Available types are: %r."
            "Using default token class as fallback ",
            token_type,
            list(tokenclass_registry.keys()),
        )

        token_class = TokenClass(token)

    return token_class


def get_token_type_list():
    """
    get_token_type_list - returns the list of the available tokentypes
    like hmac, spass, totp...

    :return: list of token types
    """
    token_types = []

    for token_class_obj in set(tokenclass_registry.values()):
        token_types.append(token_class_obj.getClassType())

    return token_types


def getRealms4Token(user, tokenrealm=None):
    """
    get the realm objects of a user or from the tokenrealm defintion,
    which could be a list of realms or a single realm

    helper method to enhance the code readability

    :param user: the user wich defines the set of realms
    :param tokenrealm: a string or a list of realm strings

    :return: the list of realm objects
    """

    realms = []
    if user is not None and user.login != "":
        #  the getUserRealms should return the default realm if realm was empty
        realms = getUserRealms(user)
        #  hack: sometimes the realm of the user is not in the
        #  realmDB - so check and add
        for r in realms:
            realmObj = getRealmObject(name=r)
            if realmObj is None:
                createDBRealm(r)

    if tokenrealm is not None:
        # tokenrealm can either be a string or a list
        log.debug(
            "[getRealms4Token] tokenrealm given (%r). We will add the "
            "new token to this realm",
            tokenrealm,
        )
        if isinstance(tokenrealm, str):
            log.debug("[getRealms4Token] String: adding realm: %r", tokenrealm)
            realms.append(tokenrealm)
        elif isinstance(tokenrealm, list):
            for tr in tokenrealm:
                realms.append(tr)

    realmList = realm2Objects(realms)

    return realmList


def get_tokenserial_of_transaction(transId):
    """
    get the serial number of a token from a challenge state / transaction

    :param transId: the state / transaction id
    :return: the serial number or None
    """
    serials = []

    challenges = Challenges.lookup_challenges(transid=transId)

    for challenge in challenges:
        serials.append(challenge.tokenserial)

    return serials


def getRolloutToken4User(user=None, serial=None, tok_type="ocra2"):

    if not user and serial is None:
        return None

    serials = []
    tokens = []

    if user and user.login:
        resolverUid = user.resolverUid
        v = None
        k = None
        for k in resolverUid:
            v = resolverUid.get(k)
        user_id = v

        # in the database could be tokens of ResolverClass:
        #    useridresolver. or useridresolveree.
        # so we have to make sure
        # - there is no 'useridresolveree' in the searchterm and
        # - there is a wildcard search: second replace
        # Remark: when the token is loaded the response to the
        # resolver class is adjusted

        user_resolver = k.replace("useridresolveree.", "useridresolver.")
        user_resolver = user_resolver.replace(
            "useridresolver.", "useridresolver%."
        )

        """ coout tokens: 0 1 or more """
        tokens = Token.query.filter(
            Token.LinOtpTokenType == str(tok_type),
            Token.LinOtpIdResClass.like(str(user_resolver)),
            Token.LinOtpUserid == str(user_id),
        )

    elif serial is not None:
        tokens = Token.query.filter(
            Token.LinOtpTokenType == str(tok_type),
            Token.LinOtpTokenSerialnumber == str(serial),
        )

    for token in tokens:
        info = token.LinOtpTokenInfo
        if len(info) > 0:
            tinfo = json.loads(info)
            rollout = tinfo.get("rollout", None)
            if rollout is not None:
                serials.append(token.LinOtpTokenSerialnumber)

    if len(serials) > 1:
        raise Exception("multiple tokens found in rollout state: %r" % serials)

    if len(serials) == 1:
        serial = serials[0]

    return serial


def setRealms(serial, realmList):
    # set the tokenlist of DB tokens
    tokenList = get_raw_tokens(None, serial)

    if len(tokenList) == 0:
        raise TokenAdminError(
            "setRealms failed. No token with serial %s found" % serial, id=1119
        )

    realmObjList = realm2Objects(realmList)

    for token in tokenList:
        token.setRealms(realmObjList)

    return len(tokenList)


def getTokenRealms(serial):
    """
    This function returns a list of the realms of a token
    """
    tokenList = get_raw_tokens(None, serial)

    if len(tokenList) == 0:
        raise TokenAdminError(
            "getTokenRealms failed. No token with serial %s found" % serial,
            id=1119,
        )

    token = tokenList[0]

    return token.getRealmNames()


def getRealmsOfTokenOrUser(token):
    """
    This returns the realms of either the token or
    of the user of the token.
    """
    serial = token.getSerial()
    realms = getTokenRealms(serial)

    if len(realms) == 0:
        uid, resolver, resolverClass = token.getUser()
        # No realm and no User, this is the case in /validate/check_s
        if resolver.find(".") >= 0:
            resotype, resoname = resolver.rsplit(".", 1)
            realms = getUserRealms(User("dummy_user", "", resoname))

    log.debug(
        "[getRealmsOfTokenOrUser] the token %r "
        "is in the following realms: %r",
        serial,
        realms,
    )

    return realms


def getTokenInRealm(realm, active=True):
    """
    This returns the number of tokens in one realm.

    You can either query only active token or also disabled tokens.
    """
    if active:
        sqlQuery = (
            db.session.query(TokenRealm, Realm, Token)
            .filter(
                TokenRealm.realm_id == Realm.id,
                func.lower(Realm.name) == realm.lower(),
                Token.LinOtpIsactive,
                TokenRealm.token_id == Token.LinOtpTokenId,
            )
            .count()
        )
    else:
        sqlQuery = (
            db.session.query(TokenRealm, Realm)
            .filter(
                TokenRealm.realm_id == Realm.id,
                func.lower(Realm.name) == realm.lower(),
            )
            .count()
        )
    return sqlQuery


def get_used_tokens_count(resolver=None, active=True, realm=None):
    """
    get the number of used tokens

    :param resolver: count only the token users per resolver
    :param active: boolean - count base only on active tokens
    :return: the number of token / token user
    """

    if linotp.lib.support.get_license_type() == "user-num":
        return getNumTokenUsers(resolver=resolver, active=active)

    return getTokenNumResolver(resolver=resolver, active=active)


def getNumTokenUsers(resolver=None, active=True, realm=None):
    """
    get the number of distinct the token users

    :param resolver: count only the token users per resolver
    :param active: boolean - count base only on active tokens
    :return: the number of token users
    """

    session = db.session.query(Token.LinOtpUserid, Token.LinOtpIdResClass)

    # only count users and not the empty ones

    conditions = (and_(Token.LinOtpUserid != ""),)

    if realm:
        conditions += (
            and_(
                TokenRealm.realm_id == Realm.id,
                func.lower(Realm.name) == realm.lower(),
                TokenRealm.token_id == Token.LinOtpTokenId,
            ),
        )
        session = db.session.query(TokenRealm, Realm, Token)

    elif resolver:

        resolver = resolver.resplace("useridresolveree.", "useridresolver.")
        resolver = resolver.resplace("useridresolver.", "useridresolver%.")

        conditions += (and_(Token.LinOtpIdResClass.like(resolver)),)

    if active:

        conditions += (and_(Token.LinOtpIsactive),)

    condition = and_(*conditions)

    return session.filter(condition).distinct().count()


def getTokenNumResolver(resolver=None, active=True):
    """
    get the number of used tokens

     in the database could be tokens of ResolverClass:
        useridresolver. or useridresolveree.
     so we have to make sure
     - there is no 'useridresolveree' in the searchterm and
     - there is a wildcard search: second replace
     Remark: when the token is loaded the response to the
     resolver class is adjusted

    :param resolver: count only the token users per resolver
    :param active: boolean - count base only on active tokens
    :return: the number of token
    """

    conditions = ()

    if resolver:

        resolver = resolver.resplace("useridresolveree.", "useridresolver.")
        resolver = resolver.resplace("useridresolver.", "useridresolver%.")

        conditions += (and_(Token.LinOtpIdResClass.like(resolver)),)

    if active:

        conditions += (and_(Token.LinOtpIsactive),)

    condition = and_(*conditions)

    return Token.query.filter(condition).count()


def token_owner_iterator():
    """
    iterate all tokens for serial and users
    """

    sqlQuery = Token.query.filter(Token.LinOtpUserid != "").all()

    for token in sqlQuery:
        userInfo = {}

        serial = token.LinOtpTokenSerialnumber
        userId = token.LinOtpUserid
        resolver = token.LinOtpIdResolver
        resolverC = token.LinOtpIdResClass

        if userId and resolverC:
            userInfo = getUserInfo(userId, resolver, resolverC)

        if userId and not userInfo:
            userInfo["username"] = "/:no user info:/"

        yield serial, userInfo["username"]


def get_tokens(
    user: User = None,
    serial: string = None,
    token_type: string = None,
    read_for_update: bool = False,
    active: bool = None,
):
    """
    Get a list of tokens of type TokenClass or any of its subclasses.

    The result can be filtered by owner, serial, type and activation status.

    Additionally, the flag read_for_update specifies whether a lock on the database is required. This is necessary when
    obtaining a list of tokens for validation purposes.
    """
    tokens = get_raw_tokens(user, serial, token_type, read_for_update, active)

    return [createTokenClassObject(token) for token in tokens]


def get_raw_tokens(
    user: User = None,
    serial: string = None,
    token_type: string = None,
    read_for_update: bool = False,
    active: bool = None,
) -> List[Token]:
    """
    Get a list of tokens of type Token, an object containing the database fields for the token and little more.

    It does not provide tokens with type-specific functionality. If that is what you are looking for, please use
    get_tokens() instead.

    The result can be filtered by owner, serial, type and activation status.

    Additionally, the flag read_for_update specifies whether a lock on the database is required. This is necessary when
    obtaining a list of tokens for validation purposes.
    """
    tokenList = []

    if serial is None and user is None:
        log.warning("[get_tokens] missing user or serial")
        return tokenList

    sconditions = ()

    if active in [True, False]:
        sconditions += ((Token.LinOtpIsactive == active),)

    if token_type:
        sconditions += (
            (func.lower(Token.LinOtpTokenType) == token_type.lower()),
        )

    if serial:
        log.debug(
            "[get_tokens] getting token object with serial: %r",
            serial,
        )

        if "*" in serial:
            serial = serial.replace("*", "%")
            sconditions += ((Token.LinOtpTokenSerialnumber.like(serial)),)
        else:
            sconditions += ((Token.LinOtpTokenSerialnumber == serial),)

        # finally run the query on token serial
        condition = and_(*sconditions)

        sqlQuery = Token.query.filter(condition)

        # ------------------------------------------------------------------ --

        # for the validation we require an read for update lock

        if read_for_update:
            try:

                sqlQuery = sqlQuery.with_for_update("update").all()

            except ResourceClosedError as exx:
                log.warning("Token already locked for update: %r", exx)
                raise Exception("Token already locked for update: (%r)" % exx)

        for token in sqlQuery:
            tokenList.append(token)

    if user and user.login:
        for user_definition in user.get_uid_resolver():
            uid, resolverClass = user_definition
            # in the database could be tokens of ResolverClass:
            #    useridresolver. or useridresolveree.
            # so we have to make sure
            # - there is no 'useridresolveree' in the searchterm and
            # - there is a wildcard search: second replace
            # Remark: when the token is loaded the response to the
            # resolver class is adjusted

            uconditions = sconditions

            resolverClass = resolverClass.replace(
                "useridresolveree.", "useridresolver."
            )
            resolverClass = resolverClass.replace(
                "useridresolver.", "useridresolver%."
            )

            if isinstance(uid, int):
                uconditions += ((Token.LinOtpUserid == "%d" % uid),)
            else:
                uconditions += ((Token.LinOtpUserid == uid),)

            uconditions += ((Token.LinOtpIdResClass.like(resolverClass)),)

            sqlQuery = Token.query.filter(*uconditions)

            # ---------------------------------------------------------- --

            # for the validation we require an read for update lock
            # which could raise a ResourceClosedError to show that the
            # resource is already allocated in an other request

            if read_for_update:

                try:

                    sqlQuery = sqlQuery.with_for_update("update").all()

                except ResourceClosedError as exx:
                    log.warning("Token already locked for update: %r", exx)
                    raise Exception(
                        "Token already locked for update: (%r)" % exx
                    )

            # ---------------------------------------------------------- --

            for token in sqlQuery:
                # we have to check that the token is in the same realm as
                # the user
                t_realms = token.getRealmNames()
                u_realm = user.realm
                if u_realm != "*":
                    if len(t_realms) > 0 and len(u_realm) > 0:
                        if u_realm.lower() not in t_realms:
                            log.debug(
                                "user realm and token realm missmatch"
                                " %r::%r",
                                u_realm,
                                t_realms,
                            )
                            continue

                log.debug(
                    "[get_tokens] user serial (user): %r",
                    token.LinOtpTokenSerialnumber,
                )
                tokenList.append(token)

    log.debug("Retrieved token list %r", tokenList)
    return tokenList


def setDefaults(token):
    #  set the defaults
    token.LinOtpOtpLen = int(getFromConfig("DefaultOtpLen", 6))
    token.LinOtpCountWindow = int(getFromConfig("DefaultCountWindow", 15))
    token.LinOtpMaxFail = int(getFromConfig("DefaultMaxFailCount", 15))
    token.LinOtpSyncWindow = int(getFromConfig("DefaultSyncWindow", 1000))

    token.LinOtpTokenType = "HMAC"


def tokenExist(serial):
    """
    returns true if the token exists
    """
    if serial:
        toks = get_tokens(None, serial)
        return len(toks) > 0
    else:
        # If we have no serial we return false anyway!
        return False


def get_token_owner(token):
    """
    provide the owner as a user object for a given tokenclass obj

    :param token: tokenclass object
    :return: user object
    """

    if token is None:
        # for backward compatibility, we return here an empty user
        return User()

    serial = token.getSerial()

    uid, resolver, resolverClass = token.getUser()

    userInfo = getUserInfo(uid, resolver, resolverClass)

    if not userInfo:
        return User()

    realms = getUserRealms(User(uid, "", resolverClass.split(".")[-1]))

    # if there are several realms, than we need to find out, which one!
    if len(realms) > 1:
        t_realms = getTokenRealms(serial)
        common_realms = list(set(realms).intersection(t_realms))
        if len(common_realms) > 1:
            raise Exception(
                _(
                    "get_token_owner: The user %s/%s and the token"
                    " %s is located in several realms: "
                    "%s!" % (uid, resolverClass, serial, common_realms)
                )
            )
        realm = common_realms[0]
    elif len(realms) == 0:
        raise Exception(
            _(
                "get_token_owner: The user %s in the resolver"
                " %s for token %s could not be found in any "
                "realm!" % (uid, resolverClass, serial)
            )
        )
    else:
        realm = realms[0]

    user = User()
    user.realm = realm
    user.login = userInfo.get("username")
    user.resolver_config_identifier = resolverClass
    if userInfo:
        user.info = userInfo

    log.debug(
        "[get_token_owner] found the user %r and the realm %r as "
        "owner of token %r",
        user.login,
        user.realm,
        serial,
    )

    return user


def getTokenType(serial):
    """
    Returns the tokentype of a given serial number

    :param serial: the serial number of the to be searched token
    """
    toks = get_raw_tokens(None, serial)

    typ = ""
    for tok in toks:
        typ = tok.LinOtpTokenType

    log.debug("The token type of serial %s is %r", serial, typ)

    return typ


def add_last_accessed_info(list_of_tokens):
    """small wrapper to set the accessed time info"""
    add_time_info(list_of_tokens, mode="accessed")


def add_last_verified_info(list_of_tokens):
    """small wrapper to set the verified time info"""
    add_time_info(list_of_tokens, mode="verified")


def add_time_info(list_of_tokens, mode="accessed"):
    """
    add time info to token
    if token_last_access is defined in the config. it is used as a filter to
    only preserve information which is compliant with the data preserving policy

    :param list_of_tokens: all tokens which should get a time stamp update
    :param mode: which token data should be stored
    """

    token_access = getFromConfig("linotp.token.last_access", None)

    if token_access in [None, False]:
        return
    elif token_access is True:
        token_access_fmt = DEFAULT_TIMEFORMAT
    elif token_access.lower() == "false":
        return
    elif token_access.lower() == "true":
        token_access_fmt = DEFAULT_TIMEFORMAT
    else:
        token_access_fmt = token_access

    # ---------------------------------------------------------------------- --

    # we take the given time format as a filter and keep only
    # relevant information. but first we remove the microsecond as these
    # causes problem in case of mysql

    now = datetime.datetime.utcnow().replace(microsecond=0)

    try:

        dt_str = now.strftime(token_access_fmt)
        now_stripped = datetime.datetime.strptime(dt_str, token_access_fmt)

    except ValueError as err:

        # in case of a time string format error we do not filter the time
        # and only log an error as it's not acceptable to stop a validation
        # caused by a formatting error

        log.error("linotp.token.last_access time format error: %r", err)
        return

    # ---------------------------------------------------------------------- --

    # finally add the time to the token

    for token in list_of_tokens:
        if mode == "verified":
            token.token.LinOtpLastAuthSuccess = now_stripped
        else:
            token.token.LinOtpLastAuthMatch = now_stripped

            # we softly migrate the last_access away from the token info

            if token.getFromTokenInfo("last_access"):
                token.removeFromTokenInfo("last_access")


def get_multi_otp(serial, count=0, epoch_start=0, epoch_end=0, curTime=None):
    """
    This function returns a list of OTP values for the given Token.
    Please note, that this controller needs to be activated and
    that the tokentype needs to support this function.

    method
        get_multi_otp    - get the list of OTP values

    parameter
        serial            - the serial number of the token
        count             - number of the <count> next otp values (to be used with event or timebased tokens)
        epoch_start       - unix time start date (used with timebased tokens)
        epoch_end         - unix time end date (used with timebased tokens)
        curTime           - used for token test

    return
        dictionary of otp values
    """
    ret = {"result": False}
    toks = get_tokens(None, serial)

    if len(toks) > 1:
        raise TokenAdminError(
            "multiple tokens found - cannot get OTP!", id=1201
        )

    if len(toks) == 0:
        log.warning("No token with serial %r found", serial)
        ret["error"] = "No Token with serial %s found." % serial

    if len(toks) == 1:
        token = toks[0]
        log.debug(
            "[get_multi_otp] getting multiple otp values for token %r. "
            "curTime=%r",
            token,
            curTime,
        )

        # if the token does not support getting the OTP
        # value, res==False is returned

        (res, error, otp_dict) = token.get_multi_otp(
            count=count,
            epoch_start=epoch_start,
            epoch_end=epoch_end,
            curTime=curTime,
        )

        if res is True:
            ret = otp_dict
            ret["result"] = True
        else:
            ret["error"] = error

    return ret


def getOtp(serial, curTime=None):
    """
    This function returns the current OTP value for a given Token.
    Please note, that this controller needs to be activated and
    that the tokentype needs to support this function.

    method
        getOtp    - get the current OTP value

    parameter
        serial    - serialnumber for token
        curTime   - used for self test

    return
        tuple with (res, pin, otpval, passw)

    """
    log.debug("[getOtp] retrieving OTP value for token %r", serial)
    toks = get_tokens(None, serial)

    if len(toks) > 1:
        raise TokenAdminError(
            "multiple tokens found - cannot get OTP!", id=1101
        )

    if len(toks) == 0:
        log.warning("[getOTP] there is no token with serial %r", serial)
        return (-1, "", "", "")

    if len(toks) == 1:
        token = toks[0]
        # if the token does not support getting the OTP value, a -2 is
        # returned.
        return token.getOtp(curTime=curTime)


def setPin(pin, user, serial, param=None):
    """
    set the PIN
    """
    if param is None:
        param = {}

    if (user is None) and (serial is None):
        raise ParameterError("Parameter user or serial required!", id=1212)

    if user is not None:
        log.info("[setPin] setting Pin for user %r@%r", user.login, user.realm)
    if serial is not None:
        log.info("[setPin] setting Pin for token with serial %r", serial)

    tokenList = get_tokens(user, serial)

    for token in tokenList:
        token.setPin(pin, param)
        token.addToSession()

    return len(tokenList)


# local

###############################################################################
#  LinOtpTokenPinUser
###############################################################################
def setPinUser(userPin, serial):

    user = None

    if serial is None:
        raise ParameterError("Parameter 'serial' is required!", id=1212)

    log.debug("[setPinUser] setting Pin for serial %r", serial)
    tokenList = get_tokens(user, serial)

    for token in tokenList:
        token.setUserPin(userPin)
        token.addToSession()

    return len(tokenList)


###############################################################################
#  LinOtpTokenPinSO
###############################################################################


def setPinSo(soPin, serial):
    user = None

    if serial is None:
        raise ParameterError("Parameter 'serial' is required!", id=1212)

    log.debug("[setPinSo] setting Pin for serial %r", serial)
    tokenList = get_tokens(user, serial)

    for token in tokenList:
        token.setSoPin(soPin)
        token.addToSession()

    return len(tokenList)


def resetToken(user=None, serial=None):

    if (user is None) and (serial is None):
        log.warning("[resetToken] Parameter serial or user required!")
        raise ParameterError("Parameter user or serial required!", id=1212)

    log.debug("[resetToken] reset token with serial %r", serial)
    tokenList = get_tokens(user, serial)

    for token in tokenList:
        token.reset()
        token.addToSession()

    return len(tokenList)


def _gen_serial(prefix, tokennum, min_len=8):
    """
    helper to create a hex digit string

    :param prefix: the prepended prefix like LSGO
    :param tokennum: the token number counter (int)
    :param min_len: int, defining the length of the hex string
    :return: hex digit string
    """
    h_serial = ""
    num_str = "%.4d" % tokennum
    h_len = min_len - len(num_str)
    if h_len > 0:
        h_serial = (
            binascii.hexlify(os.urandom(h_len)).decode().upper()[0:h_len]
        )
    return "%s%s%s" % (prefix, num_str, h_serial)


def genSerial(tokenType=None, prefix=None):
    """
    generate a serial number similar to the one generated in the manage web gui

    :param tokenType: the token type prefix is done by a lookup on the tokens
    :return: serial number
    """
    if tokenType is None:
        tokenType = "LSUN"

    if prefix is None:
        prefix = tokenType.upper()
        if tokenType.lower() in tokenclass_registry:
            token_cls = tokenclass_registry.get(tokenType.lower())
            prefix = token_cls.getClassPrefix().upper()

    #  now search the number of ttypes in the token database
    tokennum = Token.query.filter_by(LinOtpTokenType="" + tokenType).count()

    serial = _gen_serial(prefix, tokennum + 1)

    #  now test if serial already exists
    while True:
        numtokens = Token.query.filter_by(
            LinOtpTokenSerialnumber="" + serial
        ).count()
        if numtokens == 0:
            #  ok, there is no such token, so we're done
            break
        #  else - rare case:
        #  we add the numtokens to the number of existing tokens with serial
        serial = _gen_serial(prefix, tokennum + numtokens)

    return serial


def getTokenConfig(tok, section=None):
    """
    getTokenConfig - return the config definition
                     of a dynamic token

    :param tok: token type (shortname)
    :type  tok: string

    :param section: subsection of the token definition - optional
    :type   section: string

    :return: dict - if nothing found an empty dict
    :rtype:  dict
    """

    res = {}

    if tok in tokenclass_registry:
        tclt = tokenclass_registry.get(tok)
        # check if we have a policy in the token definition
        if hasattr(tclt, "getClassInfo"):
            res = tclt.getClassInfo(section, ret={})

    return res


def _calculate_validity_end(validity):
    """
    helper function to calculate the validity end for a token

    :param validity: the validity as days (int) or as duration expression
    :return: the end date as string
    """

    if validity == -1:
        validity = 10

    try:

        int(validity)

        # in case of only <int> days are given, for compatibility
        # the day ends at 23:59 minutes. So we adjust the duration
        # expression with remaining hours and minutes

        end_date = (
            datetime.date.today() + datetime.timedelta(days=validity)
        ).strftime("%d/%m/%y")

        end_date = "%s 23:59" % end_date

    except ValueError:

        end_date = (
            datetime.datetime.now() + parse_duration(validity)
        ).strftime("%d/%m/%y %H:%M")

    log.debug("losttoken: validity: %r", validity)

    return end_date


def remove_token(token):
    """
    remove a token and all related entries like challenges or realm reference

    :param token: Token or TokenClass object
    """

    if issubclass(token.__class__, linotp.tokens.base.TokenClass):
        token = token.token

    #  we cleanup the challenges
    serial = token.getSerial()
    for chall in Challenges.lookup_challenges(serial=serial):
        db.session.delete(chall)

    # cleanup of the realm references
    token_id = token.LinOtpTokenId
    TokenRealm.query.filter_by(token_id=token_id).delete()

    # as these references seems not to be marked in the cache, we have to
    # update the cache manaualy

    db.session.commit()

    # finally remove the token
    db.session.delete(token)


# eof #########################################################################

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

"""
userservice controller -
     This is the controller for the user self service
     interface, where an authenitcated users can manage their own tokens

There are three types of requests
  * the context requests: before, context
  * the auth requests: auth, userinfo
  * the admin requests

At least all admin request must provide the auth cookie and the username
- the auth cookie is verified by decryption
- the username is checked for valid policy acceptance

Remarks:
 * the userinfo request could use the cookie check as it is running after
   the authorization request,  but no policy definition is required
 * the context request might as well run for an authenticated user, thus
   auth request but no policy check

"""

import base64
import json
import logging
import os

from flask_babel import gettext as _
from mako.exceptions import CompileException
from werkzeug.exceptions import Forbidden, Unauthorized

from flask import current_app, g

from linotp.controllers.base import BaseController
from linotp.flap import config
from linotp.flap import render_mako as render
from linotp.flap import request, response
from linotp.flap import tmpl_context as c
from linotp.lib.apps import create_google_authenticator, create_oathtoken_url
from linotp.lib.audit.base import get_token_num_info
from linotp.lib.audit.base import search as audit_search
from linotp.lib.auth.validate import ValidationHandler
from linotp.lib.challenges import Challenges
from linotp.lib.config import getFromConfig
from linotp.lib.context import request_context
from linotp.lib.error import ParameterError
from linotp.lib.policy import (
    PolicyException,
    checkOTPPINPolicy,
    checkPolicyPost,
    checkPolicyPre,
    get_client_policy,
    getOTPPINEncrypt,
)
from linotp.lib.policy.action import get_selfservice_action_value
from linotp.lib.realm import getDefaultRealm, getRealms
from linotp.lib.reply import (
    create_img,
    create_img_src,
    sendError,
    sendQRImageResult,
)
from linotp.lib.reply import sendResult as sendResponse
from linotp.lib.reporting import token_reporting
from linotp.lib.resolver import getResolverObject
from linotp.lib.token import (
    TokenHandler,
    get_multi_otp,
    getTokenRealms,
    getTokens4UserOrSerial,
    getTokenType,
    resetToken,
    setPin,
    setPinUser,
)
from linotp.lib.type_utils import boolean
from linotp.lib.user import (
    User,
    getRealmBox,
    getUserId,
    getUserInfo,
    splitUser,
)
from linotp.lib.userservice import (
    check_session,
    create_auth_cookie,
    get_context,
    get_cookie_authinfo,
    get_pre_context,
    get_transaction_detail,
    get_userinfo,
    getTokenForUser,
    remove_auth_cookie,
)
from linotp.lib.util import generate_otpkey, get_client, remove_empty_lines
from linotp.model import db
from linotp.tokens import tokenclass_registry

log = logging.getLogger(__name__)

ENCODING = "utf-8"

HASHLIB_MAP = {1: "sha1", 2: "sha256", 3: "sha512"}


# -------------------------------------------------------------------------- --


def secure_cookie():
    """
    in the development environment where we run in debug mode
    there is probaly no https defined. So we switch secure cookies off.
    this is done in the settings.py
    """
    return config["SESSION_COOKIE_SECURE"]


# -------------------------------------------------------------------------- --


class UserNotFound(Exception):
    pass


def get_auth_user(request):
    """
    retrieve the authenticated user either from
    selfservice or userservice api / remote selfservice

    :param request: the request object
    :return: tuple of (authentication type and authenticated user and
                        authentication state)
    """

    # ---------------------------------------------------------------------- --

    # for the form based selfservice we have the 'user_selfservice' cookie

    selfservice_cookie = request.cookies.get("user_selfservice")

    if selfservice_cookie:
        user, _client, state, _state_data = get_cookie_authinfo(
            selfservice_cookie
        )
        auth_type = "user_selfservice"

        return auth_type, user, state

    # ---------------------------------------------------------------------- --

    # for the remote selfservice or userservice api via /userservice/auth
    # we have the 'userauthcookie'

    remote_selfservice_cookie = request.cookies.get("userauthcookie")

    if remote_selfservice_cookie:
        user, _client, state, _state_data = get_cookie_authinfo(
            remote_selfservice_cookie
        )
        auth_type = "userservice"

        return auth_type, user, state

    return "unauthenticated", None, None


def unauthorized(response_proxy, exception, status=401):
    """extend the standard sendResult to handle cookies"""

    response = sendError(_response=None, exception=exception)

    response.status_code = status

    if response_proxy and response_proxy.delete_cookies:
        for delete_cookie in response_proxy.delete_cookies:
            response.delete_cookie(key=delete_cookie)

    if response_proxy and response_proxy.cookies:
        for args, kwargs in response_proxy.cookies:
            response.set_cookie(*args, **kwargs)

    if response_proxy and response_proxy.mime_type:
        response.mime_type = response_proxy.mime_type

    return Unauthorized(response=response)


def sendResult(response_proxy, obj, id=1, opt=None, status=True):
    """extend the standard sendResult to handle cookies"""

    response = sendResponse(
        response=None, obj=obj, id=id, opt=opt, status=status
    )

    if response_proxy and response_proxy.delete_cookies:
        for delete_cookie in response_proxy.delete_cookies:
            response.delete_cookie(key=delete_cookie)

    if response_proxy and response_proxy.cookies:
        for args, kwargs in response_proxy.cookies:
            response.set_cookie(*args, **kwargs)

    if response_proxy and response_proxy.mime_type:
        response.mime_type = response_proxy.mime_type

    return response


class LocalResponseProxy:
    def __init__(self):
        self.delete_cookies = set()
        self.cookies = []
        self.mime_type = None

    def set_cookie(self, *args, **kwargs):
        self.cookies.append((args, kwargs))

    def delete_cookie(self, key):
        self.delete_cookies.add(key)


class UserserviceController(BaseController):
    """
    the interface from the service into linotp to execute the actions for the
    user in the scope of the selfservice

    after the login, the selfservice user gets an auth cookie, which states
    that he already has been authenticated. This cookie is provided on every
    request during which the auth_cookie and session is verified
    """

    def __before__(self, **params):
        """
        __before__ is called before every action

        every request to the userservice must pass this place
        here we can check the authorisation for each action and the
        per request general available information

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'

        """

        # for seamless migration from pylons to flask
        self.response = LocalResponseProxy()

        action = request_context["action"]

        self.client = get_client(request) or ""

        # ------------------------------------------------------------------ --

        # build up general available variables

        context = get_pre_context(self.client)
        self.mfa_login = context["settings"]["mfa_login"]
        self.autoassign = context["settings"]["autoassign"]
        self.autoenroll = context["settings"]["autoenroll"]

        # ------------------------------------------------------------------ --

        # setup the audit for general availibility

        g.audit["success"] = False
        g.audit["client"] = self.client

        # ------------------------------------------------------------------ --

        # the following actions dont require an authenticated session

        if action in ["auth", "pre_context", "login", "logout"]:

            return

        # ------------------------------------------------------------------ --

        # every action other than auth, login and pre_context requires a valid
        # session and cookie

        auth_type, identity, auth_state = get_auth_user(request)

        if not identity or auth_type not in [
            "userservice",
            "user_selfservice",
        ]:

            raise unauthorized(self.response, _("No valid session"))

        # ------------------------------------------------------------------ --

        # make the authenticated user global available

        self.authUser = identity

        # we put the authenticated user in the `request_context['AuthUser']`
        # which is normaly filled by the getUserFromRequest
        # as we require the authenticated user in the __after__ method for
        # audit and reporting

        request_context["AuthUser"] = {
            "login": self.authUser.login,
            "realm": self.authUser.realm,
        }

        c.user = identity.login
        c.realm = identity.realm

        # ------------------------------------------------------------------ --

        # finally check the validty of the session

        if not check_session(request, self.authUser, self.client):

            raise unauthorized(self.response, _("No valid session"))

        # ------------------------------------------------------------------ --

        # the usertokenlist could be catched in any identified state

        if action in ["usertokenlist", "userinfo"]:

            return

        # ------------------------------------------------------------------ --

        # any other action requires a full ' state

        if auth_state != "authenticated":

            raise unauthorized(self.response, _("No valid session"))

        # ------------------------------------------------------------------ --

        return

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        action = request_context["action"]

        authUser = request_context["AuthUser"]

        try:
            if g.audit["action"] not in [
                "userservice/context",
                "userservice/pre_context",
                "userservice/userinfo",
            ]:

                g.audit["user"] = authUser.get("login", "")
                g.audit["realm"] = authUser.get("realm", "")

                log.debug(
                    "[__after__] authenticating as %s in realm %s!",
                    g.audit["user"],
                    g.audit["realm"],
                )

                if "serial" in request.params:
                    serial = request.params["serial"]
                    g.audit["serial"] = serial
                    g.audit["token_type"] = getTokenType(serial)

                # --------------------------------------------------------- --

                # actions which change the token amount do some reporting

                if action in [
                    "assign",
                    "unassign",
                    "enable",
                    "disable",
                    "enroll",
                    "delete",
                    "finishocra2token",
                ]:
                    event = "token_" + action

                    if g.audit.get("source_realm"):
                        source_realms = g.audit.get("source_realm")
                        token_reporting(event, source_realms)

                    target_realms = g.audit.get("realm")
                    token_reporting(event, target_realms)

                    g.audit["action_detail"] += get_token_num_info()

                current_app.audit_obj.log(g.audit)
                db.session.commit()

            return response

        except Exception as acc:
            # the exception, when an abort() is called if forwarded
            log.error("[__after__::%r] webob.exception %r", action, acc)
            return sendError(response, acc, context="__after__")

    def _identify_user(self, params):
        """
        identify the user from the request parameters

        the idea of the processing was derived from the former selfservice
        user identification and authentication:
                lib.user.get_authenticated_user
        and has been adjusted to the need to run the password authentication
        as a seperate step

        :param params: request parameters
        :return: User Object or None
        """

        try:
            username = params["login"]
        except KeyError as exx:
            log.error("Missing Key: %r", exx)
            return None

        realm = params.get("realm", "").strip().lower()

        # if we have an realmbox, we take the user as it is
        # - the realm is always given

        if getRealmBox():
            user = User(username, realm, "")
            if user.exists():
                return user

        # if no realm box is given
        #    and realm is not empty:
        #    - create the user from the values (as we are in auto_assign, etc)
        if realm and realm in getRealms():
            user = User(username, realm, "")
            if user.exists():
                return user

        # if the realm is empty or no realm parameter or realm does not exist
        #     - the user could live in the default realm
        else:
            def_realm = getDefaultRealm()
            if def_realm:
                user = User(username, def_realm, "")
                if user.exists():
                    return user

        # if any explicit realm handling had no success, we end up here
        # with the implicit realm handling:

        login, realm = splitUser(username)
        user = User(login, realm)
        if user.exists():
            return user

        return None

    ##########################################################################
    # authentication hooks

    def auth(self):
        """
        user authentication for example to the remote selfservice

        :param login: login name of the user normaly in the user@realm format
        :param realm: the realm of the user
        :param password: the password for the user authentication
                         which is base32 encoded to seperate the
                         os_passw:pin+otp in case of mfa_login

        :return: {result : {value: bool} }
        :rtype: json dict with bool value
        """

        try:

            param = self.request_params

            # -------------------------------------------------------------- --

            # identify the user

            user = self._identify_user(params=param)
            if not user:
                log.info("User %r not found", param.get("login"))
                g.audit["action_detail"] = "User %r not found" % param.get(
                    "login"
                )
                g.audit["success"] = False
                return sendResult(self.response, False, 0)

            uid = "%s@%s" % (user.login, user.realm)

            self.authUser = user
            request_context["authUser"] = user

            # -------------------------------------------------------------- --

            # extract password

            try:
                password = param["password"]
            except KeyError as exx:

                log.info("Missing password for user %r", uid)
                g.audit["action_detail"] = "Missing password for user %r" % uid
                g.audit["success"] = False
                return sendResult(self.response, False, 0)

            (otp, passw) = password.split(":")
            otp = base64.b32decode(otp)
            passw = base64.b32decode(passw)

            # -------------------------------------------------------------- --

            # check the authentication

            if self.mfa_login:

                res = self._mfa_login_check(user, passw, otp)

            else:

                res = self._default_auth_check(user, passw, otp)

            if not res:

                log.info("User %r failed to authenticate!", uid)
                g.audit["action_detail"] = (
                    "User %r failed to authenticate!" % uid
                )
                g.audit["success"] = False
                return sendResult(self.response, False, 0)

            # -------------------------------------------------------------- --

            log.debug("Successfully authenticated user %s:", uid)

            (cookie_value, expires, expiration) = create_auth_cookie(
                user, self.client
            )

            self.response.set_cookie(
                "userauthcookie",
                value=cookie_value,
                secure=secure_cookie(),
                expires=expires,
            )

            g.audit["action_detail"] = "expires: %s " % expiration
            g.audit["success"] = True

            db.session.commit()
            return sendResult(self.response, True, 0)

        except Exception as exx:

            g.audit["info"] = ("%r" % exx)[:80]
            g.audit["success"] = False

            db.session.rollback()
            return sendError(response, exx)

    def _login_with_cookie(self, cookie, params):
        """
        verify the mfa login second step
        - the credentials have been verified in the first step, so that the
          authentication state is either 'credentials_verified' or
          'challenge_triggered'

        :param cookie: preserving the authentication state
        :param params: the request parameters
        """
        user, _client, auth_state, _state_data = get_cookie_authinfo(cookie)

        if not user:
            raise UserNotFound("no user info in authentication cache")

        request_context["selfservice"] = {"state": auth_state, "user": user}

        if auth_state == "credentials_verified":
            return self._login_with_cookie_credentials(cookie, params)

        elif auth_state == "challenge_triggered":
            return self._login_with_cookie_challenge(cookie, params)

        else:
            raise NotImplementedError("unknown state %r" % auth_state)

    def _login_with_cookie_credentials(self, cookie, params):
        """
        verify the mfa login second step
        - the credentials have been verified in the first step, so that the
          authentication state is 'credentials_verified'

        :param cookie: preserving the authentication state

        :param params: the request parameters
        """

        user, _client, _auth_state, _state_data = get_cookie_authinfo(cookie)

        # -------------------------------------------------------------- --

        otp = params.get("otp", "")
        serial = params.get("serial")

        # in case of a challenge trigger, provide default qr and push settings
        if "data" not in params and "content_type" not in params:
            params["data"] = _(
                "Selfservice Login Request\nUser: {}".format(user.login)
            )
            params["content_type"] = 0

        vh = ValidationHandler()

        if "serial" in params:
            res, reply = vh.checkSerialPass(serial, passw=otp, options=params)
        else:
            res, reply = vh.checkUserPass(user, passw=otp, options=params)

        # -------------------------------------------------------------- --

        # if res is True: success for direct authentication and we can
        # set the cookie for successful authenticated

        if res:
            ret = create_auth_cookie(user, self.client)
            (cookie, expires, _exp) = ret

            self.response.set_cookie(
                "user_selfservice",
                cookie,
                secure=secure_cookie(),
                expires=expires,
            )

            g.audit["info"] = "User %r authenticated from otp" % user

            db.session.commit()
            return sendResult(self.response, res, 0)

        # -------------------------------------------------------------- --

        # if res is False and reply is provided, a challenge was triggered
        # and we set the state 'challenge_triggered'

        if not res and reply:

            if "message" in reply and "://chal/" in reply["message"]:
                reply["img_src"] = create_img_src(reply["message"])

            ret = create_auth_cookie(
                user,
                self.client,
                state="challenge_triggered",
                state_data=reply,
            )
            cookie, expires, expiration = ret

            self.response.set_cookie(
                "user_selfservice",
                cookie,
                secure=secure_cookie(),
                expires=expires,
            )

            g.audit["success"] = False

            # -------------------------------------------------------------- --

            # determine the tokentype and adjust the offline, online reply

            token_type = reply.get("linotp_tokentype")

            # announce available reply channels via reply_mode
            # - online: token supports online mode where the user can
            #   independently answer the challenge via a different channel
            #   without having to enter an OTP.
            # - offline: token supports offline mode where the user needs
            #   to manually enter an OTP.

            reply_mode = ""

            if token_type == "push":
                reply_mode = ["online"]
            elif token_type == "qr":
                reply_mode = ["offline", "online"]
            else:
                reply_mode = ["offline"]

            reply["replyMode"] = reply_mode

            # ------------------------------------------------------------- --

            # add transaction data wrt to the new spec

            if reply.get("img_src"):
                reply["transactionData"] = reply["message"]

            # ------------------------------------------------------------- --

            # care for the messages as it is done with verify

            if token_type == "qr":
                reply["message"] = _("Please scan the provided qr code")

            # ------------------------------------------------------------- --

            # adjust the transactionid to transactionId for api conformance

            if "transactionid" in reply:
                transaction_id = reply["transactionid"]
                del reply["transactionid"]
                reply["transactionId"] = transaction_id

            db.session.commit()
            return sendResult(self.response, False, 0, opt=reply)

        # -------------------------------------------------------------- --

        # if no reply and res is False, the authentication failed

        if not res and not reply:

            db.session.commit()
            return sendResult(self.response, False, 0)

    def _login_with_cookie_challenge(self, cookie, params):
        """
        verify the mfa login second step
        - the credentials have been verified in the first step and a challenge
          has been triggered, so that the authentication state is
          'challenge_triggered'

        :param cookie: preserving the authentication state
        :param params: the request parameters
        """
        user, _client, _auth_state, state_data = get_cookie_authinfo(cookie)

        if not state_data:
            raise Exception("invalid state data")

        # if there has been a challenge triggerd before, we can extract
        # the the transaction info from the cookie cached data

        transid = state_data.get("transactionid")

        if "otp" in params:
            return self._login_with_cookie_challenge_check_otp(
                user, transid, params
            )

        return self._login_with_cookie_challenge_check_status(user, transid)

    def _login_with_cookie_challenge_check_otp(self, user, transid, params):
        """Verify challenge against the otp.

        check if it is a valid otp, we grant access

        state: challenge_tiggered

        :param user: the login user
        :param transid: the transaction id, taken from the cookie context
        :param params: all input parameters
        """

        vh = ValidationHandler()
        res, _reply = vh.check_by_transactionid(
            transid, passw=params["otp"], options={"transactionid": transid}
        )

        if res:
            (cookie, expires, expiration) = create_auth_cookie(
                user, self.client
            )

            self.response.set_cookie(
                "user_selfservice",
                cookie,
                secure=secure_cookie(),
                expires=expires,
            )

            g.audit["action_detail"] = "expires: %s " % expiration
            g.audit["info"] = "%r logged in " % user

        db.session.commit()
        return sendResult(self.response, res, 0)

    def _login_with_cookie_challenge_check_status(self, user, transid):
        """Check status of the login challenge.

        check, if there is no otp in the request, we assume that we have to
        poll for the transaction state. If a valid tan was recieved we grant
        access.

        input state: challenge_tiggered

        :param user: the login user
        :param transid: the transaction id, taken out of the cookie content
        """

        va = ValidationHandler()
        ok, opt = va.check_status(transid=transid, user=user, password="")

        verified = False
        if ok and opt:
            verified = (
                opt.get("transactions", {})
                .get(transid, {})
                .get("valid_tan", False)
            )

        if verified:
            (cookie, expires, expiration) = create_auth_cookie(
                user, self.client
            )

            self.response.set_cookie(
                "user_selfservice",
                cookie,
                secure=secure_cookie(),
                expires=expires,
            )

            g.audit["action_detail"] = "expires: %s " % expiration
            g.audit["info"] = "%r logged in " % user

        detail = get_transaction_detail(transid)

        db.session.commit()
        return sendResult(self.response, verified, opt=detail)

    def _login_with_otp(self, user, passw, param):
        """
        handle login with otp - either if provided directly or delayed

        :param user: User Object of the identified user
        :param password: the password parameter
        :param param: the request parameters
        """

        if not user.checkPass(passw):

            log.info("User %r failed to authenticate!", user)
            g.audit["action_detail"] = "User %r failed to authenticate!" % user
            g.audit["success"] = False

            db.session.commit()
            return sendResult(self.response, False, 0)

        # ------------------------------------------------------------------ --

        # if there is an otp, we can do a direct otp authentication

        otp = param.get("otp", "")
        if otp:

            vh = ValidationHandler()
            res, reply = vh.checkUserPass(user, passw + otp)

            if res:
                log.debug("Successfully authenticated user %r:", user)

                (cookie_value, expires, expiration) = create_auth_cookie(
                    user, self.client
                )

                self.response.set_cookie(
                    "user_selfservice",
                    value=cookie_value,
                    secure=secure_cookie(),
                    expires=expires,
                )

                g.audit["action_detail"] = "expires: %s " % expiration
                g.audit["info"] = "%r logged in " % user

            elif not res and reply:
                log.error("challenge trigger though otp is provided")

            g.audit["success"] = res

            db.session.commit()
            return sendResult(self.response, res, 0, reply)

        # ------------------------------------------------------------------ --

        # last step - we have no otp but mfa_login request - so we
        # create the 'credentials_verified state'

        (cookie_value, expires, expiration) = create_auth_cookie(
            user, self.client, state="credentials_verified"
        )

        self.response.set_cookie(
            "user_selfservice",
            value=cookie_value,
            secure=secure_cookie(),
            expires=expires,
        )

        tokenList = getTokenForUser(
            self.authUser, active=True, exclude_rollout=False
        )

        reply = {
            "message": "credential verified - "
            "additional authentication parameter required",
            "tokenList": tokenList,
        }

        g.audit["action_detail"] = "expires: %s " % expiration
        g.audit["info"] = "%r credentials verified" % user

        g.audit["success"] = True
        db.session.commit()

        return sendResult(self.response, False, 0, opt=reply)

    def _login_with_password_only(self, user, password):
        """
        simple old password authentication

        :param user: the identified user
        :param password: the password
        """

        res = user.checkPass(password)

        if res:
            (cookie_value, expires, _expiration) = create_auth_cookie(
                user, self.client
            )

            self.response.set_cookie(
                "user_selfservice",
                value=cookie_value,
                secure=secure_cookie(),
                expires=expires,
            )

        g.audit["success"] = res
        g.audit["info"] = "%r logged in " % user

        db.session.commit()

        return sendResult(self.response, res, 0)

    def login(self):
        """
        user authentication for example to the remote selfservice

        parameters:

            login: login name of the user normaly in the user@realm format
            realm: the realm of the user
            password: the password for the user authentication
            otp: optional the otp

        return: {result : {value: bool} }
        """

        try:
            param = self.request_params.copy()

            # -------------------------------------------------------------- --

            # the new selfservice provides the parameter 'username' instead of
            # 'login'. As all lower llayers expect 'login' we switch the case

            if "login" not in param and "username" in param:
                param["login"] = param["username"]
                del param["username"]

            # -------------------------------------------------------------- --

            # if this is an pre-authenticated login we continue
            # with the authentication states

            user_selfservice_cookie = request.cookies.get("user_selfservice")

            # check if this cookie is still valid

            auth_info = get_cookie_authinfo(user_selfservice_cookie)

            if auth_info[0] and check_session(
                request, auth_info[0], auth_info[1]
            ):

                return self._login_with_cookie(user_selfservice_cookie, param)

            # if there is a cookie but could not be found in cache
            # we remove the out dated client cookie

            if user_selfservice_cookie and not auth_info[0]:

                self.response.delete_cookie("user_selfservice")

            # -------------------------------------------------------------- --

            # identify the user

            user = self._identify_user(params=param)
            if not user:
                raise UserNotFound("user %r not found!" % param.get("login"))

            self.authUser = user
            request_context["authUser"] = user

            # -------------------------------------------------------------- --

            password = param["password"]

            if self.mfa_login:

                # allow the mfa login for users that have no token till now
                # if the policy 'mfa_passOnNoToken' is defined with password
                # only

                tokenArray = getTokenForUser(self.authUser)

                policy = get_client_policy(
                    client=self.client,
                    scope="selfservice",
                    action="mfa_passOnNoToken",
                    userObj=user,
                    active_only=True,
                )

                if policy and not tokenArray:

                    return self._login_with_password_only(user, password)

                return self._login_with_otp(user, password, param)

            else:

                return self._login_with_password_only(user, password)

            # -------------------------------------------------------------- --

        except (Unauthorized, Forbidden) as exx:

            log.error("userservice login failed: %r", exx)

            g.audit["info"] = ("%r" % exx)[:80]
            g.audit["success"] = False

            raise exx

        except Exception as exx:

            log.error("userservice login failed: %r", exx)

            g.audit["info"] = ("%r" % exx)[:80]
            g.audit["success"] = False

            db.session.rollback()
            return sendResult(self.response, False, 0)

    def _default_auth_check(self, user, password, otp=None):
        """
        the former selfservice login controll:
         check for username and os_pass

        :param user: user object
        :param password: the expected os_password
        :param otp: not used

        :return: bool
        """
        (uid, _resolver, resolver_class) = getUserId(user)
        r_obj = getResolverObject(resolver_class)
        res = r_obj.checkPass(uid, password)
        return res

    def _mfa_login_check(self, user, password, otp):
        """
        secure auth requires the os password and the otp (pin+otp)
        - secure auth supports autoassignement, where the user logs in with
                      os_password and only the otp value. If user has no token,
                      a token with a matching otp in the window is searched
        - secure auth supports autoenrollment, where a user with no token will
                      get automaticaly enrolled one token.

        :param user: user object
        :param password: the os_password
        :param otp: empty (for autoenrollment),
                    otp value only for auto assignment or
                    pin+otp for standard authentication (respects
                                                            otppin ploicy)

        :return: bool
        """
        ret = False

        passwd_match = self._default_auth_check(user, password, otp)

        if passwd_match:
            toks = getTokenForUser(user, active=True)

            # if user has no token, we check for auto assigneing one to him
            if len(toks) == 0:
                th = TokenHandler()

                # if no token and otp, we might do an auto assign
                if self.autoassign and otp:
                    ret = th.auto_assignToken(password + otp, user)

                # if no token no otp, we might trigger an aouto enroll
                elif self.autoenroll and not otp:
                    (auto_enroll_return, reply) = th.auto_enrollToken(
                        password, user
                    )
                    if auto_enroll_return is False:
                        error = "autoenroll: %r" % reply.get("error", "")
                        raise Exception(error)
                    # we always have to return a false, as we have
                    # a challenge tiggered
                    ret = False

            # user has at least one token, so we do a check on pin + otp
            else:
                vh = ValidationHandler()
                (ret, _reply) = vh.checkUserPass(user, otp)
        return ret

    def usertokenlist(self):
        """
        This returns a tokenlist as html output
        """

        try:
            if self.request_params.get("active", "").lower() in ["true"]:
                active = True
            elif self.request_params.get("active", "").lower() in ["false"]:
                active = True
            else:
                active = None

            tokenArray = getTokenForUser(
                self.authUser, active=active, exclude_rollout=False
            )

            db.session.commit()
            return sendResult(self.response, tokenArray, 0)

        except Exception as exx:
            log.error("failed with error: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    def userinfo(self):
        """
        hook for the auth, which requests additional user info
        """

        try:

            uinfo = get_userinfo(self.authUser)

            g.audit["success"] = True

            db.session.commit()
            return sendResult(self.response, uinfo, 0)

        except Exception as exx:
            db.session.rollback()
            error = "error (%r) " % exx
            log.error(error)
            return "<pre>%s</pre>" % error

        finally:
            db.session.close()

    def logout(self):
        """
        hook for the auth, which requests additional user info
        """

        try:

            cookie = request.cookies.get("user_selfservice")
            remove_auth_cookie(cookie)
            self.response.delete_cookie(key="user_selfservice")

            g.audit["success"] = True

            db.session.commit()
            return sendResult(self.response, True, 0)

        except Exception as exx:
            db.session.rollback()
            error = "error (%r) " % exx
            log.error(error)
            return "<pre>%s</pre>" % error

        finally:
            log.debug("done")

    ##########################################################################
    # context setup functions
    def pre_context(self):
        """
        This is the authentication to self service
        If you want to do ANYTHING with selfservice, you need to be
        authenticated. The _before_ is executed before any other function
        in this controller.
        """
        try:
            pre_context = get_pre_context(self.client)
            return sendResult(self.response, True, opt=pre_context)

        except Exception as exx:
            log.error("pre_context failed with error: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    def context(self):
        """
        This is the authentication to self service
        If you want to do ANYTHING with selfservice, you need to be
        authenticated. The _before_ is executed before any other function
        in this controller.
        """

        try:
            context = get_context(config, self.authUser, self.client)
            return sendResult(self.response, True, opt=context)

        except Exception as e:
            log.error("[context] failed with error: %r", e)
            db.session.rollback()
            return sendError(response, e)

    # action hooks for the js methods ########################################

    def enable(self):
        """
        enables a token or all tokens of a user

        as this is a controller method, the parameters are taken from
        BaseController.request_params

        :param serial: serial number of the token *required
        :param user: username in format user@realm *required

        :return: a linotp json doc with result {u'status': True, u'value': 2}

        """
        param = self.request_params
        res = {}
        log.debug("remoteservice enable to enable/disable a token")

        try:
            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            # check selfservice authorization
            checkPolicyPre(
                "selfservice", "userenable", param, authUser=self.authUser
            )
            th = TokenHandler()
            if th.isTokenOwner(serial, self.authUser):
                log.info(
                    "[userenable] user %s@%s is enabling his token with "
                    "serial %s.",
                    self.authUser.login,
                    self.authUser.realm,
                    serial,
                )
                ret = th.enableToken(True, None, serial)
                res["enable token"] = ret

                g.audit["realm"] = self.authUser.realm
                g.audit["success"] = ret

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pe:
            log.error("[enable] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as e:
            log.error("[enable] failed: %r", e)
            db.session.rollback()
            return sendError(response, e, 1)

    ########################################################
    def disable(self):
        """
        disables a token

        as this is a controller method, the parameters are taken from
        BaseController.request_params

        :param serial: serial number of the token *required
        :param user: username in format user@realm *required

        :return: a linotp json doc with result {u'status': True, u'value': 2}

        """
        param = self.request_params
        res = {}
        log.debug("remoteservice disable a token")

        try:

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            # check selfservice authorization
            checkPolicyPre(
                "selfservice", "userdisable", param, authUser=self.authUser
            )
            th = TokenHandler()
            if th.isTokenOwner(serial, self.authUser):
                log.info(
                    "user %s@%s is disabling his token with serial %s.",
                    self.authUser.login,
                    self.authUser.realm,
                    serial,
                )
                ret = th.enableToken(False, None, serial)
                res["disable token"] = ret

                g.audit["realm"] = self.authUser.realm
                g.audit["success"] = ret

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pe:
            log.error("policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as e:
            log.error("failed: %r", e)
            db.session.rollback()
            return sendError(response, e, 1)

    def delete(self):
        """
        This is the internal delete token function that is called from within
        the self service portal. The user is only allowed to delete token,
        that belong to him.
        """
        param = self.request_params
        res = {}

        try:
            # check selfservice authorization
            checkPolicyPre("selfservice", "userdelete", param, self.authUser)

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            th = TokenHandler()
            if th.isTokenOwner(serial, self.authUser):
                log.info(
                    "[userdelete] user %s@%s is deleting his token with "
                    "serial %s.",
                    self.authUser.login,
                    self.authUser.realm,
                    serial,
                )
                ret = th.removeToken(serial=serial)
                res["delete token"] = ret

                g.audit["realm"] = self.authUser.realm
                g.audit["success"] = ret

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pe:
            log.error("[userdelete] policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as e:
            log.error(
                "[userdelete] deleting token %s of user %s failed!",
                serial,
                c.user,
            )
            db.session.rollback()
            return sendError(response, e, 1)

    def reset(self):
        """
        This internally resets the failcounter of the given token.
        """
        res = {}
        param = self.request_params
        serial = None

        try:
            checkPolicyPre("selfservice", "userreset", param, self.authUser)
            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            th = TokenHandler()
            if True == th.isTokenOwner(serial, self.authUser):
                log.info(
                    "[userreset] user %s@%s is resetting the failcounter"
                    " of his token with serial %s",
                    self.authUser.login,
                    self.authUser.realm,
                    serial,
                )
                ret = resetToken(serial=serial)
                res["reset Failcounter"] = ret

                g.audit["success"] = ret

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as e:
            log.error("error resetting token with serial %s: %r", serial, e)
            db.session.rollback()
            return sendError(response, e, 1)

    def unassign(self):
        """
        This is the internal unassign function that is called from within
        the self service portal. The user is only allowed to unassign token,
        that belong to him.
        """
        param = self.request_params
        res = {}

        try:
            # check selfservice authorization
            checkPolicyPre("selfservice", "userunassign", param, self.authUser)

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            upin = param.get("pin", None)

            th = TokenHandler()
            if True == th.isTokenOwner(serial, self.authUser):
                log.info(
                    "user %s@%s is unassigning his token with serial %s.",
                    self.authUser.login,
                    self.authUser.realm,
                    serial,
                )

                ret = th.unassignToken(serial, None, upin)
                res["unassign token"] = ret

                g.audit["success"] = ret
                g.audit["realm"] = self.authUser.realm

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as e:
            log.error(
                "unassigning token %s of user %s failed! %r", serial, c.user, e
            )
            db.session.rollback()
            return sendError(response, e, 1)

    def setpin(self):
        """
        When the user hits the set pin button, this function is called.
        """
        res = {}
        param = self.request_params

        # # if there is a pin
        try:
            # check selfservice authorization
            checkPolicyPre("selfservice", "usersetpin", param, self.authUser)

            try:
                userPin = param["userpin"]
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            th = TokenHandler()
            if True == th.isTokenOwner(serial, self.authUser):
                log.info(
                    "user %s@%s is setting the OTP PIN "
                    "for token with serial %s",
                    self.authUser.login,
                    self.authUser.realm,
                    serial,
                )

                check_res = checkOTPPINPolicy(userPin, self.authUser)

                if not check_res["success"]:
                    log.warning(
                        "Setting of OTP PIN for Token %s"
                        " by user %s failed: %s",
                        serial,
                        self.authUser.login,
                        check_res["error"],
                    )

                    return sendError(
                        response, _("Error: %s") % check_res["error"]
                    )

                if 1 == getOTPPINEncrypt(serial=serial, user=self.authUser):
                    param["encryptpin"] = "True"
                ret = setPin(userPin, None, serial, param)
                res["set userpin"] = ret

                g.audit["success"] = ret

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pex:
            log.error("policy failed: %r", pex)
            db.session.rollback()
            return sendError(response, pex, 1)

        except Exception as exx:
            log.error("Error setting OTP PIN: %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    def setmpin(self):
        """
        When the user hits the set pin button, this function is called.
        """
        res = {}
        param = self.request_params
        # # if there is a pin
        try:
            # check selfservice authorization
            checkPolicyPre("selfservice", "usersetmpin", param, self.authUser)
            try:
                pin = param["pin"]
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            th = TokenHandler()
            if True == th.isTokenOwner(serial, self.authUser):
                log.info(
                    "user %s@%s is setting the mOTP PIN"
                    " for token with serial %s",
                    self.authUser.login,
                    self.authUser.realm,
                    serial,
                )
                ret = setPinUser(pin, serial)
                res["set userpin"] = ret

                g.audit["success"] = ret

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pex:
            log.error("policy failed: %r", pex)
            db.session.rollback()
            return sendError(response, pex, 1)

        except Exception as exx:
            log.error("Error setting the mOTP PIN %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    def resync(self):
        """
        This is the internal resync function that is called from within
        the self service portal
        """

        res = {}
        param = self.request_params
        serial = "N/A"

        try:
            # check selfservice authorization
            checkPolicyPre("selfservice", "userresync", param, self.authUser)

            try:
                serial = param["serial"]
                otp1 = param["otp1"]
                otp2 = param["otp2"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            th = TokenHandler()
            if True == th.isTokenOwner(serial, self.authUser):
                log.info(
                    "user %s@%s is resyncing his token with serial %s",
                    self.authUser.login,
                    self.authUser.realm,
                    serial,
                )
                ret = th.resyncToken(otp1, otp2, None, serial)
                res["resync Token"] = ret

                g.audit["success"] = ret

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as e:
            log.error("error resyncing token with serial %s:%r", serial, e)
            db.session.rollback()
            return sendError(response, e, 1)

    def verify(self):
        """
        verify a token, identified by a serial number

        after a successful authentication and a valid session, the idenitfied
        user can verify his enrolled tokens. To verify the token, the token
        serial number is used.

        for direct authenticating tokens like hmac and totp, the parameter otp
        is required:

        a valid verification request example would be:

              https://.../userservice/verify?serial=token_serial&otp=123456&session=...

        replied by the usual /validate/check json response

        {
             "jsonrpc": "2.XX",
               "result": {
                  "status": true,
                  "value": true
               },
               "version": "LinOTP 2.XX",
               "id": 1
        }
        """

        try:
            params = self.request_params

            checkPolicyPre("selfservice", "userverify", params, self.authUser)

            # -------------------------------------------------------------- --

            # setup - get the tokens from the serial or transactionid/state

            transaction_id = params.get("transactionid", params.get("state"))
            serial = params.get("serial")

            if not serial and not transaction_id:
                raise ParameterError(
                    "Missing parameter: serial or transactionid"
                )

            # -------------------------------------------------------------- --

            # check for invalid params

            supported_params = ["serial", "transactionid", "otp", "session"]
            unknown_params = [p for p in params if p not in supported_params]
            if len(unknown_params) > 0:
                raise ParameterError(
                    "unsupported parameters: %r" % unknown_params
                )

            # -------------------------------------------------------------- --

            # identify the affected tokens
            challenge = None

            if transaction_id:
                reply = Challenges.get_challenges(transid=transaction_id)
                _expired_challenges, valid_challenges = reply

                if _expired_challenges:
                    raise Exception("challenge already expired!")

                if not valid_challenges:
                    raise Exception("no valid challenge found!")

                if len(valid_challenges) != 1:
                    raise Exception(
                        "Could not uniquely identify challenge for "
                        "transaction id {} ".format(transaction_id)
                    )

                challenge = valid_challenges[0]

                serials = [c.tokenserial for c in valid_challenges]
                serials = list(set(serials))  # remove duplicates

                tokens = []
                for serial in serials:
                    tokens.extend(getTokens4UserOrSerial(serial=serial))

            elif serial:
                tokens = getTokens4UserOrSerial(serial=serial)

            # -------------------------------------------------------------- --

            # now there are all tokens identified either by serial or by
            # transaction id, we can do the sanity checks that there is only
            # one token which belongs to the authenticated user

            if len(tokens) == 0:
                raise Exception("no token found!")

            if len(tokens) > 1:
                raise Exception("multiple tokens found!")

            token = tokens[0]

            th = TokenHandler()
            if not th.isTokenOwner(token.getSerial(), self.authUser):
                raise Exception("User is not token owner")

            # -------------------------------------------------------------- --

            # determine which action is meant

            action = None

            # verify the transaction if we have an otp
            if transaction_id and "otp" in params:
                action = "verify transaction"

            # only a transaction id, so we query the transaction status
            elif transaction_id and "otp" not in params:
                action = "query transaction"

            # if no transaction id but otp, we directly verify the otp
            elif not transaction_id and "otp" in params:
                action = "verify otp"

            # no transaction id and no OTP - trigger a challenge
            elif not transaction_id and "otp" not in params:
                action = "trigger challenge"

            # -------------------------------------------------------------- --

            if action == "verify transaction":
                vh = ValidationHandler()
                (res, _opt) = vh.check_by_transactionid(
                    transid=transaction_id, passw=params["otp"], options=params
                )

                db.session.commit()
                return sendResult(self.response, res)

            # -------------------------------------------------------------- --

            elif action == "query transaction":

                detail = get_transaction_detail(transaction_id)

                db.session.commit()
                return sendResult(
                    self.response, detail.get("valid_tan", False), opt=detail
                )

            # -------------------------------------------------------------- --

            elif action == "verify otp":

                vh = ValidationHandler()
                (res, _opt) = vh.checkUserPass(
                    self.authUser, passw=params["otp"], options=params
                )

                db.session.commit()
                return sendResult(self.response, res)

            # -------------------------------------------------------------- --

            # challenge request:

            elif action == "trigger challenge":

                transaction_data = None
                transaction_id = None

                # 'authenticate': default for non-challenge response tokens
                #                 like ['hmac', 'totp', 'motp']

                if "authenticate" in token.mode:
                    message = _("Please enter your otp")

                # 'challenge': tokens that do not have a direct authentication
                #              mode need a challenge to be tested

                elif "challenge" in token.mode:
                    data = _(
                        "SelfService token test\n\nToken: {0}\n"
                        "Serial: {1}\nUser: {2}"
                    ).format(
                        token.type,
                        token.token.LinOtpTokenSerialnumber,
                        self.authUser.login,
                    )

                    options = {"content_type": "0", "data": data}

                    res, reply = Challenges.create_challenge(
                        token, options=options
                    )
                    if not res:
                        raise Exception(
                            "failed to trigger challenge {:r}".format(reply)
                        )

                    if token.type == "qr":
                        transaction_data = reply["message"]
                        message = _("Please scan the provided qr code")

                    else:
                        message = reply["message"]

                    transaction_id = reply["transactionid"]

                else:
                    raise Exception("unsupported token mode")

                # announce available reply channels via reply_mode
                # - online: token supports online mode where the user can
                #   independently answer the challenge via a different channel
                #   without having to enter an OTP.
                # - offline: token supports offline mode where the user needs
                #   to manually enter an OTP.

                if token.type == "push":
                    reply_mode = ["online"]
                elif token.type == "qr":
                    reply_mode = ["offline", "online"]
                else:
                    reply_mode = ["offline"]

                # ---------------------------------------------------------- --

                # create the challenge detail response

                detail_response = {
                    "message": message,  # localized user facing message
                    "replyMode": reply_mode,
                }

                if transaction_id:
                    detail_response["transactionId"] = transaction_id

                if transaction_data:
                    detail_response["transactionData"] = transaction_data

                # ---------------------------------------------------------- --

                # close down the session and submit the result

                db.session.commit()
                return sendResult(self.response, False, opt=detail_response)

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe)

        except Exception as exx:
            g.audit["success"] = False
            log.error("error verifying token with serial %s: %r", serial, exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    def assign(self):
        """
        This is the internal assign function that is called from within
        the self service portal
        """
        param = self.request_params
        res = {}

        try:

            description = param.get("description", None)
            upin = param.get("pin", None)

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            # check selfservice authorization
            checkPolicyPre("selfservice", "userassign", param, self.authUser)

            # check if token is in another realm
            realm_list = getTokenRealms(serial)
            if not self.authUser.realm.lower() in realm_list and len(
                realm_list
            ):
                # if the token is assigned to realms, then the user must be in
                # one of the realms, otherwise the token can not be assigned
                raise Exception(
                    _(
                        "The token you want to assign is "
                        "not contained in your realm!"
                    )
                )
            th = TokenHandler()

            if th.hasOwner(serial):
                raise Exception(
                    _("The token is already assigned to another user.")
                )

            # -------------------------------------------------------------- --

            # assign  token to user

            log.info(
                "user %s@%s is assign the token with serial %s to himself.",
                self.authUser.login,
                self.authUser.realm,
                serial,
            )

            ret_assign = th.assignToken(serial, self.authUser, upin)

            # -------------------------------------------------------------- --

            # if we have a description, we set it to the token

            if ret_assign and description:

                log.info("set description of token %s", serial)
                th.setDescription(description, serial=serial)

            # -------------------------------------------------------------- --

            res["assign token"] = ret_assign

            g.audit["realm"] = self.authUser.realm
            g.audit["success"] = ret_assign

            checkPolicyPost("selfservice", "userassign", param, self.authUser)

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pe:
            log.error("[userassign] policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[userassign] token assignment failed! %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    def getSerialByOtp(self):
        """
         method:
            selfservice/usergetSerialByOtp

        description:
            searches for the token, that generates the given OTP value.
            The search can be restricted by several critterions
            This method only searches tokens in the realm of the user
            and tokens that are not assigned!

        arguments:
            otp      - required. Will search for the token, that produces
                       this OTP value
            type     - optional, will only search in tokens of type

        returns:
            a json result with the serial


        exception:
            if an error occurs an exception is serialized and returned

        """
        param = self.request_params
        res = {}
        try:
            # check selfservice authorization
            checkPolicyPre(
                "selfservice", "usergetserialbyotp", param, self.authUser
            )
            try:
                otp = param["otp"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            ttype = param.get("type", None)

            g.audit["token_type"] = ttype
            th = TokenHandler()
            serial, _username, _resolverClass = th.get_serial_by_otp(
                None, otp, 10, typ=ttype, realm=self.authUser.realm, assigned=0
            )
            res = {"serial": serial}

            g.audit["success"] = 1
            g.audit["serial"] = serial

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("token getSerialByOtp failed! %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    def enroll(self):
        """Enroll a token.

        Remarks:
            Depending on the token type more parameters have to be provided
            as http parameters

        :param type: one of (hmac, totp, pw, ...)
        """
        response_detail = {}
        param = self.request_params.copy()

        try:

            try:
                tok_type = param["type"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            # check selfservice authorization
            checkPolicyPre("selfservice", "userinit", param, self.authUser)

            serial = param.get("serial", None)
            prefix = param.get("prefix", None)

            # --------------------------------------------------------- --

            # enrollment of hotp (hmac) or totp token

            if tok_type in ["hmac", "totp"]:
                if "otpkey" not in param:
                    param["genkey"] = param.get("genkey", "1")

            if tok_type == "hmac":

                # --------------------------------------------------------- --

                # query for hmac_otplen

                hmac_otplen = get_selfservice_action_value(
                    "hmac_otplen", user=self.authUser, default=6
                )

                param["otplen"] = param.get("otplen", hmac_otplen)

                # --------------------------------------------------------- --

                # query for hashlib

                hmac_hashlib = get_selfservice_action_value(
                    "hmac_hashlib", user=self.authUser, default=1
                )

                param["hashlib"] = param.get(
                    "hashlib", HASHLIB_MAP[hmac_hashlib]
                )

            elif tok_type == "totp":

                # --------------------------------------------------------- --

                # query for timestep

                totp_timestep = get_selfservice_action_value(
                    "totp_timestep", user=self.authUser, default=30
                )

                param["timeStep"] = param.get("timeStep", totp_timestep)

                # --------------------------------------------------------- --

                # query for totp_otplen

                totp_otplen = get_selfservice_action_value(
                    "totp_otplen", user=self.authUser, default=6
                )

                param["otplen"] = param.get("totp_otplen", totp_otplen)

                # --------------------------------------------------------- --

                # query for totp hashlib

                totp_hashlib = get_selfservice_action_value(
                    "totp_hashlib", user=self.authUser, default=1
                )

                param["hashlib"] = param.get(
                    "totp_hashlib", HASHLIB_MAP[totp_hashlib]
                )

            th = TokenHandler()
            if not serial:
                serial = th.genSerial(tok_type, prefix)
                param["serial"] = serial

            desc = param.get("description", "")
            otppin = param.get("otppin")

            log.info(
                "[userinit] initialize a token with serial %s "
                "and type %s by user %s@%s",
                serial,
                tok_type,
                self.authUser.login,
                self.authUser.realm,
            )

            log.debug(
                "[userinit] Initializing the token serial: %s,"
                " desc: %s, otppin: %s for user %s @ %s.",
                serial,
                desc,
                otppin,
                self.authUser.login,
                self.authUser.realm,
            )
            log.debug(param)

            # extend the interface by parameters, so that decisssion could
            # be made in the token update method
            param["::scope::"] = {"selfservice": True, "user": self.authUser}

            (ret, tokenObj) = th.initToken(param, self.authUser)
            if tokenObj is not None and hasattr(tokenObj, "getInfo"):
                info = tokenObj.getInfo()
                response_detail.update(info)

            # result enrichment - if the token is sucessfully created,
            # some processing info is added to the result document,
            #  e.g. the otpkey :-) as qr code
            initDetail = tokenObj.getInitDetail(param, self.authUser)
            response_detail.update(initDetail)

            # -------------------------------------------------------------- --

            g.audit["serial"] = response_detail.get("serial", "")
            g.audit["success"] = ret
            g.audit["user"] = self.authUser.login
            g.audit["realm"] = self.authUser.realm

            g.audit["success"] = ret

            # -------------------------------------------------------------- --

            # in the checkPolicyPost for selfservice, the serial is used

            if "serial" not in param:
                param["serial"] = response_detail.get("serial", "")

            # -------------------------------------------------------------- --

            checkPolicyPost("selfservice", "enroll", param, user=self.authUser)

            db.session.commit()

            # # finally we render the info as qr image, if the qr parameter
            # # is provided and if the token supports this
            if "qr" in param and tokenObj is not None:
                (rdata, hparam) = tokenObj.getQRImageData(response_detail)
                hparam.update(response_detail)
                hparam["qr"] = param.get("qr") or "html"
                return sendQRImageResult(response, rdata, hparam)
            else:
                return sendResult(self.response, ret, opt=response_detail)

        except PolicyException as pe:
            log.error("[userinit] policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as e:
            log.error("[userinit] token initialization failed! %r", e)
            db.session.rollback()
            return sendError(response, e, 1)

    def webprovision(self):
        """
        This function is called, when the create OATHtoken button is hit.
        This is used for web provisioning. See:
            http://code.google.com/p/oathtoken/wiki/WebProvisioning
            and
            http://code.google.com/p/google-authenticator/wiki/KeyUriFormat

        in param:
            type: valid values are "oathtoken" and "googleauthenticator" and
                        "googleauthenticator_time"

            description: string containing a description for the token

        It returns the data and the URL containing the HMAC key
        """
        log.debug("[userwebprovision] calling function")
        param = self.request_params.copy()

        valid_tokens = [
            "googleauthenticator",
            "googleauthenticator_time",
            "oathtoken",
            "ocra2",
        ]

        try:
            ret = {}
            ret1 = False

            typ = param["type"]

            if typ not in [
                "oathtoken",
                "googleauthenticator",
                "googleauthenticator_time",
                "ocra2",
            ]:
                raise Exception(
                    "Unsupported token type: valid types are %s. "
                    "You provided %s" % (", ".join(valid_tokens), typ)
                )

            # check selfservice authorization
            checkPolicyPre(
                "selfservice", "userwebprovision", param, self.authUser
            )

            # -------------------------------------------------------------- --

            # handle description parameter

            description = param.get("description")

            # -------------------------------------------------------------- --

            typ = param["type"]
            t_type = "hmac"

            serial = param.get("serial", None)
            prefix = param.get("prefix", None)

            # date = datetime.datetime.now().strftime("%y%m%d%H%M%S")
            # rNum = random.randrange(1000, 9999)
            th = TokenHandler()

            if typ.lower() == "oathtoken":
                t_type = "hmac"

                if description is None:
                    description = "OATHtoken web provisioning"

                if prefix is None:
                    prefix = "LSAO"
                if serial is None:
                    serial = th.genSerial(t_type, prefix)

                # deal: 32 byte. We could use 20 bytes.
                # we must take care, that the url is not longer than 119 chars.
                # otherwise qrcode.js will fail.Change to 32!
                # Usually the URL is 106 bytes long
                otpkey = generate_otpkey(20)

                log.debug(
                    "[userwebprovision] Initializing the token serial:"
                    " %s, desc: %s for user %s @ %s.",
                    serial,
                    description,
                    self.authUser.login,
                    self.authUser.realm,
                )

                (ret1, _tokenObj) = th.initToken(
                    {
                        "type": t_type,
                        "serial": serial,
                        "description": description,
                        "otpkey": otpkey,
                        "otplen": 6,
                        "timeStep": 30,
                        "timeWindow": 180,
                        "hashlib": "sha1",
                    },
                    self.authUser,
                )

                if ret1:
                    url = create_oathtoken_url(
                        self.authUser.login,
                        self.authUser.realm,
                        otpkey,
                        serial=serial,
                    )
                    ret = {
                        "url": url,
                        "img": create_img(url, width=300, alt=serial),
                        "key": otpkey,
                        "name": serial,
                        "serial": serial,
                        "timeBased": False,
                        "counter": 0,
                        "numDigits": 6,
                        "lockdown": True,
                    }

            elif typ.lower() in [
                "googleauthenticator",
                "googleauthenticator_time",
            ]:

                if description is None:
                    description = "Google Authenticator web prov"

                # ideal: 32 byte.
                otpkey = generate_otpkey(32)
                t_type = "hmac"
                if typ.lower() == "googleauthenticator_time":
                    t_type = "totp"

                if prefix is None:
                    prefix = "LSGO"
                if serial is None:
                    serial = th.genSerial(t_type, prefix)

                log.debug(
                    "Initializing the token serial: "
                    "%s, description: %s for user %s @ %s.",
                    serial,
                    description,
                    self.authUser.login,
                    self.authUser.realm,
                )

                (ret1, _tokenObj) = th.initToken(
                    {
                        "type": t_type,
                        "serial": serial,
                        "otplen": 6,
                        "description": description,
                        "otpkey": otpkey,
                        "timeStep": 30,
                        "timeWindow": 180,
                        "hashlib": "sha1",
                    },
                    self.authUser,
                )

                if ret1:
                    pparam = {
                        "user.login": self.authUser.login,
                        "user.realm": self.authUser.realm,
                        "otpkey": otpkey,
                        "serial": serial,
                        "type": t_type,
                        "description": description,
                    }
                    url = create_google_authenticator(
                        pparam, user=self.authUser
                    )
                    label = "%s@%s" % (
                        self.authUser.login,
                        self.authUser.realm,
                    )
                    ret = {
                        "url": url,
                        "img": create_img(url, width=300, alt=serial),
                        "key": otpkey,
                        "label": label,
                        "serial": serial,
                        "counter": 0,
                        "digits": 6,
                    }
            else:
                return sendError(
                    response,
                    _(
                        "valid types are 'oathtoken' and 'googleauthenticator' and "
                        "'googleauthenticator_time'. You provided %s"
                    )
                    % typ,
                )

            g.audit["serial"] = serial
            # the Google and OATH are always HMAC; sometimes (FUTURE) totp"
            g.audit["token_type"] = t_type
            g.audit["success"] = ret1
            param["serial"] = serial

            checkPolicyPost("selfservice", "enroll", param, user=self.authUser)

            db.session.commit()
            return sendResult(
                self.response,
                {"init": ret1, "setpin": False, "oathtoken": ret},
            )

        except PolicyException as pe:
            log.error("[userwebprovision] policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error(
                "[userwebprovision] token initialization failed! %r", exx
            )
            db.session.rollback()
            return sendError(response, exx, 1)

    def getmultiotp(self):
        """
        Using this function the user may receive OTP values for his own tokens.

        method:
            selfservice/getmultiotp

        arguments:
            serial  - the serial number of the token
            count   - number of otp values to return
            curTime - used ONLY for internal testing: datetime.datetime object

        returns:
            JSON response
        """

        getotp_active = boolean(getFromConfig("linotpGetotp.active", False))
        if not getotp_active:
            return sendError(response, _("getotp is not activated."), 0)

        param = self.request_params
        ret = {}

        try:
            try:
                serial = param["serial"]
                count = int(param["count"])
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            curTime = param.get("curTime", None)

            th = TokenHandler()
            if True != th.isTokenOwner(serial, self.authUser):
                error = _("The serial %s does not belong to user %s@%s") % (
                    serial,
                    self.authUser.login,
                    self.authUser.realm,
                )
                log.error(error)
                return sendError(response, error, 1)

            max_count = checkPolicyPre(
                "selfservice", "max_count", param, self.authUser
            )
            log.debug("checkpolicypre returned %s", max_count)

            if count > max_count:
                count = max_count

            log.debug(
                "[usergetmultiotp] retrieving OTP value for token %s", serial
            )
            ret = get_multi_otp(serial, count=int(count), curTime=curTime)
            if ret["result"] is False and max_count == -1:
                ret["error"] = "%s - %s" % (
                    ret["error"],
                    _("see policy definition."),
                )

            ret["serial"] = serial
            g.audit["success"] = True

            db.session.commit()
            return sendResult(self.response, ret, 0)

        except PolicyException as pe:
            log.error("[usergetmultiotp] policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as e:
            log.error("[usergetmultiotp] gettoken/getmultiotp failed: %r", e)
            db.session.rollback()
            return sendError(
                response, _("selfservice/usergetmultiotp failed: %r") % e, 0
            )

    def history(self):
        """
        This returns the list of the tokenactions of this user
        It returns the audit information for the given search pattern

        method:
            selfservice/userhistory

        arguments:
            key, value pairs as search patterns.

            or: Usually the key=values will be locally AND concatenated.
                it a parameter or=true is passed, the filters will be OR
                concatenated.

            The Flexigrid provides us the following parameters:
                ('page', u'1'), ('rp', u'100'),
                ('sortname', u'number'),
                ('sortorder', u'asc'),
                ('query', u''), ('qtype', u'serial')]
        returns:
            JSON response
        """

        param = self.request_params
        res = {}

        try:
            log.debug("params: %r", param)
            checkPolicyPre("selfservice", "userhistory", param, self.authUser)

            lines, total, page = audit_search(
                param,
                user=self.authUser,
                columns=[
                    "date",
                    "action",
                    "success",
                    "serial",
                    "token_type",
                    "administrator",
                    "action_detail",
                    "info",
                ],
            )

            response.content_type = "application/json"

            if not total:
                total = len(lines)

            res = {"page": page, "total": total, "rows": lines}

            g.audit["success"] = True

            db.session.commit()
            return json.dumps(res, indent=3)

        except PolicyException as pe:
            log.error("[search] policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[search] audit/search failed: %r", exx)
            db.session.rollback()
            return sendError(
                response, _("audit/search failed: %s") % str(exx), 0
            )

    def activateocratoken(self):
        """
        activateocratoken - called from the selfservice web ui to activate the  OCRA token

        :param type:    'ocra2'
        :type type:     string
        :param serial:    serial number of the token
        :type  serial:    string
        :param activationcode: the calculated activation code
        :type  activationcode: string - activationcode format

        :return:    dict about the token
        :rtype:     { 'activate': True, 'ocratoken' : {
                        'url' :     url,
                        'img' :     '<img />',
                        'label' :   "%s@%s" % (self.authUser.login,
                                                   self.authUser.realm),
                        'serial' :  serial,
                    }  }
        """
        param = self.request_params
        ret = {}

        try:
            # check selfservice authorization

            checkPolicyPre(
                "selfservice", "useractivateocra2token", param, self.authUser
            )

            try:
                typ = param["type"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            if typ and typ.lower() not in ["ocra2"]:
                return sendError(
                    response,
                    _("valid types is 'ocra2'. You provided %s") % typ,
                )

            helper_param = {}
            helper_param["type"] = typ
            try:
                helper_param["serial"] = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            acode = param["activationcode"]
            helper_param["activationcode"] = acode.upper()

            try:
                helper_param["genkey"] = param["genkey"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            th = TokenHandler()
            (ret, tokenObj) = th.initToken(helper_param, self.authUser)

            info = {}
            serial = ""
            if tokenObj is not None:
                info = tokenObj.getInfo()
                serial = tokenObj.getSerial()
            else:
                raise Exception("Token not found!")

            url = info.get("app_import")
            trans = info.get("transactionid")

            ret = {
                "url": url,
                "img": create_img(url, width=400, alt=url),
                "label": "%s@%s" % (self.authUser.login, self.authUser.realm),
                "serial": serial,
                "transaction": trans,
            }

            g.audit["serial"] = serial
            g.audit["token_type"] = typ
            g.audit["success"] = True
            g.audit["realm"] = self.authUser.realm

            db.session.commit()
            return sendResult(
                self.response, {"activate": True, "ocratoken": ret}
            )

        except PolicyException as pe:
            log.error("policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("token initialization failed! %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    def finishocra2token(self):
        """

        finishocra2token - called from the selfservice web ui to finish
                        the OCRA2 token to run the final check_t for the token

        :param passw: the calculated verificaton otp
        :type  passw: string
        :param transactionid: the transactionid
        :type  transactionid: string

        :return:    dict about the token
        :rtype:     { 'result' = ok
                      'failcount' = int(failcount)
                    }

        """

        param = self.request_params.copy()

        if "session" in param:
            del param["session"]

        value = {}
        ok = False
        typ = ""
        opt = None

        try:

            typ = param.get("type", None)
            if not typ:
                raise ParameterError("Missing parameter: type")

            # check selfservice authorization

            checkPolicyPre(
                "selfservice", "userwebprovision", param, self.authUser
            )

            passw = param.get("pass", None)
            if not passw:
                raise ParameterError("Missing parameter: pass")

            transid = param.get("state", param.get("transactionid", None))
            if not transid:
                raise ParameterError(
                    "Missing parameter: state or transactionid!"
                )

            vh = ValidationHandler()
            (ok, reply) = vh.check_by_transactionid(
                transid=transid, passw=passw, options=param
            )

            value["value"] = ok
            value["failcount"] = int(reply.get("failcount", 0))

            g.audit["transactionid"] = transid
            g.audit["token_type"] = reply["token_type"]
            g.audit["success"] = ok
            g.audit["realm"] = self.authUser.realm

            db.session.commit()
            return sendResult(self.response, value, opt)

        except PolicyException as pe:
            log.error("[userfinishocra2token] policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as e:
            error = (
                "[userfinishocra2token] token initialization failed! %r" % e
            )
            log.error(error)
            db.session.rollback()
            return sendError(response, error, 1)

    def token_call(self):
        """
        the generic method call for an dynamic token
        """
        param = self.request_params.copy()

        res = {}

        try:
            # # method could be part of the virtual url
            context = request.path_info.split("/")
            if len(context) > 2:
                method = context[2]
            else:
                try:
                    method = param["method"]
                except KeyError as exx:
                    raise ParameterError("Missing parameter: '%s'" % str(exx))

            try:
                typ = param["type"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            serial = param.get("serial", None)

            # check selfservice authorization for this dynamic method
            pols = get_client_policy(
                self.client,
                scope="selfservice",
                realm=self.authUser.realm,
                action=method,
                userObj=self.authUser.realm,
                find_resolver=False,
            )
            if not pols or len(pols) == 0:
                log.error(
                    "user %r not authorized to call %s", self.authUser, method
                )
                raise PolicyException(
                    "user %r not authorized to call %s"
                    % (self.authUser, method)
                )

            if typ in tokenclass_registry:
                token_cls = tokenclass_registry.get(typ)
                tclt = None
                if serial is not None:
                    toks = getTokens4UserOrSerial(None, serial, _class=False)
                    tokenNum = len(toks)
                    if tokenNum == 1:
                        token = toks[0]
                        # object method call
                        tclt = token_cls(token)

                # static method call
                if tclt is None:
                    tclt = token_cls
                method = "" + method.strip()
                if hasattr(tclt, method):
                    # TODO: check that method name is a function / method
                    ret = getattr(tclt, method)(param)
                    if len(ret) == 1:
                        res = ret[0]
                    if len(ret) > 1:
                        res = ret[1]
                    g.audit["success"] = res
                else:
                    res["status"] = "method %s.%s not supported!" % (
                        typ,
                        method,
                    )
                    g.audit["success"] = False

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pe:
            log.error("[token_call] policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error(
                "[token_call] calling method %s.%s of user %s failed! %r",
                typ,
                method,
                c.user,
                exx,
            )
            db.session.rollback()
            return sendError(response, exx, 1)

    def setdescription(self):
        """
        sets a description for a token, provided the setDescription policy is set.

        as this is a controller method, the parameters are taken from
        BaseController.request_params

        :param serial: serial number of the token *required
        :param description: string containing a new description for the token

        :return: a linotp json doc with result {'status': True, 'value': True}

        """

        log.debug("set token description")

        try:

            param = self.request_params

            try:

                serial = param["serial"]
                description = param["description"]

            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx)

            checkPolicyPre(
                "selfservice", "usersetdescription", param, self.authUser
            )

            th = TokenHandler()

            if not th.isTokenOwner(serial, self.authUser):
                raise Exception(
                    "User %r is not owner of the token" % self.authUser.login
                )

            log.info(
                "user %s@%s is changing description of token with "
                "serial %s.",
                self.authUser.login,
                self.authUser.realm,
                serial,
            )

            ret = th.setDescription(description, serial=serial)

            res = {"set description": ret}

            g.audit["realm"] = self.authUser.realm
            g.audit["success"] = ret

            db.session.commit()
            return sendResult(self.response, res, 1)

        except PolicyException as pex:
            log.error("[setdescription] policy failed")
            db.session.rollback()
            return sendError(response, pex, 1)

        except Exception as exx:
            log.error("failed: %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)


# eof##########################################################################

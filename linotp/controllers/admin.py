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
admin controller - interfaces to administrate LinOTP
"""
import json
import logging
import os
from datetime import datetime

from flask_babel import gettext as _
from werkzeug.datastructures import FileStorage

from flask import (
    Response,
    after_this_request,
    current_app,
    g,
    stream_with_context,
)

from linotp.controllers.base import (
    BaseController,
    JWTMixin,
    SessionCookieMixin,
)
from linotp.flap import HTTPUnauthorized, config, request, response
from linotp.lib.audit.base import get_token_num_info
from linotp.lib.challenges import Challenges
from linotp.lib.context import request_context
from linotp.lib.error import ParameterError, TokenAdminError
from linotp.lib.ImportOTP.oath import parseOATHcsv
from linotp.lib.ImportOTP.safenet import ImportException, parseSafeNetXML
from linotp.lib.ImportOTP.yubico import parseYubicoCSV
from linotp.lib.policy import (
    PolicyException,
    checkPolicyPost,
    checkPolicyPre,
    getOTPPINEncrypt,
)
from linotp.lib.realm import getDefaultRealm, getRealms
from linotp.lib.reply import (
    sendCSVResult,
    sendError,
    sendQRImageResult,
    sendResult,
    sendResultIterator,
    sendXMLError,
    sendXMLResult,
)
from linotp.lib.reporting import token_reporting
from linotp.lib.resolver import (
    get_resolver_class,
    getResolverInfo,
    getResolverObject,
)
from linotp.lib.token import (
    TokenHandler,
    getTokenRealms,
    getTokens4UserOrSerial,
    getTokenType,
    resetToken,
    setPin,
    setPinSo,
    setPinUser,
    setRealms,
)
from linotp.lib.tokeniterator import TokenIterator
from linotp.lib.user import (
    User,
    getSearchFields,
    getUserFromParam,
    getUserFromRequest,
    getUserListIterators,
)
from linotp.lib.useriterator import iterate_users
from linotp.lib.util import (
    SESSION_KEY_LENGTH,
    check_session,
    get_client,
    getLowerParams,
)
from linotp.model import db
from linotp.tokens import tokenclass_registry

log = logging.getLogger(__name__)


class AdminController(BaseController, JWTMixin, SessionCookieMixin):

    """
    The linotp.controllers are the implementation of the web-API to talk to
    the LinOTP server.
    The AdminController is used for administrative tasks like adding tokens
    to LinOTP, assigning tokens or revoking tokens.
    The functions of the AdminController are invoked like this

        https://server/admin/<functionname>

    The functions are described below in more detail.
    """

    session_cookie_name = "admin_session"  # for `SessionCookieMixin`

    def __before__(self, **params):
        """
        __before__ is called before every action

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        action = request_context["action"]

        try:

            g.audit["success"] = False
            g.audit["client"] = get_client(request)

            if request.path.lower() in [
                "/admin/getsession",
                "/admin/login",
                "/admin/logout",
            ]:
                return None

            check_session(request)

            return None

        except Exception as exx:
            log.error("[__before__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(response, exx, context="before")

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        action = request_context["action"]
        audit = config.get("audit")

        try:
            # prevent logging of getsession or other irrelevant requests
            if action in ["getsession", "dropsession"]:
                return response

            g.audit["administrator"] = getUserFromRequest(request).get("login")

            serial = request.params.get("serial")
            if serial:
                g.audit["serial"] = serial
                g.audit["token_type"] = getTokenType(serial)

            # ------------------------------------------------------------- --

            # show the token usage counter for the actions which change the
            # numbers of tokens

            if action in [
                "assign",
                "unassign",
                "enable",
                "disable",
                "init",
                "loadtokens",
                "copyTokenUser",
                "losttoken",
                "remove",
                "tokenrealm",
                "loadtokens",
            ]:
                event = "token_" + action

                if g.audit.get("source_realm"):
                    source_realms = g.audit.get("source_realm")
                    token_reporting(event, source_realms)

                target_realms = g.audit.get("realm")
                token_reporting(event, target_realms)

                g.audit["action_detail"] += get_token_num_info()

            # ------------------------------------------------------------- --

            current_app.audit_obj.log(g.audit)
            db.session.commit()
            return response

        except Exception as exx:
            log.error("[__after__] unable to create a session cookie: %r", exx)
            db.session.rollback()
            return sendError(response, exx, context="after")

    def getTokenOwner(self):
        """
        provide the userinfo of the token, which is specified as serial
        """

        ret = {}
        try:
            serial = self.request_params["serial"]

            # check admin authorization
            checkPolicyPre("admin", "tokenowner", self.request_params)
            th = TokenHandler()
            owner = th.getTokenOwner(serial)
            if owner.info:
                ret = owner.info

            g.audit["success"] = len(ret) > 0

            db.session.commit()
            return sendResult(response, ret)

        except PolicyException as pe:
            log.error("Error getting token owner. Exception was %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("Error getting token owner. Exception was %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    @staticmethod
    def parse_tokeninfo(tok):
        """
        Parse TokenInfo to JSON
        and format validity periode date fields to isoformat

        """

        token_info = tok["LinOtp.TokenInfo"]

        if token_info:
            info = json.loads(token_info)
        else:
            info = {}

        for field in ["validity_period_end", "validity_period_start"]:
            if field in info:
                date = datetime.strptime(info[field], "%d/%m/%y %H:%M")
                info[field] = date.isoformat()

        tok["LinOtp.TokenInfo"] = info

    def show(self):
        """
        method:
            admin/show

        description:
            displays the list of the available tokens

        arguments:
            * serial  - optional: only this serial will be displayed
            * user    - optional: only the tokens of this user will be
                                  displayed. If the user does not exist,
                                  linotp will search tokens of users, who
                                  contain this substring.
                        **TODO:** This can be very time consuming an will be
                                  changed in the next release to use wildcards.
            * filter  - optional: takes a substring to search in table token
                                  columns
            * viewrealm - optional: takes a realm, only the tokens in this
                                    realm will be displayed
            * realm - - optional: alias to the viewrealm
            * sortby  - optional: sort the output by column
            * sortdir - optional: asc/desc
            * page    - optional: reqeuest a certain page
            * pagesize- optional: limit the number of returned tokens
            * user_fields - optional: additional user fields from the userid resolver of the owner (user)
            * outform - optional: if set to "csv", than the token list will be given in CSV
            * tokeninfo_format - optional: if set to "json", this will be supplied in embedded JSON
                                 otherwise, string format is returned with dates in format
                                 DD/MM/YYYY TODO

        returns:
            a json result with:
            { "head": [],
            "data": [ [row1], [row2] .. ]
            }

        exception:
            if an error occurs an exception is serialized and returned
        """

        param = self.request_params
        try:
            serial = param.get("serial")
            page = param.get("page")
            filter = param.get("filter")
            sort = param.get("sortby")
            dir = param.get("sortdir")
            psize = param.get("pagesize")
            realm = param.get("viewrealm", param.get("realm", ""))
            ufields = param.get("user_fields")
            output_format = param.get("outform")
            is_tokeninfo_json = param.get("tokeninfo_format") == "json"

            user_fields = []
            if ufields:
                user_fields = [u.strip() for u in ufields.split(",")]

            user = getUserFromParam(param)

            filterRealm = []
            # check admin authorization
            res = checkPolicyPre("admin", "show", param, user=user)

            # check if policies are active at all
            # If they are not active, we are allowed to SHOW any tokens.
            filterRealm = ["*"]
            if res["active"] and res["realms"]:
                filterRealm = res["realms"]

            if realm:
                # If the admin wants to see only one realm, then do it:
                log.debug("Only tokens in realm %s will be shown", realm)
                if realm in filterRealm or "*" in filterRealm:
                    filterRealm = [realm]

            log.info(
                "[show] admin >%s< may display the following realms: %r",
                res["admin"],
                filterRealm,
            )

            toks = TokenIterator(
                user,
                serial,
                page,
                psize,
                filter,
                sort,
                dir,
                filterRealm,
                user_fields,
            )

            g.audit["success"] = True
            g.audit["info"] = "realm: %s, filter: %r" % (filterRealm, filter)

            # put in the result
            result = {}

            # now row by row
            lines = []
            for tok in toks:

                if is_tokeninfo_json:
                    self.parse_tokeninfo(tok)

                lines.append(tok)

            result["data"] = lines
            result["resultset"] = toks.getResultSetInfo()

            db.session.commit()

            if output_format == "csv":
                return sendCSVResult(response, result)
            else:
                return sendResult(response, result)

        except PolicyException as pe:
            log.error("[show] policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[show] failed: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    def remove(self):
        """
        method:
            admin/remove

        description:
            deletes either a certain token given by serial or all tokens of a user

        arguments:
            * serial  - optional
            * user    - optional

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params

        try:
            serials = param.get("serial", [])
            if serials and not isinstance(serials, list):
                serials = [serials]

            user = getUserFromParam(param)

            g.audit["user"] = user.login
            g.audit["realm"] = user.realm or ""

            if not serials and not user:
                raise ParameterError("missing parameter user or serial!")

            if user:
                tokens = getTokens4UserOrSerial(user)
                for token in tokens:
                    serials.append(token.getSerial())

            realms = set()
            for serial in set(serials):
                realms.union(getTokenRealms(serial))

            g.audit["realm"] = "%r" % realms

            log.info(
                "[remove] removing token with serial %r for user %r",
                serials,
                user.login,
            )

            ret = 0
            check_params = {}
            check_params.update(param)

            th = TokenHandler()
            for serial in set(serials):

                # check admin authorization
                check_params["serial"] = serial
                checkPolicyPre("admin", "remove", check_params)

                ret = ret + th.removeToken(user, serial)

            g.audit["success"] = 0
            g.audit["serial"] = " ".join(serials)

            opt_result_dict = {}

            # if not token could be removed, create a response detailed
            if ret == 0:
                if user:
                    msg = "No tokens for this user %r" % user.login
                else:
                    msg = "No token with serials %r" % serials

                opt_result_dict["message"] = msg

            db.session.commit()
            return sendResult(response, ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.error("[remove] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[remove] failed! %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################

    def enable(self):
        """
        method:
            admin/enable

        description:
            enables a token or all tokens of a user

        arguments:
            * serial  - optional
            * user    - optional

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params
        try:
            serial = param.get("serial")
            user = getUserFromParam(param)

            # check admin authorization
            checkPolicyPre("admin", "enable", param, user=user)

            th = TokenHandler()
            log.info(
                "[enable] enable token with serial %s for user %s@%s.",
                serial,
                user.login,
                user.realm,
            )
            ret = th.enableToken(True, user, serial)

            g.audit["success"] = ret
            g.audit["user"] = user.login

            if user.is_empty:
                g.audit["realm"] = getTokenRealms(serial)
            else:
                g.audit["realm"] = user.realm
                if g.audit["realm"] == "":
                    realms = set()
                    for tokenserial in getTokens4UserOrSerial(user, serial):
                        realms.union(tokenserial.getRealms())
                    g.audit["realm"] = realms

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict["message"] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.is_empty:
                opt_result_dict["message"] = "No tokens for this user"

            checkPolicyPost("admin", "enable", param, user=user)

            db.session.commit()
            return sendResult(response, ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.error("[enable] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[enable] failed: %r", exx)
            db.session.rollback()
            log.error("[enable] error enabling token")
            return sendError(response, exx, 1)

    ########################################################

    def getSerialByOtp(self):
        """
        method:
            admin/getSerialByOtp

        description:
            searches for the token, that generates the given OTP value.
            The search can be restricted by several critterions

        arguments:
            * otp      - required. Will search for the token, that produces this OTP value
            * type     - optional, will only search in tokens of type
            * realm    - optional, only search in this realm
            * assigned - optional. 1: only search assigned tokens, 0: only search unassigned tokens

        returns:
            a json result with the serial


        exception:
            if an error occurs an exception is serialized and returned

        """

        ret = {}
        param = self.request_params

        try:
            try:
                otp = param["otp"]
            except KeyError:
                raise ParameterError("Missing parameter: 'otp'")

            typ = param.get("type")
            realm = param.get("realm")
            assigned = param.get("assigned")

            serial = ""
            username = ""

            # check admin authorization
            checkPolicyPre("admin", "getserial", param)
            th = TokenHandler()
            serial, username, resolverClass = th.get_serial_by_otp(
                None, otp, 10, typ=typ, realm=realm, assigned=assigned
            )
            log.debug(
                "[getSerialByOtp] found %s with user %s", serial, username
            )

            if "" != serial:
                checkPolicyPost("admin", "getserial", {"serial": serial})

            g.audit["success"] = 1
            g.audit["serial"] = serial

            ret["success"] = True
            ret["serial"] = serial
            ret["user_login"] = username
            ret["user_resolver"] = resolverClass

            db.session.commit()
            return sendResult(response, ret, 1)

        except PolicyException as pe:
            log.error("[disable] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            g.audit["success"] = 0
            db.session.rollback()
            log.error("[getSerialByOtp] error: %r", exx)
            return sendError(response, exx, 1)

    ########################################################

    def disable(self):
        """
        method:
            admin/disable

        description:
            disables a token given by serial or all tokens of a user

        arguments:
            * serial  - optional
            * user    - optional

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params
        try:
            serial = param.get("serial")
            user = getUserFromParam(param)
            auth_user = getUserFromRequest(request)

            # check admin authorization
            checkPolicyPre("admin", "disable", param, user=user)

            th = TokenHandler()
            log.info(
                "[disable] disable token with serial %s for user %s@%s.",
                serial,
                user.login,
                user.realm,
            )
            ret = th.enableToken(False, user, serial)

            g.audit["success"] = ret
            g.audit["user"] = user.login

            if user.is_empty:
                g.audit["realm"] = getTokenRealms(serial)
            else:
                g.audit["realm"] = user.realm
                if g.audit["realm"] == "":
                    realms = set()
                    for tokenserial in getTokens4UserOrSerial(user, serial):
                        realms.union(tokenserial.getRealms())
                    g.audit["realm"] = realms

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict["message"] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.is_empty:
                opt_result_dict["message"] = "No tokens for this user"

            db.session.commit()
            return sendResult(response, ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.error("[disable] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[disable] failed! %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    #######################################################

    def check_serial(self):
        """
        method
            admin/check_serial

        description:
            This function checks, if a given serial will be unique.
            It returns True if the serial does not yet exist and
            new_serial as a new value for a serial, that does not exist, yet

        arguments:
            serial    - required- the serial to be checked

        returns:
            a json result with a new suggestion for the serial

        exception:
            if an error occurs an exception is serialized and returned

        """

        try:
            try:
                serial = self.request_params["serial"]
            except KeyError:
                raise ParameterError("Missing parameter: 'serial'")

            # check admin authorization
            # try:
            #    checkPolicyPre('admin', 'disable', param )
            # except PolicyException as pe:
            #    return sendError(response, pe, 1)

            log.info("[check_serial] checking serial %s", serial)
            th = TokenHandler()
            (unique, new_serial) = th.check_serial(serial)

            g.audit["success"] = True
            g.audit["serial"] = serial
            g.audit["action_detail"] = "%r - %r" % (unique, new_serial)

            db.session.commit()
            return sendResult(
                response, {"unique": unique, "new_serial": new_serial}, 1
            )

        except PolicyException as pe:
            log.error("[check_serial] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[check_serial] failed! %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################

    def init(self):
        """
        method:
            admin/init

        description:
            creates a new token.

        arguments:
            * otpkey (required) the hmac Key of the token
            * genkey (required) =1, if key should be generated.
                We either need otpkey or genkey
            * keysize (optional) either 20 or 32. Default is 20
            * serial (required) the serial number / identifier of the token
            * description (optional)
            * pin (optional) the pin of the user pass
            * user (optional) login user name
            * realm (optional) realm of the user
            * type (optional) the type of the token
            * tokenrealm (optional) the realm a token should be put into
            * otplen (optional) length of the OTP value
            * hashlib (optional) used hashlib sha1 oder sha256

        ocra2 arguments:
            for generating OCRA2 Tokens type=ocra2 you can specify the
            following parameters:

            * ocrasuite (optional) - if you do not want to use the default
                ocra suite OCRA-1:HOTP-SHA256-8:QA64
            * sharedsecret (optional) if you are in Step0 of enrolling an
                OCRA2 token the sharedsecret=1 specifies,
              that you want to generate a shared secret
            * activationcode (optional) if you are in Step1 of enrolling
                an OCRA2 token you need to pass the
              activation code, that was generated in the QRTAN-App

        qrtoken arguments:
            for generating QRTokens type=qr you can specify the
            following parameters

            * hashlib (optional) the hash algorithm used in the mac
                calculation (sha512, sha256, sha1). default is sha256

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        ret = False
        response_detail = {}

        try:

            params = self.request_params.copy()
            params.setdefault("key_size", 20)

            # --------------------------------------------------------------- --

            # determine token class

            token_cls_alias = params.get("type") or "hmac"
            lower_alias = token_cls_alias.lower()

            if lower_alias not in tokenclass_registry:
                raise TokenAdminError(
                    "admin/init failed: unknown token "
                    "type %r" % token_cls_alias,
                    id=1610,
                )

            token_cls = tokenclass_registry.get(lower_alias)

            # --------------------------------------------------------------- --

            # call the token class hook in order to enrich/overwrite the
            # parameters

            helper_params = token_cls.get_helper_params_pre(params)
            params.update(helper_params)

            # --------------------------------------------------------------- --

            # fetch user from parameters.

            user = getUserFromParam(params)

            # --------------------------------------------------------------- --

            # check admin authorization

            res = checkPolicyPre("admin", "init", params, user=user)

            # --------------------------------------------------------------- --

            # if no user is given, we put the token in all realms of the admin

            tokenrealm = None
            if user.login == "":
                log.debug("[init] setting tokenrealm %r", res["realms"])
                tokenrealm = res["realms"]

            # --------------------------------------------------------------- --

            helper_params = token_cls.get_helper_params_post(params, user=user)
            params.update(helper_params)

            # --------------------------------------------------------------- --

            serial = params.get("serial", None)
            prefix = params.get("prefix", None)

            # --------------------------------------------------------------- --

            th = TokenHandler()
            if not serial:
                serial = th.genSerial(token_cls_alias, prefix)
                params["serial"] = serial

            log.info(
                "[init] initialize token. user: %s, serial: %s",
                user.login,
                serial,
            )

            # --------------------------------------------------------------- --

            (ret, token) = th.initToken(params, user, tokenrealm=tokenrealm)

            # --------------------------------------------------------------- --

            # different token types return different information on
            # initialization (e.g. otpkey, pairing_url, etc)

            initDetail = token.getInitDetail(params, user)
            response_detail.update(initDetail)

            # --------------------------------------------------------------- --

            # prepare data for audit

            if token is not None and ret is True:
                g.audit["serial"] = token.getSerial()
                g.audit["token_type"] = token.type

            g.audit["success"] = ret
            g.audit["user"] = user.login
            g.audit["realm"] = user.realm

            if g.audit["realm"] == "":
                g.audit["realm"] = tokenrealm

            g.audit["success"] = ret
            # --------------------------------------------------------------- --

            checkPolicyPost("admin", "init", params, user=user)
            db.session.commit()

            # --------------------------------------------------------------- --

            # depending on parameters send back an qr image
            # or a text result

            if "qr" in params and token is not None:
                (rdata, hparam) = token.getQRImageData(response_detail)
                hparam.update(response_detail)
                hparam["qr"] = params.get("qr") or "html"
                return sendQRImageResult(response, rdata, hparam)
            else:
                return sendResult(response, ret, opt=response_detail)

        # ------------------------------------------------------------------- --

        except PolicyException as pe:
            log.error("[init] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[init] token initialization failed! %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################

    def unassign(self):
        """
        method:
            admin/unassign - remove the assigned user from the token

        description:
            unassigns a token from a user. i.e. the binding between the token
            and the user is removed

        arguments:
            * serial    - required - the serial number / identifier of the token
            * user      - optional

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params

        try:
            try:
                serial = param["serial"]
            except KeyError:
                raise ParameterError("Missing parameter: 'serial'")

            user = getUserFromParam(param)

            g.audit["source_realm"] = getTokenRealms(serial)

            # check admin authorization
            checkPolicyPre("admin", "unassign", param)

            th = TokenHandler()
            log.info(
                "[unassign] unassigning token with serial %r from "
                "user %r@%r",
                serial,
                user.login,
                user.realm,
            )
            ret = th.unassignToken(serial, user, None)

            g.audit["success"] = ret
            g.audit["user"] = user.login
            g.audit["realm"] = user.realm

            if "" == g.audit["realm"]:
                g.audit["realm"] = getTokenRealms(serial)

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict["message"] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.is_empty:
                opt_result_dict["message"] = "No tokens for this user"

            db.session.commit()
            return sendResult(response, ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.error("[unassign] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[unassign] failed! %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    ########################################################

    def assign(self):
        """
        method:
            admin/assign

        description:
            assigns a token to a user, i.e. a binding between the token and
            the user is created.

        arguments:
            * serial     - required - the serial number / identifier of the token
            * user       - required - login user name
            * pin        - optional - the pin of the user pass

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params

        try:

            upin = param.get("pin")

            user = getUserFromParam(param)

            serials = param.get("serial", [])
            if serials and not isinstance(serials, list):
                serials = [serials]

            log.info("[assign] assigning token(s) with serial(s) %r", serials)

            call_params = {}
            call_params.update(param)

            res = True
            th = TokenHandler()
            for serial in set(serials):

                # check admin authorization

                call_params["serial"] = serial
                checkPolicyPre("admin", "assign", call_params)

                # do the assignment
                res = res and th.assignToken(
                    serial, user, upin, param=call_params
                )

            checkPolicyPost("admin", "assign", param, user)

            g.audit["success"] = res
            g.audit["user"] = user.login
            g.audit["realm"] = user.realm
            if "" == g.audit["realm"]:
                g.audit["realm"] = getTokenRealms(serial)

            db.session.commit()
            return sendResult(response, res, len(serials))

        except PolicyException as pe:
            log.error("[assign] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[assign] token assignment failed! %r", exx)
            db.session.rollback()
            return sendError(response, exx, 0)

    ########################################################

    def setPin(self):
        """
        method:
            admin/set

        description:
            This function sets the smartcard PINs of a eTokenNG OTP.
            The userpin is used to store the mOTP PIN of mOTP tokens!
            !!! For setting the OTP PIN, use the function /admin/set!

        arguments:
            * serial     - required
            * userpin    - optional: store the userpin
            * sopin      - optional: store the sopin

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        count = 0

        description = "setPin: parameters are\
        serial\
        userpin\
        sopin\
        "
        try:
            param = getLowerParams(self.request_params)

            # # if there is a pin
            if "userpin" in param:
                msg = "setting userPin failed"
                try:
                    userPin = param["userpin"]
                except KeyError:
                    raise ParameterError("Missing parameter: 'userpin'")

                try:
                    serial = param["serial"]
                except KeyError:
                    raise ParameterError("Missing parameter: 'serial'")

                # check admin authorization
                checkPolicyPre("admin", "setPin", param)

                log.info(
                    "[setPin] setting userPin for token with serial %s", serial
                )
                ret = setPinUser(userPin, serial)
                res["set userpin"] = ret
                count = count + 1
                g.audit["action_detail"] += "userpin, "

            if "sopin" in param:
                msg = "setting soPin failed"
                try:
                    soPin = param["sopin"]
                except KeyError:
                    raise ParameterError("Missing parameter: 'userpin'")

                try:
                    serial = param["serial"]
                except KeyError:
                    raise ParameterError("Missing parameter: 'serial'")

                # check admin authorization
                checkPolicyPre("admin", "setPin", param)

                log.info(
                    "[setPin] setting soPin for token with serial %s", serial
                )
                ret = setPinSo(soPin, serial)
                res["set sopin"] = ret
                count = count + 1
                g.audit["action_detail"] += "sopin, "

            if count == 0:
                db.session.rollback()
                return sendError(
                    response, ParameterError("Usage: %s" % description, id=77)
                )

            g.audit["success"] = count

            db.session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("[setPin] policy failed %r, %r", msg, pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[setPin] %s :%r", msg, exx)
            db.session.rollback()
            return sendError(response, exx, 0)

    def setValidity(self):
        """
        dedicated backend for setting the token validity for
        multiple selected tokens.

        arguments:

        * tokens[]: the token serials (required)

        * countAuthSuccessMax:
            the maximum number of allowed successful authentications

        * countAuthMax:
            the maximum number of allowed successful authentications

        * validityPeriodStart: utc - unix seconds as int

        * validityPeriodEnd: utc - unix seconds as int

        remark:

            the parameter names are the same as with the admin/set
            while admin/set does not support multiple tokens

        remark:

            if the value is 'unlimited' the validity limit will be removed

        return:

        * json document with the value field containing the serials of
          the modified tokens

        """
        try:

            g.audit["info"] = "set token validity"

            param = getLowerParams(self.request_params)

            # -------------------------------------------------------------- --

            # check admin authorization

            admin_user = getUserFromRequest(request)

            checkPolicyPre("admin", "set", param, user=admin_user)

            # -------------------------------------------------------------- --

            # process the arguments

            unlimited = "unlimited"

            countAuthSuccessMax = None
            if "countAuthSuccessMax".lower() in param:
                countAuthSuccessMax = param.get("countAuthSuccessMax".lower())

            countAuthMax = None
            if "countAuthMax".lower() in param:
                countAuthMax = param.get("countAuthMax".lower())

            validityPeriodStart = None
            if "validityPeriodStart".lower() in param:
                validityPeriodStart = param.get("validityPeriodStart".lower())

            validityPeriodEnd = None
            if "validityPeriodEnd".lower() in param:
                validityPeriodEnd = param.get("validityPeriodEnd".lower())

            # -------------------------------------------------------------- --

            try:
                serials = self.request_params["tokens"]
            except KeyError:
                raise ParameterError("missing parameter: tokens[]")

            tokens = []
            for serial in serials:
                tokens.extend(getTokens4UserOrSerial(serial=serial))

            # -------------------------------------------------------------- --

            # push the validity values into the tokens

            for token in tokens:

                # ---------------------------------------------------------- --

                if countAuthMax == unlimited:
                    token.del_count_auth_max()

                elif countAuthMax is not None:
                    token.count_auth_max = int(countAuthMax)

                # ---------------------------------------------------------- --

                if countAuthSuccessMax == unlimited:
                    token.del_count_auth_success_max()

                elif countAuthSuccessMax is not None:
                    token.count_auth_success_max = int(countAuthSuccessMax)

                # ---------------------------------------------------------- --

                if validityPeriodStart == unlimited:
                    token.del_validity_period_start()

                elif validityPeriodStart is not None:

                    validity_period_start = (
                        datetime.utcfromtimestamp(int(validityPeriodStart))
                        .strftime("%d/%m/%y %H:%M")
                        .strip()
                    )
                    token.validity_period_start = validity_period_start

                # ---------------------------------------------------------- --

                if validityPeriodEnd == unlimited:
                    token.del_validity_period_end()

                elif validityPeriodEnd is not None:

                    validity_period_end = (
                        datetime.utcfromtimestamp(int(validityPeriodEnd))
                        .strftime("%d/%m/%y %H:%M")
                        .strip()
                    )

                    token.validity_period_end = validity_period_end

            g.audit["success"] = 1

            g.audit["action_detail"] = ("%r " % serials)[:80]

            db.session.commit()
            return sendResult(response, serials, 1)

        except PolicyException as pex:
            log.error("policy failed%r", pex)
            db.session.rollback()
            return sendError(response, pex, 1)

        except Exception as exx:

            g.audit["success"] = False

            log.error("%r", exx)
            db.session.rollback()
            return sendError(response, exx, 0)

    ########################################################

    def set(self):
        """
        method:
            admin/set

        description:
            this function is used to set many different values of a token.

        arguments:
            * serial     - optional
            * user       - optional
            * pin        - optional - set the OTP PIN
            * MaxFailCount  - optional - set the maximum fail counter of a token
            * SyncWindow    - optional - set the synchronization window of the token
            * OtpLen        - optional - set the OTP Lenght of the token
            * CounterWindow - optional - set the counter window (blank presses)
            * hashlib       - optioanl - set the hashing algo for HMAC tokens. This can be sha1, sha256, sha512
            * timeWindow    - optional - set the synchronize window for timebased tokens (in seconds)
            * timeStep      - optional - set the timestep for timebased tokens (usually 30 or 60 seconds)
            * timeShift     - optional - set the shift or timedrift of this token
            * countAuthSuccessMax    - optional    - set the maximum allowed successful authentications
            * countAuthSuccess       - optional    - set the counter of the successful authentications
            * countAuth        - optional - set the counter of authentications
            * countAuthMax     - optional - set the maximum allowed authentication tries
            * validityPeriodStart    - optional - set the start date of the validity period. The token can not be used before this date
            * validityPeriodEnd      - optional - set the end date of the validaity period. The token can not be used after this date
            * phone - set the phone number for an SMS token

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        count = 0

        description = "set: parameters are\
        pin\
        MaxFailCount\
        SyncWindow\
        OtpLen\
        CounterWindow\
        hashlib\
        timeWindow\
        timeStep\
        timeShift\
        countAuthSuccessMax\
        countAuthSuccess\
        countAuth\
        countAuthMax\
        validityPeriodStart\
        validityPeriodEnd\
        description\
        phone\
        "
        msg = ""

        try:
            param = getLowerParams(self.request_params)

            serial = param.get("serial")
            user = getUserFromParam(param)

            # check admin authorization
            checkPolicyPre("admin", "set", param, user=user)

            th = TokenHandler()
            # # if there is a pin
            if "pin" in param:
                msg = "[set] setting pin failed"
                upin = param["pin"]
                log.info("[set] setting pin for token with serial %r", serial)
                if 1 == getOTPPINEncrypt(serial=serial, user=user):
                    param["encryptpin"] = "True"
                ret = setPin(upin, user, serial, param)
                res["set pin"] = ret
                count = count + 1
                g.audit["action_detail"] += "pin, "

            if "MaxFailCount".lower() in param:
                msg = "[set] setting MaxFailCount failed"
                maxFail = int(param["MaxFailCount".lower()])
                log.info(
                    "[set] setting maxFailCount (%r) for token with "
                    "serial %r",
                    maxFail,
                    serial,
                )
                ret = th.setMaxFailCount(maxFail, user, serial)
                res["set MaxFailCount"] = ret
                count = count + 1
                g.audit["action_detail"] += "maxFailCount=%d, " % maxFail

            if "SyncWindow".lower() in param:
                msg = "[set] setting SyncWindow failed"
                syncWindow = int(param["SyncWindow".lower()])
                log.info(
                    "[set] setting syncWindow (%r) for token with "
                    "serial %r",
                    syncWindow,
                    serial,
                )
                ret = th.setSyncWindow(syncWindow, user, serial)
                res["set SyncWindow"] = ret
                count = count + 1
                g.audit["action_detail"] += "syncWindow=%d, " % syncWindow

            if "description".lower() in param:
                msg = "[set] setting description failed"
                description = param["description".lower()]
                log.info(
                    "[set] setting description (%r) for token with serial"
                    " %r",
                    description,
                    serial,
                )
                ret = th.setDescription(description, user, serial)
                res["set description"] = ret
                count = count + 1
                g.audit["action_detail"] += "description=%r, " % description

            if "CounterWindow".lower() in param:
                msg = "[set] setting CounterWindow failed"
                counterWindow = int(param["CounterWindow".lower()])
                log.info(
                    "[set] setting counterWindow (%r) for token with serial %r",
                    counterWindow,
                    serial,
                )
                ret = th.setCounterWindow(counterWindow, user, serial)
                res["set CounterWindow"] = ret
                count = count + 1
                g.audit["action_detail"] += (
                    "counterWindow=%d, " % counterWindow
                )

            if "OtpLen".lower() in param:
                msg = "[set] setting OtpLen failed"
                otpLen = int(param["OtpLen".lower()])
                log.info(
                    "[set] setting OtpLen (%r) for token with serial %r",
                    otpLen,
                    serial,
                )
                ret = th.setOtpLen(otpLen, user, serial)
                res["set OtpLen"] = ret
                count = count + 1
                g.audit["action_detail"] += "otpLen=%d, " % otpLen

            if "hashlib".lower() in param:
                msg = "[set] setting hashlib failed"
                hashlib = param["hashlib".lower()]
                log.info(
                    "[set] setting hashlib (%r) for token with serial %r",
                    hashlib,
                    serial,
                )
                th = TokenHandler()
                ret = th.setHashLib(hashlib, user, serial)
                res["set hashlib"] = ret
                count = count + 1
                g.audit["action_detail"] += "hashlib=%s, " % str(hashlib)

            if "timeWindow".lower() in param:
                msg = "[set] setting timeWindow failed"
                timeWindow = int(param["timeWindow".lower()])
                log.info(
                    "[set] setting timeWindow (%r) for token with serial"
                    " %r",
                    timeWindow,
                    serial,
                )
                ret = th.addTokenInfo("timeWindow", timeWindow, user, serial)
                res["set timeWindow"] = ret
                count = count + 1
                g.audit["action_detail"] += "timeWindow=%d, " % timeWindow

            if "timeStep".lower() in param:
                msg = "[set] setting timeStep failed"
                timeStep = int(param["timeStep".lower()])
                log.info(
                    "[set] setting timeStep (%r) for token with serial %r",
                    timeStep,
                    serial,
                )
                tokens = getTokens4UserOrSerial(serial=serial)
                for token in tokens:
                    token.timeStep = timeStep

                res["set timeStep"] = len(tokens)
                count = count + 1
                g.audit["action_detail"] += "timeStep=%d, " % timeStep

            if "timeShift".lower() in param:
                msg = "[set] setting timeShift failed"
                timeShift = int(param["timeShift".lower()])
                log.info(
                    "[set] setting timeShift (%r) for token with serial %r",
                    timeShift,
                    serial,
                )
                ret = th.addTokenInfo("timeShift", timeShift, user, serial)
                res["set timeShift"] = ret
                count = count + 1
                g.audit["action_detail"] += "timeShift=%d, " % timeShift

            if "countAuth".lower() in param:
                msg = "[set] setting countAuth failed"
                ca = int(param["countAuth".lower()])
                log.info(
                    "[set] setting count_auth (%r) for token with serial %r",
                    ca,
                    serial,
                )
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.count_auth = ca
                    count = count + 1
                    ret += 1
                res["set countAuth"] = ret
                g.audit["action_detail"] += "countAuth=%d, " % ca

            if "countAuthMax".lower() in param:
                msg = "[set] setting countAuthMax failed"
                ca = int(param["countAuthMax".lower()])
                log.info(
                    "[set] setting count_auth_max (%r) for token with serial %r",
                    ca,
                    serial,
                )
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.count_auth_max = ca
                    count = count + 1
                    ret += 1
                res["set countAuthMax"] = ret
                g.audit["action_detail"] += "countAuthMax=%d, " % ca

            if "countAuthSuccess".lower() in param:
                msg = "[set] setting countAuthSuccess failed"
                ca = int(param["countAuthSuccess".lower()])
                log.info(
                    "[set] setting count_auth_success (%r) for token with"
                    "serial %r",
                    ca,
                    serial,
                )
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.count_auth_success = ca
                    count = count + 1
                    ret += 1
                res["set countAuthSuccess"] = ret
                g.audit["action_detail"] += "countAuthSuccess=%d, " % ca

            if "countAuthSuccessMax".lower() in param:
                msg = "[set] setting countAuthSuccessMax failed"
                ca = int(param["countAuthSuccessMax".lower()])
                log.info(
                    "[set] setting count_auth_success_max (%r) for token with"
                    "serial %r",
                    ca,
                    serial,
                )
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.count_auth_success_max = ca
                    count = count + 1
                    ret += 1
                res["set countAuthSuccessMax"] = ret
                g.audit["action_detail"] += "countAuthSuccessMax=%d, " % ca

            if "validityPeriodStart".lower() in param:
                msg = "[set] setting validityPeriodStart failed"
                ca = param["validityPeriodStart".lower()]
                log.info(
                    "[set] setting validity_period_start (%r) for token with"
                    "serial %r",
                    ca,
                    serial,
                )
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.validity_period_start = ca
                    count = count + 1
                    ret += 1
                res["set validityPeriodStart"] = ret
                g.audit["action_detail"] += "validityPeriodStart=%s, " % str(
                    ca
                )

            if "validityPeriodEnd".lower() in param:
                msg = "[set] setting validityPeriodEnd failed"
                ca = param["validityPeriodEnd".lower()]
                log.info(
                    "[set] setting validity_period_end (%r) for token with"
                    "serial %r",
                    ca,
                    serial,
                )
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.validity_period_end = ca
                    count = count + 1
                    ret += 1
                res["set validityPeriodEnd"] = ret
                g.audit["action_detail"] += "validityPeriodEnd=%s, " % str(ca)

            if "phone" in param:
                msg = "[set] setting phone failed"
                ca = param["phone".lower()]
                log.info(
                    "[set] setting phone (%r) for token with serial %r",
                    ca,
                    serial,
                )
                tokens = getTokens4UserOrSerial(user, serial)
                ret = 0
                for tok in tokens:
                    tok.addToTokenInfo("phone", ca)
                    count = count + 1
                    ret += 1
                res["set phone"] = ret
                g.audit["action_detail"] += "phone=%s, " % str(ca)

            if count == 0:
                db.session.rollback()
                return sendError(
                    response, ParameterError("Usage: %s" % description, id=77)
                )

            g.audit["success"] = count
            g.audit["user"] = user.login
            g.audit["realm"] = user.realm

            if g.audit["realm"] == "":
                g.audit["realm"] = getTokenRealms(serial)

            db.session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("[set] policy failed: %s, %r", msg, pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("%s: %r", msg, exx)
            db.session.rollback()
            # as this message is directly returned into the javascript
            # alert as escaped string we remove here all escaping chars
            error = "%r" % exx
            error = error.replace('"', "|")
            error = error.replace("'", ":")
            error = error.replace("&", "+")
            error = error.replace(">", "]")
            error = error.replace("<", "[")
            result = "%s: %s" % (msg, error)
            return sendError(response, result)

    ########################################################
    def resync(self):
        """
        method:
            admin/resync - resync a token to a new counter

        description:
            this function resync the token, if the counter on server side is out of sync
            with the physica token.

        arguments:
            * serial     - serial or user required
            * user       - s.o.
            * otp1       - the next otp to be found
            * otp2       - the next otp after the otp1

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params
        try:
            serial = param.get("serial")
            user = getUserFromParam(param)

            try:
                otp1 = param["otp1"]
            except KeyError:
                raise ParameterError("Missing parameter: 'otp1'")

            try:
                otp2 = param["otp2"]
            except KeyError:
                raise ParameterError("Missing parameter: 'otp2'")

            # to support the challenge based resync, we have to pass the challenges
            #    down to the token implementation

            chall1 = param.get("challenge1")
            chall2 = param.get("challenge2")

            options = None
            if chall1 is not None and chall2 is not None:
                options = {"challenge1": chall1, "challenge2": chall2}

            # check admin authorization
            checkPolicyPre("admin", "resync", param)
            th = TokenHandler()
            log.info(
                "[resync] resyncing token with serial %r, user %r@%r",
                serial,
                user.login,
                user.realm,
            )
            res = th.resyncToken(otp1, otp2, user, serial, options)

            g.audit["success"] = res
            g.audit["user"] = user.login
            g.audit["realm"] = user.realm
            if "" == g.audit["realm"] and "" != g.audit["user"]:
                g.audit["realm"] = getDefaultRealm()

            db.session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("[resync] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[resync] resyncing token failed %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    ########################################################
    def userlist(self):
        """
        method:
            admin/userlist - list all users

        description:
            lists the user in a realm

        arguments:
            * <searchexpr>: will be retrieved from the UserIdResolverClass
            * realm: a realm, which is a collection of resolver configurations
            * resConf: a destinct resolver configuration
            * page: the number of page, which should be retrieved (optional)
            * rp: the number of users per page (optional)

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params.copy()

        # check admin authorization
        # check if we got a realm or resolver, that is ok!
        try:

            # TODO:
            # check if admin is allowed to see the useridresolvers
            # as users_iters is (user_iterator, resolvername)
            # we could simply check if the admin is allowed to view the
            # resolver
            # hint:
            # done by getting the list of realm the admin is allowed to view
            # and add this as paramter list to the getUserListIterators
            # (s. helpdesk api)

            realm = param.get("realm")

            # Here we need to list the users, that are only visible in the
            # realm!! we could also only list the users in the realm, if the
            # admin got the right "userlist".

            checkPolicyPre("admin", "userlist", param)

            up = 0
            user = getUserFromParam(param)

            log.info("[userlist] displaying users with param: %s, ", param)

            if len(user.realm) > 0:
                up = up + 1
            if len(user.resolver_config_identifier) > 0:
                up = up + 1

            if len(param) == up:
                usage = {
                    "usage": "list available users matching the "
                    "given search patterns:"
                }
                usage["searchfields"] = getSearchFields(user)
                res = usage
                db.session.commit()
                return sendResult(response, res)

            list_params = {}
            list_params.update(param)

            if "session" in list_params:
                del list_params["session"]

            rp = None
            if "rp" in list_params:
                rp = int(list_params["rp"])
                del list_params["rp"]

            page = None
            if "page" in list_params:
                page = list_params["page"]
                del list_params["page"]

            users_iters = getUserListIterators(list_params, user)

            g.audit["success"] = True
            g.audit["info"] = "realm: %s" % realm

            db.session.commit()

            return Response(
                stream_with_context(
                    sendResultIterator(
                        iterate_users(users_iters), rp=rp, page=page
                    )
                ),
                mimetype="application/json",
            )

            # ---------------------------------------------------------- --

        except PolicyException as pe:
            log.error("[userlist] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[userlist] failed %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################
    def tokenrealm(self):
        """
        method:
            admin/tokenrealm - set the realms a token belongs to

        description:
            sets the realms of a token

        arguments:
            * serial    - required -  serialnumber of the token
            * realms    - required -  comma seperated list of realms
        """

        param = self.request_params
        try:
            try:
                serial = param["serial"]
            except KeyError:
                raise ParameterError("Missing parameter: 'serial'")

            try:
                realms = param["realms"]
            except KeyError:
                raise ParameterError("Missing parameter: 'realms'")

            # check admin authorization
            checkPolicyPre("admin", "tokenrealm", param)

            g.audit["source_realm"] = getTokenRealms(serial)
            log.info(
                "[tokenrealm] setting realms for token %s to %s",
                serial,
                realms,
            )
            realmList = [r.strip() for r in realms.split(",")]
            ret = setRealms(serial, realmList)

            g.audit["success"] = ret
            g.audit["info"] = realms
            g.audit["realm"] = realmList

            db.session.commit()
            return sendResult(response, ret, 1)

        except PolicyException as pe:
            log.error("[tokenrealm] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[tokenrealm] error setting realms for token %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    ########################################################

    def reset(self):
        """
        method:
            admin/reset

        description:
            reset the FailCounter of a Token

        arguments:
            user or serial - to identify the tokens

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        param = self.request_params

        serial = param.get("serial")
        user = getUserFromParam(param)

        try:

            # check admin authorization
            checkPolicyPre("admin", "reset", param, user=user)

            log.info(
                "[reset] resetting the FailCounter for token with serial %s",
                serial,
            )
            ret = resetToken(user, serial)

            g.audit["success"] = ret
            g.audit["user"] = user.login
            g.audit["realm"] = user.realm

            # DeleteMe: This code will never run, since getUserFromParam
            # always returns a realm!
            # if "" == g.audit['realm'] and "" != g.audit['user']:
            #    g.audit['realm'] = getDefaultRealm()

            opt_result_dict = {}
            if ret == 0 and serial:
                opt_result_dict["message"] = "No token with serial %s" % serial
            elif ret == 0 and user and not user.is_empty:
                opt_result_dict["message"] = "No tokens for this user"

            db.session.commit()
            return sendResult(response, ret, opt=opt_result_dict)

        except PolicyException as pe:
            log.error("[reset] policy failed %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[reset] Error resetting failcounter %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################

    def copyTokenPin(self):
        """
        method:
            admin/copyTokenPin

        description:
            copies the token pin from one token to another

        arguments:
            * from - required - serial of token from
            * to   - required - serial of token to

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        ret = 0
        err_string = ""
        param = self.request_params

        try:

            try:
                serial_from = param["from"]
            except KeyError:
                raise ParameterError("Missing parameter: 'from'")

            try:
                serial_to = param["to"]
            except KeyError:
                raise ParameterError("Missing parameter: 'to'")

            # check admin authorization
            checkPolicyPre("admin", "copytokenpin", param)

            th = TokenHandler()
            log.info(
                "[copyTokenPin] copying Pin from token %s to token %s",
                serial_from,
                serial_to,
            )
            ret = th.copyTokenPin(serial_from, serial_to)

            g.audit["success"] = ret
            g.audit["serial"] = serial_to
            g.audit["action_detail"] = "from %s" % serial_from

            err_string = str(ret)
            if -1 == ret:
                err_string = "can not get PIN from source token"
            if -2 == ret:
                err_string = "can not set PIN to destination token"
            if 1 != ret:
                g.audit["action_detail"] += ", " + err_string
                g.audit["success"] = 0

            db.session.commit()
            # Success
            if 1 == ret:
                return sendResult(response, True)
            else:
                return sendError(
                    response, "copying token pin failed: %s" % err_string
                )

        except PolicyException as pe:
            log.error("[losttoken] Error doing losttoken %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[copyTokenPin] Error copying token pin: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################

    def copyTokenUser(self):
        """
        method:
            admin/copyTokenUser

        description:
            copies the token user from one token to another

        arguments:
            * from - required - serial of token from
            * to   - required - serial of token to

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        ret = 0
        err_string = ""
        param = self.request_params

        try:

            try:
                serial_from = param["from"]
            except KeyError:
                raise ParameterError("Missing parameter: 'from'")

            try:
                serial_to = param["to"]
            except KeyError:
                raise ParameterError("Missing parameter: 'to'")

            # check admin authorization
            checkPolicyPre("admin", "copytokenuser", param)

            th = TokenHandler()
            log.info(
                "[copyTokenUser] copying User from token %s to token %s",
                serial_from,
                serial_to,
            )
            ret = th.copyTokenUser(serial_from, serial_to)

            g.audit["success"] = ret
            g.audit["serial"] = serial_to
            g.audit["action_detail"] = "from %s" % serial_from
            g.audit["source_realm"] = getTokenRealms(serial_from)
            g.audit["realm"] = getTokenRealms(serial_to)

            err_string = str(ret)
            if -1 == ret:
                err_string = "can not get user from source token"
            if -2 == ret:
                err_string = "can not set user to destination token"
            if 1 != ret:
                g.audit["action_detail"] += ", " + err_string
                g.audit["success"] = 0

            db.session.commit()
            # Success
            if 1 == ret:
                return sendResult(response, True)
            else:
                return sendError(
                    response, "copying token user failed: %s" % err_string
                )

        except PolicyException as pe:
            log.error("[copyTokenUser] Policy Exception %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[copyTokenUser] Error copying token user: %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################

    def losttoken(self):
        """
        method:
            admin/losttoken

        description:
            creates a new password token and copies the PIN and the
            user of the old token to the new token.
            The old token is disabled.

        arguments:
            * serial - serial of the old token
            * type   - optional, password, email or sms
            * email  - optional, email address, to overrule the owner email
            * mobile - optional, mobile number, to overrule the owner mobile

        returns:
            a json result with the new serial an the password

        exception:
            if an error occurs an exception is serialized and returned

        """

        ret = 0
        res = {}
        param = self.request_params.copy()

        try:
            serial = param["serial"]

            # check admin authorization
            checkPolicyPre("admin", "losttoken", param)
            th = TokenHandler()
            res = th.losttoken(serial, param=param)

            g.audit["success"] = ret
            g.audit["serial"] = res.get("serial")
            g.audit["action_detail"] = "from %s" % serial
            g.audit["source_realm"] = getTokenRealms(serial)
            g.audit["realm"] = getTokenRealms(g.audit["serial"])

            db.session.commit()
            return sendResult(response, res)

        except PolicyException as pe:
            log.error("[losttoken] Policy Exception: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[losttoken] Error doing losttoken %r", exx)
            db.session.rollback()
            return sendError(response, exx)

    ########################################################

    def loadtokens(self):
        """
        method:
            admin/loadtokens

        description:
            loads a whole token file to the server

        arguments:
            * file -  the file in a post request
            * type -  the file type.
            * realm - the target real of the tokens

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """
        res = "Loading token file failed!"
        known_types = ["aladdin-xml", "oathcsv", "yubikeycsv"]
        TOKENS = {}
        res = None

        sendResultMethod = sendResult
        sendErrorMethod = sendError

        from linotp.lib.ImportOTP import getKnownTypes

        known_types.extend(getKnownTypes())
        log.info(
            "[loadtokens] importing linotp.lib. Known import types: %s",
            known_types,
        )

        from linotp.lib.ImportOTP.PSKC import parsePSKCdata

        log.info("[loadtokens] loaded parsePSKCdata")

        from linotp.lib.ImportOTP.DPWplain import parseDPWdata

        log.info("[loadtokens] loaded parseDPWdata")

        from linotp.lib.ImportOTP.eTokenDat import parse_dat_data

        log.info("[loadtokens] loaded parseDATdata")

        params = self.request_params

        try:
            log.debug("[loadtokens] getting upload data")
            log.debug("[loadtokens] %r", request.params)
            tokenFile = request.files["file"]
            fileType = params["type"]
            targetRealm = params.get(
                "realm", params.get("targetrealm", "")
            ).lower()

            # for encrypted token import data, this is the decryption key
            transportkey = params.get("transportkey", None)
            if not transportkey:
                transportkey = None

            pskc_type = None
            pskc_password = None
            pskc_preshared = None
            pskc_checkserial = False

            hashlib = None

            if "pskc" == fileType:
                pskc_type = params["pskc_type"]
                pskc_password = params["pskc_password"]
                pskc_preshared = params["pskc_preshared"]
                if "pskc_checkserial" in params:
                    pskc_checkserial = True

            fileString = ""
            typeString = ""

            log.debug(
                "[loadtokens] loading token file to server "
                "Filetype: %s. File: %s",
                fileType,
                tokenFile,
            )

            # In case of form post requests, it is a "instance" of FileStorage
            # i.e. the Filename is selected in the browser and the data is
            # transferred in an iframe. see:
            # http://jquery.malsup.com/form/#sample4

            if isinstance(tokenFile, FileStorage):
                log.debug("[loadtokens] Field storage file: %s", tokenFile)
                fileString = tokenFile.read().decode()
                sendResultMethod = sendXMLResult
                sendErrorMethod = sendXMLError
            else:
                fileString = tokenFile
            log.debug("[loadtokens] fileString: %s", fileString)

            if isinstance(fileType, FileStorage):
                log.debug("[loadtokens] Field storage type: %s", fileType)
                typeString = fileType.read()
            else:
                typeString = fileType
            log.debug("[loadtokens] typeString: <<%s>>", typeString)
            if "pskc" == typeString:
                log.debug(
                    "[loadtokens] passing password: %s, key: %s, "
                    "checkserial: %s",
                    pskc_password,
                    pskc_preshared,
                    pskc_checkserial,
                )

            if fileString == "" or typeString == "":
                log.error("[loadtokens] file: %s", fileString)
                log.error("[loadtokens] type: %s", typeString)
                log.error(
                    "[loadtokens] Error loading/importing token file. "
                    "file or type empty!"
                )
                return sendErrorMethod(
                    response, ("Error loading tokens. File or Type empty!")
                )

            if typeString not in known_types:
                log.error(
                    "[loadtokens] Unknown file type: >>%s<<. "
                    "We only know the types: %s",
                    typeString,
                    ", ".join(known_types),
                )
                return sendErrorMethod(
                    response,
                    (
                        "Unknown file type: >>%s<<. We only know the "
                        "types: %s" % (typeString, ", ".join(known_types))
                    ),
                )

            # Parse the tokens from file and get dictionary
            if typeString == "aladdin-xml":
                TOKENS = parseSafeNetXML(fileString)
                # we only do hashlib for aladdin at the moment.
                if "aladdin_hashlib" in params:
                    hashlib = params["aladdin_hashlib"]

            elif typeString == "oathcsv":
                TOKENS = parseOATHcsv(fileString)

            elif typeString == "yubikeycsv":
                TOKENS = parseYubicoCSV(fileString)

            elif typeString == "dpw":
                TOKENS = parseDPWdata(fileString)

            elif typeString == "dat":
                startdate = params.get("startdate", None)
                TOKENS = parse_dat_data(fileString, startdate)

            elif typeString == "feitian":
                TOKENS = parsePSKCdata(fileString, do_feitian=True)

            elif typeString == "pskc":
                if "key" == pskc_type:
                    TOKENS = parsePSKCdata(
                        fileString,
                        preshared_key_hex=pskc_preshared,
                        do_checkserial=pskc_checkserial,
                    )

                elif "password" == pskc_type:
                    TOKENS = parsePSKCdata(
                        fileString,
                        password=pskc_password,
                        do_checkserial=pskc_checkserial,
                    )

                elif "plain" == pskc_type:
                    TOKENS = parsePSKCdata(
                        fileString, do_checkserial=pskc_checkserial
                    )

            tokenrealm = ""

            # -------------------------------------------------------------- --
            # first check if we are allowed to import the tokens at all
            # if not, this will raise a PolicyException

            rights = checkPolicyPre("admin", "import", {})

            # if an empty list of realms is returned, there is no admin policy
            # defined at all. So we grant access to all realms

            access_realms = rights.get("realms")
            if access_realms == []:
                access_realms = ["*"]

            # -------------------------------------------------------------- --

            # determin the admin realms

            available_realms = getRealms()

            if "*" in access_realms:

                admin_realms = available_realms

            else:

                # remove non existing realms from the admin realms

                admin_realms = list(set(available_realms) & set(access_realms))

                # this is a ugly unlogical case for legacy compliance

                if admin_realms:
                    tokenrealm = admin_realms[0]

            # -------------------------------------------------------------- --

            # determin the target tokenrealm

            if targetRealm:

                if targetRealm not in admin_realms:
                    raise Exception("target realm could not be assigned")

                tokenrealm = targetRealm

                # double check, if this is an allowed targetrealm

                checkPolicyPre(
                    "admin", "loadtokens", {"tokenrealm": tokenrealm}
                )

            log.info("[loadtokens] setting tokenrealm %r", tokenrealm)

            # -------------------------------------------------------------- --

            # Now import the Tokens from the dictionary

            log.debug(
                "[loadtokens] read %i tokens. starting import now", len(TOKENS)
            )

            ret = ""
            th = TokenHandler()
            for serial in TOKENS:
                log.debug("[loadtokens] importing token %s", TOKENS[serial])

                log.info(
                    "[loadtokens] initialize token. serial: %r, realm: %r",
                    serial,
                    tokenrealm,
                )

                # for the eToken dat we assume, that it brings all its
                # init parameters in correct format

                if typeString == "dat":
                    init_param = TOKENS[serial]

                else:
                    init_param = {
                        "serial": serial,
                        "type": TOKENS[serial]["type"],
                        "description": TOKENS[serial].get(
                            "description", "imported"
                        ),
                        "otpkey": TOKENS[serial]["hmac_key"],
                        "otplen": TOKENS[serial].get("otplen"),
                        "timeStep": TOKENS[serial].get("timeStep"),
                        "hashlib": TOKENS[serial].get("hashlib"),
                    }

                # add ocrasuite for ocra tokens, only if ocrasuite is not empty
                if TOKENS[serial]["type"] in ["ocra2"]:
                    if TOKENS[serial].get("ocrasuite", "") != "":
                        init_param["ocrasuite"] = TOKENS[serial].get(
                            "ocrasuite"
                        )

                if hashlib and hashlib != "auto":
                    init_param["hashlib"] = hashlib

                (ret, _tokenObj) = th.initToken(
                    init_param, User("", "", ""), tokenrealm=tokenrealm
                )

                # check policy to set token pin random
                checkPolicyPost("admin", "setPin", {"serial": serial})

            # check the max tokens per realm

            checkPolicyPost("admin", "loadtokens", {"tokenrealm": tokenrealm})

            log.info("[loadtokens] %i tokens imported.", len(TOKENS))
            res = {"value": True, "imported": len(TOKENS)}

            g.audit["info"] = "%s, %s (imported: %i)" % (
                fileType,
                tokenFile,
                len(TOKENS),
            )
            g.audit["serial"] = ", ".join(list(TOKENS.keys()))
            g.audit["success"] = ret
            g.audit["realm"] = tokenrealm

            db.session.commit()
            return sendResultMethod(response, res)

        except PolicyException as pex:
            log.error("[loadtokens] Failed checking policy: %r", pex)
            db.session.rollback()
            return sendError(response, "%r" % pex, 1)

        except Exception as exx:
            log.error("[loadtokens] failed! %r", exx)
            db.session.rollback()
            return sendErrorMethod(response, "%r" % exx)

    def _ldap_parameter_mapping(self, params):
        """
        translate the ui parameters into LDAPResolver format
        """

        # setup the ldap parameters including defaults

        ldap_params = {
            "NOREFERRALS": "True",
            "CACERTIFICATE": "",
            "EnforceTLS": "False",
        }

        mapping = {
            "ldap_basedn": "LDAPBASE",
            "ldap_uri": "LDAPURI",
            "ldap_binddn": "BINDDN",
            "ldap_password": "BINDPW",
            "ldap_timeout": "TIMEOUT",
            "ldap_basedn": "LDAPBASE",
            "ldap_loginattr": "LOGINNAMEATTRIBUTE",
            "ldap_searchfilter": "LDAPSEARCHFILTER",
            "ldap_userfilter": "LDAPFILTER",
            "ldap_mapping": "USERINFO",
            "ldap_uidtype": "UIDTYPE",
            "ldap_sizelimit": "SIZELIMIT",
            "noreferrals": "NOREFERRALS",
            "ldap_certificate": "CACERTIFICATE",
            "enforcetls": "EnforceTLS",
        }
        for key, value in list(params.items()):
            if key.lower() in mapping:
                ldap_params[mapping[key.lower()]] = value
            else:
                ldap_params[key] = value

        return ldap_params

    def testresolver(self):
        """
        method:
            admin/testresolver

        description:
            This method tests a useridresolvers configuration

        arguments:
            * type     - "LDAP": depending on the type there are other parameters:
                       - "SQL"

            * LDAP:
                * BINDDN
                * BINDPW
                * LDAPURI
                * TIMEOUT
                * LDAPBASE
                * LOGINNAMEATTRIBUTE
                * LDAPSEARCHFILTER
                * LDAPFILTER
                * USERINFO
                * LDAPSEARCHFILTER
                * SIZELIMIT
                * NOREFERRALS
                * CACERTIFICATE

            * SQL:
                * Driver
                * Server
                * Port
                * Database
                * User
                * Password
                * Table

        returns:
            a json result with a boolean
              "result": true

        exception:
            if an error occurs an exception is serialized and returned

        """

        try:
            request_params = self.request_params
            try:
                resolvername = self.request_params["name"]

            except KeyError as exx:
                raise ParameterError(_("Missing parameter: %r") % exx)

            if resolvername not in request_context["Resolvers"]:
                raise Exception("no such resolver %r defined!" % resolvername)

            # ---------------------------------------------------------- --

            # from the request context fetch the resolver details and
            # call the class method 'testconnection' with the retrieved
            # resolver configuration data

            resolver_info = getResolverInfo(resolvername)

            resolver_cls = get_resolver_class(resolver_info["type"])

            if not callable(resolver_cls.testconnection):
                raise Exception(
                    "resolver %r does not support a connection test",
                    resolvername,
                )

            (status, desc) = resolver_cls.testconnection(resolver_info["data"])

            res = {"result": status, "desc": desc}

            db.session.commit()
            return sendResult(response, res)

        except Exception as exx:
            log.error("[testresolver] failed: %r", exx)
            db.session.rollback()
            return sendError(response, exx, 1)

    def totp_lookup(self):
        """
        method:
            admin/totp_lookup - get otp iformation from a totp token

        arguments:
            * serial    - required -  serialnumber of the token
            * otp       - optional - to return status to the token
        """

        param = self.request_params
        try:

            serial = param.get("serial")
            if not serial:
                raise ParameterError("Missing parameter: 'serial'")

            g.audit["serial"] = serial

            otp = param.get("otp")
            if not otp:
                raise ParameterError("Missing parameter: 'otp'")

            window = param.get("window", "24h")

            # -------------------------------------------------------------- --

            # we require access to at least one token realm

            checkPolicyPre("admin", "totp_lookup", param=param)

            # -------------------------------------------------------------- --

            # lookup of serial and type totp

            tokens = getTokens4UserOrSerial(serial=serial, token_type="totp")

            if not tokens:
                g.audit["success"] = False
                g.audit["info"] = "no token found"
                return sendResult(response, False)

            token = tokens[0]

            # -------------------------------------------------------------- --

            # now gather the otp info from the token

            res, opt = token.get_otp_detail(otp=otp, window=window)
            g.audit["success"] = res

            if not res:
                g.audit["info"] = "no otp %r found in window %r" % (
                    otp,
                    window,
                )

            db.session.commit()
            return sendResult(response, res, opt=opt)

            # -------------------------------------------------------------- --

        except PolicyException as pe:
            log.error("[totp_lookup] policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe)

        except Exception as exx:
            log.error("[totp_lookup] failed: %r", exx)
            db.session.rollback()
            return sendResult(response, exx, 0)

    def checkstatus(self):
        """
        show the status either

        * of one dedicated challenge
        * of all challenges of a token
        * of all challenges belonging to all tokens of a user

        :param transactionid/state:  the transaction id of the challenge
        :param serial: serial number of the token - will show all challenges
        :param user:

        :return: json result of token and challenges

        """

        res = {}

        param = self.request_params.copy()
        only_open_challenges = True

        log.debug("[checkstatus] check challenge token status: %r", param)

        description = """
            admin/checkstatus: check the token status -
            for assynchronous verification. Missing parameter:
            You need to provide one of the parameters "transactionid", "user" or "serial"'
            """

        try:
            checkPolicyPre("admin", "checkstatus")

            transid = param.get("transactionid", None) or param.get(
                "state", None
            )
            user = getUserFromParam(param)
            serial = param.get("serial")
            all = param.get("open", "False").lower() == "true"

            if all:
                only_open_challenges = False

            if transid is None and user.is_empty and serial is None:
                # # raise exception
                log.error(
                    "[admin/checkstatus] : missing parameter: "
                    "transactionid, user or serial number for token"
                )
                raise ParameterError("Usage: %s" % description, id=77)

            # # gather all challenges from serial, transactionid and user
            challenges = set()
            if serial is not None:
                challenges.update(
                    Challenges.lookup_challenges(
                        serial=serial, filter_open=only_open_challenges
                    )
                )

            if transid is not None:
                challenges.update(
                    Challenges.lookup_challenges(
                        transid=transid, filter_open=only_open_challenges
                    )
                )

            # # if we have a user
            if not user.is_empty:
                tokens = getTokens4UserOrSerial(user=user)
                for token in tokens:
                    serial = token.getSerial()
                    challenges.update(
                        Challenges.lookup_challenges(
                            serial=serial, filter_open=True
                        )
                    )

            serials = set()
            for challenge in challenges:
                serials.add(challenge.getTokenSerial())

            status = {}
            # # sort all information by token serial number
            for serial in serials:
                stat = {}
                chall_dict = {}

                # # add the challenges info to the challenge dict
                for challenge in challenges:
                    if challenge.getTokenSerial() == serial:
                        chall_dict[
                            challenge.getTransactionId()
                        ] = challenge.get_vars(save=True)
                stat["challenges"] = chall_dict

                # # add the token info to the stat dict
                tokens = getTokens4UserOrSerial(serial=serial)
                token = tokens[0]
                stat["tokeninfo"] = token.get_vars(save=True)

                # # add the local stat to the summary status dict
                status[serial] = stat

            res["values"] = status
            g.audit["success"] = res

            db.session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.error("[checkstatus] policy failed: %r", pe)
            db.session.rollback()
            return sendError(response, pe)

        except Exception as exx:
            log.error("[checkstatus] failed: %r", exx)
            db.session.rollback()
            return sendResult(response, exx, 0)

    # ------------------------------------------------------------------------ -

    def unpair(self):
        """admin/unpair - resets a token to its unpaired state"""

        try:

            params = self.request_params.copy()

            serial = params.get("serial")
            user = getUserFromParam(params)

            # ---------------------------------------------------------------- -

            # check admin authorization

            checkPolicyPre("admin", "unpair", params, user=user)

            # ---------------------------------------------------------------- -

            tokens = getTokens4UserOrSerial(user, serial)

            if not tokens:
                raise Exception("No token found. Unpairing not possible")

            if len(tokens) > 1:
                raise Exception(
                    "Multiple tokens found. Unpairing not possible"
                )

            token = tokens[0]

            # ---------------------------------------------------------------- -

            # prepare some audit entries
            t_owner = token.getUser()

            realms = token.getRealms()
            realm = ""
            if realms:
                realm = realms[0]

            g.audit["user"] = t_owner or ""
            g.audit["realm"] = realm

            # ---------------------------------------------------------------- -

            token.unpair()
            db.session.commit()

            # ---------------------------------------------------------------- -

            return sendResult(response, True)

        # -------------------------------------------------------------------- -

        except Exception as exx:
            log.error("admin/unpair failed: %r", exx)
            g.audit["info"] = str(exx)
            db.session.rollback()
            return sendResult(response, False, 0, status=False)


# eof ########################################################################

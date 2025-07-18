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
"""
gettoken controller - to retrieve OTP values
"""

import logging

from flask import current_app, g, request

from linotp.controllers.base import BaseController
from linotp.flap import render_mako as render
from linotp.flap import tmpl_context as c
from linotp.lib import deprecated_methods
from linotp.lib.config import getFromConfig
from linotp.lib.context import request_context
from linotp.lib.policy import PolicyException, checkPolicyPre
from linotp.lib.reply import sendError, sendResult
from linotp.lib.token import get_multi_otp, get_tokens, getOtp, getTokenType
from linotp.lib.type_utils import boolean
from linotp.lib.user import (
    getUserFromRequest,
)
from linotp.lib.util import getParam
from linotp.model import db

optional = True
required = False

log = logging.getLogger(__name__)


class GettokenController(BaseController):
    """
    The linotp.controllers are the implementation of the web-API to talk to
    the LinOTP server. The ValidateController is used to validate the username
    with its given OTP value.

    The Tagespasswort Token uses this controller to retrieve the current
    OTP value of the Token and be able to set it in the application
    The functions of the GettokenController are invoked like this

        https://server/gettoken/<functionname>

    The functions are described below in more detail.
    """

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        g.audit["administrator"] = getUserFromRequest()
        if "serial" in request.args:
            serial = request.args["serial"]
            g.audit["serial"] = serial
            g.audit["token_type"] = getTokenType(serial)

        current_app.audit_obj.log(g.audit)

        return response

    @deprecated_methods(["POST"])
    def getmultiotp(self):
        """
        This function is used to retrieve multiple otp values for a given user
        or a given serial. If the user has more than one token, the list of
        the tokens is returend.

        :param serial: the serial number of the token
        :param count: number of otp values to return

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        getotp_active = boolean(getFromConfig("linotpGetotp.active", False))
        if not getotp_active:
            return sendError("getotp is not activated.", 0)

        param = self.request_params
        ret = {}

        try:
            serial = getParam(param, "serial", required)
            count = int(getParam(param, "count", required))
            curTime = getParam(param, "curTime", optional)
            view = getParam(param, "view", optional)

            r1 = checkPolicyPre("admin", "getotp", param)
            log.debug("[getmultiotp] admin-getotp policy: %s", r1)

            max_count = checkPolicyPre("gettoken", "max_count", param)
            log.debug("[getmultiotp] maxcount policy: %s", max_count)
            count = min(count, max_count)

            log.debug("[getmultiotp] retrieving OTP value for token %s", serial)
            ret = get_multi_otp(serial, count=int(count), curTime=curTime)
            ret["serial"] = serial

            g.audit["success"] = True
            db.session.commit()

            if view:
                c.ret = ret
                return render("/selfservice/multiotp_view.mako").decode("utf-8")
            else:
                return sendResult(ret, 0)

        except PolicyException as pe:
            log.error("[getotp] gettoken/getotp policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[getmultiotp] gettoken/getmultiotp failed: %r", exx)
            db.session.rollback()
            return sendError(f"gettoken/getmultiotp failed: {exx!r}", 0)

    @deprecated_methods(["POST"])
    def getotp(self):
        """
        This function is used to retrieve the current otp value for a given
        user or a given serial. If the user has more than one token, the list
        of the tokens is returend.

        :param user: username / loginname
        :param realm: additional realm to match the user to a useridresolver
        :param serial: the serial number of the token
        :param curTime: used ONLY for internal testing: datetime.datetime object

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        getotp_active = boolean(getFromConfig("linotpGetotp.active", False))
        if not getotp_active:
            return sendError("getotp is not activated.", 0)

        param = self.request_params
        ret = {}
        res = -1
        otpval = ""
        passw = ""
        serials = []

        try:
            serial = getParam(param, "serial", optional)
            user = request_context["RequestUser"]
            curTime = getParam(param, "curTime", optional)

            if serial:
                log.debug("[getotp] retrieving OTP value for token %s", serial)
            elif user.login:
                log.debug(
                    "[getotp] retrieving OTP value for token for user %s@%s",
                    user.login,
                    user.realm,
                )

                toks = get_tokens(user, serial)
                tokennum = len(toks)

                if tokennum > 1:
                    log.debug(
                        "[getotp] The user has more than one token."
                        "Returning the list of serials"
                    )
                    res = -3
                    serials = [token.getSerial() for token in toks]
                elif tokennum == 1:
                    serial = toks[0].getSerial()
                    log.debug(
                        "[getotp] retrieving OTP for token %s for user %s@%s",
                        serial,
                        user.login,
                        user.realm,
                    )
                else:
                    log.debug(
                        "[getotp] no token found for user %s@%s",
                        user.login,
                        user.realm,
                    )
                    res = -4
            else:
                res = -5

            # if a serial was given or a unique serial could be
            # received from the given user.

            if serial:
                max_count = checkPolicyPre("gettoken", "max_count", param)
                log.debug("[getmultiotp] max_count policy: %s", max_count)
                if max_count <= 0:
                    return sendError(
                        "The policy forbids receiving"
                        f" OTP values for the token {serial} in "
                        "this realm",
                        1,
                    )

                (res, pin, otpval, passw) = getOtp(serial, curTime=curTime)

            g.audit["success"] = True

            if int(res) < 0:
                ret["result"] = False
                error_messages = {
                    -1: "No Token with this serial number",
                    -2: "This Token does not support the getOtp function",
                    -3: "The user has more than one token",
                    -4: "No Token found for this user",
                    -5: "You need to provide a user or a serial",
                }
                ret["description"] = error_messages.get(res, f"Unexpected error: {res}")
                if res == -3:
                    ret["serials"] = serials
            else:
                ret["result"] = True
                ret["otpval"] = otpval
                ret["pin"] = pin
                ret["pass"] = passw

            db.session.commit()
            return sendResult(ret, 0)

        except PolicyException as pe:
            log.error("[getotp] gettoken/getotp policy failed: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[getotp] gettoken/getotp failed: %r", exx)
            db.session.rollback()
            return sendError(f"gettoken/getotp failed: {exx}", 0)


# eof###########################################################################

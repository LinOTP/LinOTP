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
"""
selfservice controller - This is the controller for the self service interface,
                where users can manage their own tokens

"""
import base64
import logging
import os

from flask_babel import gettext as _
from mako.exceptions import CompileException
from werkzeug.exceptions import Forbidden, Unauthorized

from flask import Response, current_app, g, redirect, url_for

from linotp.controllers.base import BaseController
from linotp.controllers.userservice import get_auth_user, getTokenForUser
from linotp.flap import config
from linotp.flap import render_mako as render
from linotp.flap import request
from linotp.flap import tmpl_context as c
from linotp.lib import deprecated_methods
from linotp.lib.context import request_context
from linotp.lib.error import ParameterError
from linotp.lib.policy import _get_auth_PinPolicy
from linotp.lib.policy.action import get_selfservice_actions
from linotp.lib.realm import getDefaultRealm, getRealms
from linotp.lib.reply import sendError
from linotp.lib.selfservice import get_imprint
from linotp.lib.user import getRealmBox
from linotp.lib.userservice import (
    add_dynamic_selfservice_enrollment,
    add_dynamic_selfservice_policies,
    check_session,
    get_pre_context,
    remove_auth_cookie,
)
from linotp.lib.util import (
    get_client,
    get_copyright_info,
    get_version,
    remove_empty_lines,
)
from linotp.model import db
from linotp.tokens import tokenclass_registry

ENCODING = "utf-8"
log = logging.getLogger(__name__)


class SelfserviceController(BaseController):
    default_url_prefix = "/selfservice-legacy"

    jwt_exempt = True  # Don't do JWT auth in this controller

    authUser = None

    # the following actions don't require a session parameter
    # as they are only callbacks to render a form
    form_access_methods = [
        "assign",
        "custom_style",
        "delete",
        "disable",
        "enable",
        "getotp",
        "history",
        "index",
        "landing",
        "load_form",
        "reset",
        "resync",
        "setmpin",
        "setpin",
        "unassign",
        "webprovisiongoogletoken",
        "webprovisionoathtoken",
    ]

    def __before__(self, **params):
        """
        __before__ is called before every action

        This is the authentication to self service. If you want to do
        ANYTHING with the selfservice, you need to be authenticated. The
        _before_ is executed before any other function in this controller.

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        action = request_context["action"]

        try:
            c.version = get_version()
            c.licenseinfo = get_copyright_info()
            c.version_ref = base64.encodebytes(c.version.encode())[:6]

            g.authUser = None
            g.client = get_client(request)

            # -------------------------------------------------------------- --

            # handle requests which dont require authetication

            if action in ["logout", "custom_style"]:
                return

            # -------------------------------------------------------------- --

            # get the authenticated user

            auth_type, auth_user, auth_state = get_auth_user(request)

            # -------------------------------------------------------------- --

            # handle not authenticated requests

            if not auth_user or auth_type not in ["user_selfservice"]:
                if action in ["login"]:
                    return

                if action in ["index"]:
                    return redirect(url_for(".login"))

                else:
                    raise Unauthorized("No valid session")

            # -------------------------------------------------------------- --

            # handle authenticated requests

            # there is only one special case, which is the login that
            # could be forwarded to the index page

            if action in ["login"]:
                if auth_state != "authenticated":
                    return

                return redirect(url_for(".index"))

            # -------------------------------------------------------------- --

            # in case of user_selfservice, an unauthenticated request should
            # always go to login
            if (
                auth_user
                and auth_type == "user_selfservice"
                and auth_state != "authenticated"
            ):
                return redirect(url_for(".login"))

            # futher processing with the authenticated user

            if auth_state != "authenticated":
                raise Unauthorized("No valid session")

            c.user = auth_user.login
            c.realm = auth_user.realm
            g.authUser = auth_user

            # -------------------------------------------------------------- --

            # authenticated session verification

            if auth_type == "user_selfservice":
                # checking the session only for not_form_access actions
                if action not in self.form_access_methods:
                    valid_session = check_session(request, auth_user, g.client)

                    if not valid_session:
                        g.audit["action"] = request.path[1:]
                        g.audit["info"] = "session expired"
                        current_app.audit_obj.log(g.audit)

                        raise Unauthorized("No valid session")

            # -------------------------------------------------------------- --

            c.imprint = get_imprint(c.realm)

            c.tokenArray = []

            c.user = g.authUser.login
            c.realm = g.authUser.realm

            # only the defined actions should be displayed
            # - remark: the generic actions like enrollTT are allready approved
            #   to have a rendering section and included
            actions = get_selfservice_actions(g.authUser)
            c.actions = actions

            for action_name, action_value in actions.items():
                setattr(
                    c,
                    action_name,
                    -1 if action_value is True else action_value,
                )

            c.dynamic_actions = add_dynamic_selfservice_enrollment(
                config, c.actions
            )

            # all token policies need to be initialized for selfservice controller
            additional_policies = add_dynamic_selfservice_policies(
                config, actions
            )
            for policy in additional_policies:
                c.__setattr__(policy, -1)

            c.otplen = -1
            c.totp_len = -1

            c.pin_policy = _get_auth_PinPolicy(user=g.authUser)

        except (Unauthorized, Forbidden) as acc:
            # the exception, when an abort() is called if forwarded
            log.info("[__before__::%r] webob.exception %r", action, acc)
            db.session.rollback()
            raise acc

        except Exception as exx:
            log.error("[__before__] failed with error: %r", exx)
            db.session.rollback()
            return sendError(exx, context="before")

    @deprecated_methods(["POST"])
    def index(self):
        """
        This is the redirect to the first template
        """

        c.title = _("LinOTP Self Service")
        return render("selfservice/base.mako")

    @deprecated_methods(["POST"])
    def logout(self):
        """
        handle the logout

        we delete the cookies from the server and the client and
        redirect to the login page
        """

        redirect_response = redirect(url_for(".login"))

        if request.cookies.get("user_selfservice"):
            remove_auth_cookie(request.cookies.get("user_selfservice"))
            redirect_response.delete_cookie("user_selfservice")

        return redirect_response

    @deprecated_methods(["POST"])
    def login(self):
        """
        render the selfservice login page
        """

        c.title = _("LinOTP Self Service Login")

        # ------------------------------------------------------------------ --

        # prepare the realms and put the default realm on the top

        defaultRealm = getDefaultRealm()

        # domain-knowledge: defaultRealm is the first realm
        realmArray = [defaultRealm] + [
            realm for realm in getRealms() if realm != defaultRealm
        ]

        # ------------------------------------------------------------------ --

        # prepare the global context c for the rendering context

        c.defaultRealm = defaultRealm
        c.realmArray = realmArray

        c.realmbox = getRealmBox()

        context = get_pre_context(g.audit["client"])

        mfa_login = bool(context["settings"]["mfa_login"])
        mfa_3_fields = bool(context["settings"]["mfa_3_fields"])
        c.mfa_login = mfa_login
        c.mfa_3_fields = mfa_login and mfa_3_fields

        response = Response(render("/selfservice/login.mako"))

        if request.cookies.get("user_selfservice"):
            remove_auth_cookie(request.cookies.get("user_selfservice"))
            response.delete_cookie("user_selfservice")

        return response

    @deprecated_methods(["POST"])
    def load_form(self):
        """
        This shows the enrollment form for a requested token type.

        implicit parameters are:

        :param type: token type
        :param scope: defines the rendering scope

        :return: rendered html of the requested token
        """
        res = ""

        tok = None
        section = None
        scope = None

        try:
            try:
                act = self.request_params["type"]
            except KeyError:
                raise ParameterError("Missing parameter: 'type'", id=905)

            try:
                (tok, section, scope) = act.split(".")
            except Exception:
                return res

            if section != "selfservice":
                return res

            if tok in tokenclass_registry:
                tclt = tokenclass_registry.get(tok)
                if hasattr(tclt, "getClassInfo"):
                    sections = tclt.getClassInfo(section, {})
                    if scope in list(sections.keys()):
                        section = sections.get(scope)
                        page = section.get("page")
                        c.scope = page.get("scope")
                        c.authUser = g.authUser
                        html = page.get("html")
                        res = render(os.path.sep + html).decode()
                        res = remove_empty_lines(res)

            db.session.commit()
            return res

        except CompileException as exx:
            log.error(
                "[load_form] compile error while processing %r.%r:"
                "Exeption was %r",
                tok,
                scope,
                exx,
            )
            db.session.rollback()
            raise exx

        except Exception as exx:
            db.session.rollback()
            error = (
                "error (%r) accessing form data for: tok:%r, scope:%r"
                ", section:%r" % (exx, tok, scope, section)
            )
            log.error(error)
            return "<h1>{}</h1><pre>{} {}</pre>".format(
                _("Failed to load form"), _("Error"), exx
            )

    @deprecated_methods(["POST"])
    def custom_style(self):
        """
        In case the user hasn't defined a custom css, Pylons calls this action.
        Return an empty file instead of a 404 (which would mean hitting the
        debug console)
        """
        return ""

    @deprecated_methods(["POST"])
    def assign(self):
        """
        In this form the user may assign an already existing Token to himself.
        For this, the user needs to know the serial number of the Token.
        """
        return render("/selfservice/assign.mako")

    @deprecated_methods(["POST"])
    def resync(self):
        """
        In this form, the user can resync an HMAC based OTP token
        by providing two OTP values
        """
        return render("/selfservice/resync.mako")

    @deprecated_methods(["POST"])
    def reset(self):
        """
        In this form the user can reset the Failcounter of the Token.
        """
        return render("/selfservice/reset.mako")

    @deprecated_methods(["POST"])
    def getotp(self):
        """
        In this form, the user can retrieve OTP values
        """
        return render("/selfservice/getotp.mako")

    @deprecated_methods(["POST"])
    def disable(self):
        """
        In this form the user may select a token of his own and
        disable this token.
        """
        return render("/selfservice/disable.mako")

    @deprecated_methods(["POST"])
    def enable(self):
        """
        In this form the user may select a token of his own and
        enable this token.
        """
        return render("/selfservice/enable.mako")

    @deprecated_methods(["POST"])
    def unassign(self):
        """
        In this form the user may select a token of his own and
        unassign this token.
        """
        return render("/selfservice/unassign.mako")

    @deprecated_methods(["POST"])
    def delete(self):
        """
        In this form the user may select a token of his own and
        delete this token.
        """
        return render("/selfservice/delete.mako")

    @deprecated_methods(["POST"])
    def setpin(self):
        """
        In this form the user may set the OTP PIN, which is the static password
        he enters when logging in in front of the otp value.
        """
        return render("/selfservice/setpin.mako")

    @deprecated_methods(["POST"])
    def setmpin(self):
        """
        In this form the user my set the PIN for his mOTP application soft
        token on his phone. This is the pin, he needs to enter on his phone,
        before a otp value will be generated.
        """
        return render("/selfservice/setmpin.mako")

    @deprecated_methods(["POST"])
    def history(self):
        """
        This is the form to display the history table for the user
        """
        return render("/selfservice/history.mako")

    @deprecated_methods(["POST"])
    def landing(self):
        """
        This is the landing page for selfservice
        """
        c.tokenArray = getTokenForUser(g.authUser)
        return render("/selfservice/landing.mako")

    @deprecated_methods(["POST"])
    def webprovisionoathtoken(self):
        """
        This is the form for an oathtoken to do web provisioning.
        """
        return render("/selfservice/webprovisionoath.mako")

    @deprecated_methods(["POST"])
    def webprovisiongoogletoken(self):
        """
        This is the form for an google token to do web provisioning.
        """
        try:
            c.actions = get_selfservice_actions(g.authUser)
            return render("/selfservice/webprovisiongoogle.mako")

        except Exception as exx:
            log.error("[webprovisiongoogletoken] failed with error: %r", exx)
            return sendError(exx)

    @deprecated_methods(["POST"])
    def usertokenlist(self):
        """
        This returns a tokenlist as html output
        """
        c.tokenArray = getTokenForUser(g.authUser)
        res = render("/selfservice/tokenlist.mako")
        return res


# eof #

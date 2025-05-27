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
manage controller - In provides the web gui management interface
"""

import base64
import json
import logging
import os

from flask_babel import gettext as _
from mako.exceptions import CompileException

from flask import current_app, g, request

import linotp
from linotp.controllers.base import BaseController, jwt_exempt, methods
from linotp.flap import config
from linotp.flap import render_mako as render
from linotp.flap import tmpl_context as c
from linotp.lib import deprecated_methods
from linotp.lib.config import getFromConfig
from linotp.lib.context import request_context
from linotp.lib.error import ParameterError
from linotp.lib.ImportOTP import getImportText
from linotp.lib.policy import PolicyException, checkPolicyPre, getAdminPolicies
from linotp.lib.policy.definitions import get_policy_definitions
from linotp.lib.realm import getRealms
from linotp.lib.reply import sendError, sendResult
from linotp.lib.token import getTokenType

# Our Token stuff
from linotp.lib.tokeniterator import TokenIterator
from linotp.lib.type_utils import boolean
from linotp.lib.user import (
    User,
    get_userinfo,
    getUserFromParam,
    getUserFromRequest,
    getUserList,
)
from linotp.lib.util import get_copyright_info, get_version, remove_empty_lines
from linotp.model import db
from linotp.tokens import tokenclass_registry

log = logging.getLogger(__name__)


class ManageController(BaseController):
    def __before__(self, **params):
        """
        __before__ is called before every action

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        action = request_context["action"]

        try:
            c.version = get_version()
            c.version_ref = base64.encodebytes(c.version.encode())[:6]

            c.licenseinfo = get_copyright_info()
            c.polDefs = get_policy_definitions()

            c.display_provider = boolean(
                request_context["Config"].get("display_provider", True)
            )

            # -------------------------------------------------------------- --

            # check for support of setting admin password
            c.admin_can_change_password = (
                "linotpadmin.user" in config and "linotpadmin.password" in config
            )
            c.app_config_trusted_proxies = current_app.config["TRUSTED_PROXIES"]
            c.app_config_CLIENT_PARAM_ENABLED = current_app.config[
                "GET_CLIENT_ADDRESS_FROM_POST_DATA"
            ]

        except Exception as exx:
            log.error("[__before__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(exx)

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        if g.audit["action"] in [
            "manage/tokenview_flexi",
            "manage/userview_flexi",
        ]:
            g.audit["administrator"] = getUserFromRequest()
            if "serial" in request.args:
                serial = request.args["serial"]
                g.audit["serial"] = serial
                g.audit["token_type"] = getTokenType(serial)

            g.audit["action_detail"] += linotp.lib.audit.base.get_token_num_info()
            current_app.audit_obj.log(g.audit)

        return response

    @jwt_exempt
    @deprecated_methods(["POST"])
    def index(self):
        """
        This is the main function of the management web UI
        """

        try:
            c.debug = current_app.config["DEBUG"]
            c.title = "LinOTP Management"

            c.importers = getImportText()
            log.debug("[index] importers: %s", c.importers)

            c.help_url = config["HELP_URL"].format(linotp.__version__)

            # -------------------------------------------------------------- --

            # check for support of setting admin password

            c.admin_can_change_password = (
                "linotpadmin.user" in config and "linotpadmin.password" in config
            )

            # -------------------------------------------------------------- --

            # add render info for token type config
            confs = _getTokenTypeConfig("config")
            try:
                c.token_config_tab = {
                    conf: v["title"] for conf, v in confs.items() if v.get("title")
                }
                c.token_config_div = {
                    conf: v["html"] for conf, v in confs.items() if v.get("html")
                }
            except Exception as exx:
                c.token_config_tab = {}
                c.token_config_div = {}
                log.debug(
                    "[index] no config info for a token type (%r)",
                    exx,
                )

            #  add the enrollment fragments from the token definition
            enrolls = _getTokenTypeConfig("init")
            try:
                c.token_enroll_tab = {
                    conf: v["title"] for conf, v in enrolls.items() if v.get("title")
                }
                c.token_enroll_div = {
                    conf: v["html"] for conf, v in enrolls.items() if v.get("html")
                }
            except Exception as exx:
                c.token_config_tab = {}
                c.token_config_div = {}
                log.debug(
                    "[index] no enrollment info for a token type (%r)",
                    exx,
                )

            c.tokentypes = _getTokenTypes()

            db.session.commit()
            ren = render("/manage/manage-base.mako")
            return ren

        except PolicyException as pe:
            log.error("[index] Error during checking policies: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as ex:
            log.error("[index] failed! %r", ex)
            db.session.rollback()
            raise

    @jwt_exempt
    @deprecated_methods(["POST"])
    def login(self):
        """
        Render the Manage-UI login page
        """
        c.debug = current_app.config["DEBUG"]

        return render("manage/login.mako")

    @deprecated_methods(["POST"])
    def tokentype(self):
        """
        render the tokentype info mako
        """
        c.title = "TokenTypeInfo"
        ttinfo = [tok for tok in tokenclass_registry.keys()]
        for tok in tokenclass_registry:
            tclass_object = tokenclass_registry.get(tok)
            if hasattr(tclass_object, "getClassType"):
                ii = tclass_object.getClassType()
                ttinfo.append(ii)

        c.tokeninfo = ttinfo

        return render("/manage/tokentypeinfo.mako").decode("utf-8")

    @deprecated_methods(["POST"])
    def policies(self):
        """
        This is the template for the policies TAB
        """
        c.title = "LinOTP Management - Policies"
        return render("/manage/policies.mako").decode("utf-8")

    @deprecated_methods(["POST"])
    def audittrail(self):
        """
        This is the template for the audit trail TAB
        """
        c.title = "LinOTP Management - Audit Trail"
        return render("/manage/audit.mako").decode("utf-8")

    @deprecated_methods(["POST"])
    def tokenview(self):
        """
        This is the template for the token TAB
        """
        c.title = "LinOTP Management"
        c.tokenArray = []
        c.getotp_active = boolean(getFromConfig("linotpGetotp.active", False))
        return render("/manage/tokenview.mako")

    @deprecated_methods(["POST"])
    def userview(self):
        """
        This is the template for the token TAB
        """
        c.title = "LinOTP Management"
        c.tokenArray = []
        return render("/manage/userview.mako").decode("utf-8")

    @deprecated_methods(["POST"])
    def custom_style(self):
        """
        If this action was called, the user hasn't created a custom css yet. To avoid hitting
        the debug console over and over, we serve an empty file.
        """
        return ""

    @deprecated_methods(["POST"])
    def tokenview_flexi(self):
        """
        This function is used to fill the flexigrid.
        Unlike the complex /admin/show function, it only returns a
        simple array of the tokens.

        :param page:
        :param query:
        :param qtype:
        :param sortname:
        :param sortorder:
        :param rp:

        :return:
            json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        param = self.request_params

        try:
            c.page = param.get("page")
            c.filter = param.get("query")
            c.qtype = param.get("qtype")
            c.sort = param.get("sortname")
            c.dir = param.get("sortorder")
            c.psize = param.get("rp")

            filter_all = None
            filter_realm = None
            user = User()

            if c.qtype == "loginname":
                # we take by default the given expression as a loginname,
                # especially if it contains a "*" wildcard.
                # it only might be more, a user and a realm, if there
                # is an '@' sign in the loginname and the part after the
                # last '@' sign is matching an existing realm

                user = User(login=c.filter)

                if "*" not in c.filter and "@" in c.filter:
                    login, _, realm = c.filter.rpartition("@")

                    if realm.lower() in getRealms():
                        user = User(login, realm)
                        if not user.exists():
                            user = User(login=c.filter)

            elif c.qtype == "all":
                filter_all = c.filter

            elif c.qtype == "realm":
                filter_realm = c.filter

            # check admin authorization
            res = checkPolicyPre("admin", "show", param, user=user)

            filterRealm = res["realms"]
            # check if policies are active at all
            # If they are not active, we are allowed to SHOW any tokens.
            pol = getAdminPolicies("show")
            # If there are no admin policies, we are allowed to see all realms
            if not pol["active"]:
                filterRealm = ["*"]

            # check if we only want to see ONE realm or see all realms we are
            # allowerd to see.
            if filter_realm:
                if filter_realm in filterRealm or "*" in filterRealm:
                    filterRealm = [filter_realm]

            log.debug(
                "[tokenview_flexi] admin >%s< may display the following realms: %s",
                pol["admin"],
                pol["realms"],
            )
            log.debug(
                "[tokenview_flexi] page: %s, filter: %s, sort: %s, dir: %s",
                c.page,
                c.filter,
                c.sort,
                c.dir,
            )

            if c.page is None:
                c.page = 1
            if c.psize is None:
                c.psize = 20

            log.debug(
                "[tokenview_flexi] calling TokenIterator for user=%s@%s, "
                "filter=%s, filterRealm=%s",
                user.login,
                user.realm,
                filter_all,
                filterRealm,
            )
            c.tokenArray = TokenIterator(
                user,
                None,
                c.page,
                c.psize,
                filter_all,
                c.sort,
                c.dir,
                filterRealm=filterRealm,
            )
            c.resultset = c.tokenArray.getResultSetInfo()
            # If we have chosen a page to big!
            lines = [
                {
                    "id": tok["LinOtp.TokenSerialnumber"],
                    "cell": [
                        tok["LinOtp.TokenSerialnumber"],
                        tok["LinOtp.Isactive"],
                        tok["User.username"],
                        tok["LinOtp.RealmNames"],
                        tok["LinOtp.TokenType"],
                        tok["LinOtp.FailCount"],
                        tok["LinOtp.TokenDesc"],
                        tok["LinOtp.MaxFail"],
                        tok["LinOtp.OtpLen"],
                        tok["LinOtp.CountWindow"],
                        tok["LinOtp.SyncWindow"],
                        (
                            tok["LinOtp.Userid"].decode("utf-8")
                            if isinstance(tok["LinOtp.Userid"], bytes)
                            else tok["LinOtp.Userid"]
                        ),
                        tok["LinOtp.IdResClass"].split(".")[-1],
                    ],
                }
                for tok in c.tokenArray
            ]

            # We need to return 'page', 'total', 'rows'
            res = {
                "page": int(c.page),
                "total": c.resultset["tokens"],
                "rows": lines,
            }

            g.audit["success"] = True

            db.session.commit()
            # The flexi handler should support std LinOTP output
            return sendResult(res)

        except PolicyException as pe:
            log.error("[tokenview_flexi] Error during checking policies: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[tokenview_flexi] failed: %r", exx)
            db.session.rollback()
            return sendError(exx)

    @deprecated_methods(["POST"])
    def userview_flexi(self):
        """
        This function is used to fill the flexigrid.
        Unlike the complex /admin/userlist function, it only returns a
        simple array of the tokens.

        :param page:
        :param query:
        :param qtype:
        :param sortname:
        :param sortorder:
        :param rp:
        :param realm:

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        param = self.request_params

        try:
            c.page = param.get("page")
            c.filter = param.get("query")
            qtype = param.get("qtype")
            c.sort = param.get("sortname")
            c.dir = param.get("sortorder")
            c.psize = param.get("rp")
            c.realm = param.get("realm")

            user = request_context["RequestUser"]
            # check admin authorization
            # check if we got a realm or resolver, that is ok!
            checkPolicyPre("admin", "userlist", {"user": user.login, "realm": c.realm})

            if c.filter == "":
                c.filter = "*"

            log.debug(
                "[userview_flexi] page: %s, filter: %s, sort: %s, dir: %s",
                c.page,
                c.filter,
                c.sort,
                c.dir,
            )

            if c.page is None:
                c.page = 1
            if c.psize is None:
                c.psize = 20

            c.userArray = getUserList({qtype: c.filter, "realm": c.realm}, user)
            c.userNum = len(c.userArray)

            lines = []
            for u in c.userArray:
                # shorten the useridresolver, to get a better display value
                resolver_display = ""
                if "useridresolver" in u:
                    if len(u["useridresolver"].split(".")) > 3:
                        resolver_display = (
                            u["useridresolver"].split(".")[3]
                            + " ("
                            + u["useridresolver"].split(".")[1]
                            + ")"
                        )
                    else:
                        resolver_display = u["useridresolver"]
                lines.append(
                    {
                        "id": u["username"],
                        "cell": [
                            (u["username"]) if "username" in u else (""),
                            (resolver_display),
                            (u["surname"]) if "surname" in u else (""),
                            (u["givenname"]) if "givenname" in u else (""),
                            (u["email"]) if "email" in u else (""),
                            (u["mobile"]) if "mobile" in u else (""),
                            (u["phone"]) if "phone" in u else (""),
                            (u["userid"]) if "userid" in u else (""),
                        ],
                    }
                )

            # sorting
            reverse = False
            sortnames = {
                "username": 0,
                "useridresolver": 1,
                "surname": 2,
                "givenname": 3,
                "email": 4,
                "mobile": 5,
                "phone": 6,
                "userid": 7,
            }
            if c.dir == "desc":
                reverse = True

            lines = sorted(
                lines,
                key=lambda user: user["cell"][sortnames[c.sort]],
                reverse=reverse,
            )
            # end: sorting

            # reducing the page
            if c.page and c.psize:
                page = int(c.page)
                psize = int(c.psize)
                start = psize * (page - 1)
                end = start + psize
                lines = lines[start:end]

            # We need to return 'page', 'total', 'rows'
            res = {"page": int(c.page), "total": c.userNum, "rows": lines}

            g.audit["success"] = True

            db.session.commit()
            return sendResult(res)

        except PolicyException as pe:
            log.error("[userview_flexi] Error during checking policies: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[userview_flexi] failed: %r", exx)
            db.session.rollback()
            return sendError(exx)

    @deprecated_methods(["POST"])
    def tokeninfo(self):
        """
        this returns the contents of /admin/show?serial=xyz in an html format

        :param serial: the token serial


        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        param = self.request_params

        try:
            try:
                serial = param["serial"]
            except KeyError:
                raise ParameterError("Missing parameter: 'serial'")

            filterRealm = ""
            # check admin authorization
            res = checkPolicyPre("admin", "show", param)

            # check if policies are active at all
            # If they are not active, we are allowed to SHOW any tokens.
            filterRealm = ["*"]
            if res["active"] and res["realms"]:
                filterRealm = res["realms"]

            log.info(
                "[tokeninfo] admin >%s< may display the following realms: %s",
                res["admin"],
                filterRealm,
            )
            log.info("[tokeninfo] displaying tokens: serial: %s", serial)

            toks = TokenIterator(User("", "", ""), serial, filterRealm=filterRealm)

            token_info = next(toks, {})
            c.tokeninfo = token_info

            for k in c.tokeninfo:
                if "LinOtp.TokenInfo" == k:
                    try:
                        # Try to convert string to Dictionary
                        c.tokeninfo["LinOtp.TokenInfo"] = json.loads(
                            c.tokeninfo["LinOtp.TokenInfo"]
                        )
                    except BaseException:
                        pass

            return render("/manage/tokeninfo.mako").decode("utf-8")

        except PolicyException as pe:
            log.error("[tokeninfo] Error during checking policies: %r", pe)
            db.session.rollback()
            return sendError(pe, 1)

        except Exception as exx:
            log.error("[tokeninfo] failed! %r", exx)
            db.session.rollback()
            return sendError(exx)

    @deprecated_methods(["POST"])
    def help(self, id=None):
        """
        This downloads the Manual

        The filename will be the 3. part,ID
        https://172.16.200.6/manage/help/somehelp.pdf
        The file is downloaded through Flask!

        """

        try:
            directory = config.get("linotpManual.Directory", "/usr/share/doc/linotp")
            default_filename = config.get("linotpManual.File", "LinOTP_Manual-en.pdf")
            mimetype = "application/pdf"
            headers = []

            # FIXME: Compression is better done using
            # `Content-Encoding` (ideally farther up the WSGI stack).

            # if not id:
            #     id = default_filename + ".gz"
            #     mimetype = "application/x-gzip"  # iffy

            id = id or default_filename

            r = flask.send_file(
                "%s/%s" % (directory, id),
                mimetype=mimetype,
                as_attachment=True,
                attachment_filename=default_filename,
            )
            db.session.commit()
            return r

        except Exception as exx:
            log.error("[help] Error loading helpfile: %r", exx)
            db.session.rollback()
            return sendError(exx)

    # ------------------------------------------------------------------------ -
    @methods(["GET"])
    def context(self):
        """
        provide session context for the manage ui
        - the output is structured similar to the userservice/context

        NOTE: the context might be extended to further needs

        :return: linotp json response with detail structure containing
                 the context information
        """

        try:
            user = getUserFromRequest()
            logged_in_admin: User = g.authUser

            response_detail = {
                "version": get_version(),
                "copyright": get_copyright_info(),
                "user": get_userinfo(user),
                "permissions": logged_in_admin.getPermissions().parse_for_context_api(),
            }
            return sendResult(True, opt=response_detail)

        except Exception as exx:
            log.error("manage/context failed: %r", exx)
            g.audit["info"] = str(exx)
            db.session.rollback()
            return sendError(exx)


# ###########################################################


def _getTokenTypes():
    """
    _getTokenTypes - retrieve the list of dynamic tokens and their title section

    :return: dict with token type and title
    :rtype:  dict
    """

    tinfo = {}

    for tclass_object in set(tokenclass_registry.values()):
        tok = tclass_object.getClassType()
        if hasattr(tclass_object, "getClassInfo"):
            tinfo[tok] = _(tclass_object.getClassInfo("title") or tok)

    return tinfo


def _getTokenTypeConfig(section="config"):
    """
    _getTokenTypeConfig - retrieve from the dynamic token the
                        tokentype section, eg. config or enroll

    :param section: the section of the tokentypeconfig
    :type  section: string

    :return: dict with tab and page definition (rendered)
    :rtype:  dict
    """

    res = {}

    for tclass_object in set(tokenclass_registry.values()):
        tok = tclass_object.getClassType()

        if hasattr(tclass_object, "getClassInfo"):
            conf = tclass_object.getClassInfo(section, ret={})

            # set globale render scope, so that the mako
            # renderer will return only a subsection from the template
            p_html = ""
            t_html = ""
            try:
                page = conf.get("page")
                c.scope = page.get("scope")
                p_html = render(os.path.sep + page.get("html")).decode("utf-8")
                p_html = remove_empty_lines(p_html)

                tab = conf.get("title")
                c.scope = tab.get("scope")
                t_html = render(os.path.sep + tab.get("html")).decode("utf-8")
                t_html = remove_empty_lines(t_html)

            except CompileException as cex:
                log.error(
                    "[_getTokenTypeConfig] compile error while processing %r.%r:",
                    tok,
                    section,
                )
                raise Exception(cex)

            except Exception as exx:
                log.debug("no config for token type %r (%r)", tok, exx)
                p_html = ""

            if len(p_html) > 0:
                res[tok] = {"html": p_html, "title": t_html}

    return res


############################################################

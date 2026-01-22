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
monitoring controller - interfaces to monitor LinOTP
"""

import logging

from flask import current_app, g

from linotp.controllers.base import BaseController
from linotp.flap import tmpl_context as c
from linotp.lib import deprecated_methods
from linotp.lib.context import request_context
from linotp.lib.error import HSMException
from linotp.lib.monitoring import MonitorHandler
from linotp.lib.policy import (
    PolicyException,
    checkAuthorisation,
    getAdminPolicies,
)
from linotp.lib.realm import match_realms
from linotp.lib.reply import sendError, sendResult
from linotp.lib.support import (
    InvalidLicenseException,
    getSupportLicenseInfo,
    verifyLicenseInfo,
)
from linotp.lib.token import getNumTokenUsers, getTokenNumResolver
from linotp.lib.user import getUserFromRequest
from linotp.model import db

log = logging.getLogger(__name__)


class MonitoringController(BaseController):
    """
    monitoring
    """

    def __before__(self, **params):
        """
        __before__ is called before every action

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        action = request_context["action"]

        try:
            checkAuthorisation(scope="monitoring", method=action)
        except Exception as exx:
            log.exception("[__before__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(exx)

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        action = request_context["action"]

        try:
            g.audit["administrator"] = getUserFromRequest()

            current_app.audit_obj.log(g.audit)
            db.session.commit()
            return response

        except Exception as exx:
            log.exception("[__after__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(exx)

        finally:
            db.session.close()

    @deprecated_methods(["POST"])
    def tokens(self):
        """
        Displays the number of tokens (with status) per realm
        (one token might be in multiple realms).
        The Summary gives the sum of all tokens in all given realms and
        might be smaller than the summ of all tokens
        as tokens which have two realms are only counted once!

        :param status: (optional) takes assigned or unassigned, give the number
                of tokens with this characteristic

        :param realms: (optional) takes realms, only the number of tokens in
                these realms will be displayed


        :return:
            a json result with:
            { "head": [],
            "data": [ [row1], [row2] .. ]
            }

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        result = {}
        try:
            # extract and strip the list of requested statuses + default
            # statuses and ignore empty values.

            status_params = self.request_params.get("status", "").split(",")
            status = list(
                set(
                    ["total", "total users"]
                    + [s.strip() for s in status_params if s.strip()]
                )
            )

            request_realms = self.request_params.get("realms", "").split(",")

            monit_handler = MonitorHandler()
            realm_whitelist = []

            policies = getAdminPolicies("tokens", scope="monitoring")

            if policies["active"] and policies["realms"]:
                realm_whitelist = policies.get("realms")

            # if there are no policies for us, we are allowed to see all realms
            if not realm_whitelist or "*" in realm_whitelist:
                realm_whitelist = list(request_context["Realms"].keys())

            realms = match_realms(request_realms, realm_whitelist)

            realm_info = {
                a_realm: monit_handler.token_count([a_realm], status)
                for a_realm in realms
            }

            result["Summary"] = monit_handler.token_count(realms, status)
            result["Realms"] = realm_info

            db.session.commit()
            return sendResult(result)

        except PolicyException as pol_ex:
            log.error(pol_ex)
            db.session.rollback()
            return sendError(pol_ex, 1)

        except Exception as exx:
            log.exception(exx)
            db.session.rollback()
            return sendError(exx)

    @deprecated_methods(["POST"])
    def config(self):
        """
        check if Config- Database exists

        touches DB and checks if date of last read is new

        :return:
            a json result with:
            { "head": [],
            "value": {"sync": "True"}
            }

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        result = {}
        try:
            monit_handler = MonitorHandler()
            result = monit_handler.get_sync_status()

            # useful counts:
            counts = monit_handler.get_config_info()

            result.update(counts)

            ldap = 13 * result["ldapresolver"]
            sql = 12 * result["sqlresolver"]
            policies = 7 * result["policies"]
            realms = result["realms"]
            passwd = result["passwdresolver"]
            total = result["total"]

            result["netto"] = total - ldap - sql - passwd - policies - realms

            return sendResult(result)

        except Exception as exx:
            log.exception(exx)
            return sendError(exx)

    @deprecated_methods(["POST"])
    def storageEncryption(self):
        """
        check if hsm/enckey encrypts value before storing it to config db

        :return:
            a json result with true if a new value gets encryptet before beeing stored in db

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        try:
            if hasattr(c, "hsm") is False or isinstance(c.hsm, dict) is False:
                msg = "no hsm defined in execution context!"
                raise HSMException(msg)

            hsm = c.hsm.get("obj")
            if hsm is None or hsm.isReady() is False:
                msg = "hsm not ready!"
                raise HSMException(msg)

            hsm_class = str(type(hsm))
            enc_type = hsm_class.split(".")[-1]
            enc_type = enc_type.strip("'>")
            enc_name = hsm.name
            res = {"cryptmodul_type": enc_type, "cryptmodul_name": enc_name}

            monit_handler = MonitorHandler()
            res["encryption"] = monit_handler.check_encryption()

            return sendResult(res, 1)

        except Exception as exx:
            log.exception(exx)
            return sendError(exx)

    @deprecated_methods(["POST"])
    def license(self):
        """
        license
        return the support status, which is community support by default
        or the support subscription info, which could be the old license

        :return:
            json result with license info

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        res = {}
        try:
            try:
                license_info, license_sig = getSupportLicenseInfo()
            except InvalidLicenseException as err:
                if err.type != "UNLICENSED":
                    raise err
                opt = {"valid": False, "message": f"{err!r}"}
                return sendResult({}, 1, opt=opt)

            # Add Extra info
            # if needed; use details = None ... for no details!)...

            license_ok, license_msg = verifyLicenseInfo(license_info, license_sig)
            if not license_ok:
                res = {"valid": license_ok, "message": license_msg}
                return sendResult(res, 1)

            if "user-num" in license_info:
                res["user-num"] = int(license_info.get("user-num", 0))
                active_usercount = getNumTokenUsers()
                res["user-active"] = active_usercount
                res["user-left"] = res["user-num"] - active_usercount

            else:
                res["token-num"] = int(license_info.get("token-num", 0))
                active_tokencount = getTokenNumResolver()
                res["token-active"] = active_tokencount
                res["token-left"] = res["token-num"] - active_tokencount

            return sendResult(res, 1)

        except Exception as exx:
            log.exception(exx)
            return sendError(exx)

    @deprecated_methods(["POST"])
    def userinfo(self):
        """

        for each realm, display the resolvers and the number of users
        per resolver

        :param realms: (optional) takes a realm, only information on this realm
                will be displayed

        :return:
            a json result with:
            { "head": [],
            "data": [ [row1], [row2] .. ]
            }

        """
        result = {}
        try:
            request_realms = self.request_params.get("realms", "").split(",")

            monit_handler = MonitorHandler()

            policies = getAdminPolicies("userinfo", scope="monitoring")

            realm_whitelist = []
            if policies["active"] and policies["realms"]:
                realm_whitelist = policies.get("realms")

            # if there are no policies for us, we are allowed to see all realms
            if not realm_whitelist or "*" in realm_whitelist:
                realm_whitelist = list(request_context["Realms"].keys())

            realms = match_realms(request_realms, realm_whitelist)

            if "/:no realm:/" in realms:
                realms.remove("/:no realm:/")

            realm_info = {realm: monit_handler.resolverinfo(realm) for realm in realms}

            result["Realms"] = realm_info

            db.session.commit()
            return sendResult(result)

        except PolicyException as pol_ex:
            log.error(pol_ex)
            db.session.rollback()
            return sendError(pol_ex, 1)

        except Exception as exx:
            log.exception(exx)
            db.session.rollback()
            return sendError(exx)

    @deprecated_methods(["POST"])
    def activeUsers(self):
        """

        for each realm, display the resolvers and
        the number of users which have at least one assigned active token
        per resolver
        the 'total' gives the number of all users, which are in an allowed
        realm and own an active token
        users are conted per resolver (not per realm), so if resolver is in
        multiple realms and one user ons tokens in 2 realms, the user will
        be counted only once

        :param realms: (optional) takes realms, only information on these realms
                will be displayed

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """
        result = {}
        try:
            request_realms = self.request_params.get("realms", "").split(",")

            monit_handl = MonitorHandler()

            policies = getAdminPolicies("activeUsers", scope="monitoring")

            realm_whitelist = []
            if policies["active"] and policies["realms"]:
                realm_whitelist = policies.get("realms")

            # if there are no policies for us, we are allowed to see all realms
            if not realm_whitelist or "*" in realm_whitelist:
                realm_whitelist = list(request_context["Realms"].keys())

            realms = match_realms(request_realms, realm_whitelist)

            realm_info = {
                realm: monit_handl.active_users_per_realm(realm) for realm in realms
            }

            result["Realms"] = realm_info
            result["total"] = monit_handl.active_users_total(realms)

            return sendResult(result)

        except PolicyException as pol_ex:
            log.error(pol_ex)
            db.session.rollback()
            return sendError(pol_ex, 1)

        except Exception as exx:
            log.exception(exx)
            db.session.rollback()
            return sendError(exx)

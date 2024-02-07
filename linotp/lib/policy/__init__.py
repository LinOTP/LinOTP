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

""" policy processing """

import logging
import re
from copy import deepcopy
from typing import Dict

from flask_babel import gettext as _

from flask import g

import linotp
import linotp.lib.support
import linotp.lib.token
from linotp.lib.config.parsing import ConfigNotRecognized, ConfigTree
from linotp.lib.context import request_context
from linotp.lib.context import request_context as context
from linotp.lib.error import LinotpError, ParameterError
from linotp.lib.policy.action import get_action_value
from linotp.lib.policy.definitions import SYSTEM_ACTIONS
from linotp.lib.policy.maxtoken import check_maxtoken
from linotp.lib.policy.processing import (
    get_client_policy,
    getPolicy,
    has_client_policy,
    is_authorized,
    search_policy,
)
from linotp.lib.policy.util import (
    _get_client,
    _get_pin_values,
    _getAuthenticatedUser,
    _getDefaultRealm,
    _getLinotpConfig,
    _getRealms,
    _getUserFromParam,
    _getUserRealms,
    ascii_lowercase,
    ascii_uppercase,
    digits,
    get_realm_from_policies,
    get_resolvers_for_realms,
    letters,
    parse_action_value,
    special_characters,
)
from linotp.lib.realm import getRealms
from linotp.lib.user import User, getResolversOfUser

# for generating random passwords
from linotp.lib.util import generate_password, uniquify

from .action import get_selfservice_actions

log = logging.getLogger(__name__)

# This dictionary maps the token_types to actions in the scope gettoken,
# that define the maximum allowed otp valies in case of getotp/getmultiotp
MAP_TYPE_GETOTP_ACTION = {
    "dpw": "max_count_dpw",
    "hmac": "max_count_hotp",
    "totp": "max_count_totp",
}


class PolicyException(LinotpError):
    """Generic exception class for unspecified policy violations."""

    error_code = 410

    def __init__(self, description="unspecified error!"):
        LinotpError.__init__(self, description=description, id=self.error_code)


class MaxTokenUserPolicyException(PolicyException):
    """Token count policy violation of a user across all token types."""

    error_code = 411


class MaxTokenTypeUserPolicyException(PolicyException):
    """Token count policy violation of a user for a single token type."""

    error_code = 412


class MaxTokenRealmPolicyException(PolicyException):
    """Token count policy violation in a realm."""

    error_code = 413


class AuthorizeException(LinotpError):
    def __init__(self, description="unspecified error!"):
        LinotpError.__init__(self, description=description, id=510)


# ---------------------------------------------------------------------------- -

# on module load integrate the policy config parser into the
# ConfigTree class


def parse_policy(composite_key, value):
    """Parses policy data from a config entry"""

    if not composite_key.startswith("linotp.Policy"):
        raise ConfigNotRecognized(composite_key)

    parts = composite_key.split(".")

    if len(parts) != 4:
        raise ConfigNotRecognized(composite_key)

    object_id = parts[2]
    attr_name = parts[3]

    return object_id, {attr_name: value}


ConfigTree.add_parser("policies", parse_policy)

# ---------------------------------------------------------------------------- -


def checkAuthorisation(scope, method):
    """Check if the authenticated user has the right to do the given action.

    :param scope: scope of the policy to be checked
    :param method: the requested action
    :return: nothing if authorized, else raise PolicyException
    """

    admin_user = _getAuthenticatedUser()

    if not is_authorized(admin_user, scope, method):
        log.warning("the user >%r< is not allowed to do %s", admin_user, scope)

        ret = _(
            "You do not have the administrative right to do this. You are "
            "missing a policy scope=%s, action=%s"
        ) % (scope, method)

        raise PolicyException(ret)


def _checkAdminPolicyPost(
    method: str, param: Dict[str, str] = None, user: User = None
) -> Dict:
    """Check post conditions for admin operations.

    :param method: the scope of the calling
    :param param: the parameters given to this method
    :param user: the user for whom the operations should be made
    :return: dict with some setting
    """

    ret = {}
    controller = "admin"

    log.debug("entering controller %s", controller)
    log.debug("entering method %s", method)
    log.debug("using params %r", param)

    if not param:
        param = {}

    serial = param.get("serial")

    if user is None:
        user = _getUserFromParam()

    # ------------------------------------------------------------------ --

    # check for supported methods - should become obsolete

    if method not in [
        "init",
        "assign",
        "enable",
        "setPin",
        "loadtokens",
        "getserial",
    ]:
        log.error("an unknown method <<%s>> was passed.", method)

        raise PolicyException(
            _("Failed to run getPolicyPost. Unknown method: %s") % method
        )

    # ------------------------------------------------------------------ --

    # set random pin, if policy is given

    if method in ["init", "assign", "setPin"]:
        randomPINLength = _getRandomOTPPINLength(user)
        if randomPINLength > 0:
            new_pin = createRandomPin(user, min_pin_length=randomPINLength)

            log.debug(
                "setting random pin for token with serial %s and user: %s",
                serial,
                user,
            )

            linotp.lib.token.setPin(new_pin, None, serial)

            log.debug("pin set")

            ret["new_pin"] = new_pin

    # ------------------------------------------------------------------ --

    # check the enrollment.tokencount policy compliance

    if method in ["assign", "init", "enable"]:
        if not _check_token_count(realm=user.realm, post_check=True):
            admin = _getAuthenticatedUser()

            log.warning(
                "the admin >%r< is not allowed to enroll any more "
                "tokens for the realm %r",
                admin,
                user.realm,
            )

            raise PolicyException(
                _(
                    "The maximum allowed number of tokens "
                    "for the realm %r was reached. You can"
                    " not init any more tokens. Check the "
                    "policies scope=enrollment, "
                    "action=tokencount."
                )
                % user.realm
            )

    # ---------------------------------------------------------------------- --

    # check the enrollment.tokencount policy compliance

    if method == "loadtokens":
        tokenrealm = param.get("tokenrealm", user.realm)

        if not _check_token_count(realm=tokenrealm, post_check=True):
            admin = _getAuthenticatedUser()

            log.warning(
                "the maximum tokens for the realm %s is exceeded.",
                tokenrealm,
            )

            raise MaxTokenRealmPolicyException(
                _(
                    "The maximum number of allowed tokens in realm %r is exceeded."
                    " Check policy tokencount!"
                )
                % tokenrealm
            )

    # ---------------------------------------------------------------------- --

    # check if the that returned serial/token is in the realms of the admin!

    if method == "getserial":
        policies = getAdminPolicies("getserial")
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, User("", "", "")
        ):
            log.warning(
                "the admin >%r< is not allowed to get serial of token %s",
                policies["admin"],
                serial,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to get serials from this realm!"
                )
            )

    # ---------------------------------------------------------------------- --

    # enforce license restrictions

    if method in ["assign", "init", "enable", "loadtokens"]:
        if linotp.lib.support.check_license_restrictions():
            log.warning(
                "The maximum allowed number of tokens "
                "for your license is reached"
            )
            linotp.lib.support.check_license_restrictions()

            raise linotp.lib.support.LicenseException(
                _(
                    "No more tokens can be enrolled"
                    " due to license restrictions"
                )
            )

    return ret


def _checkSystemPolicyPost(method, param=None, user=None):
    ret = {}
    controller = "system"
    admin_user = _getAuthenticatedUser()

    log.debug("entering controller %s", controller)

    if method == "getRealms":
        res = param["realms"]

        if not is_authorized(admin_user, "system", "read"):
            # If the admin is not allowed to see all realms,
            # (policy scope=system, action=read)
            # the realms, where he has no administrative rights need,
            # to be stripped.
            pol = getAdminPolicies("")
            if pol["active"]:
                log.debug(
                    "the admin has policies in these realms: %r",
                    pol["realms"],
                )

                lowerRealms = uniquify(pol["realms"])
                for realm, _v in list(res.items()):
                    if (
                        realm.lower() not in lowerRealms
                        and "*" not in lowerRealms
                    ):
                        log.debug(
                            "the admin has no policy in realm %r. "
                            "Deleting it: %r",
                            realm,
                            res,
                        )

                        del res[realm]
            else:
                log.error(
                    "system: : getRealms: The admin >%s< is not "
                    "allowed to read system config and has not "
                    "realm administrative rights!",
                    admin_user,
                )

                raise PolicyException(
                    _(
                        "You do not have system config read "
                        "rights and not realm admin "
                        "policies."
                    )
                )

        ret["realms"] = res
    return ret


def _checkSelfservicePolicyPost(method, param=None, user=None):
    ret = {}
    controller = "selfservice"

    log.debug("entering controller %s", controller)
    log.debug("entering method %s", method)
    log.debug("using params %s", param)

    serial = param.get("serial")

    if user is None:
        user = _getUserFromParam()

    if method == "enroll":
        # check if we are supposed to genereate a random OTP PIN
        randomPINLength = _getRandomOTPPINLength(user)

        if randomPINLength > 0:
            new_pin = createRandomPin(user, min_pin_length=randomPINLength)

            log.debug(
                "setting random pin for token with serial %s and user: %s",
                serial,
                user,
            )

            linotp.lib.token.setPin(new_pin, None, serial)

            log.debug("[init] pin set")
            # TODO: This random PIN could be processed and
            # printed in a PIN letter
            ret["new_pin"] = new_pin

    # -------------------------------------------------------------------- --

    # for selfservice "enroll" we check the license limits
    # - this hook covers both, the 'enroll' and the 'webprovision' userservice

    if method == "enroll":
        if linotp.lib.support.check_license_restrictions():
            raise linotp.lib.support.LicenseException(
                _(
                    "No more tokens can be enrolled"
                    " due to license restrictions"
                )
            )

    return ret


def _checkAdminPolicyPre(method, param=None, authUser=None, user=None):
    # we have to declare the imports localy to prevent cyclic imports

    ret = {}

    if not param:
        param = {}

    serial = param.get("serial")
    if user is None:
        user = _getUserFromParam()

    realm = param.get("realm")
    if realm is None or len(realm) == 0:
        realm = _getDefaultRealm()

    # ---------------------------------------------------------------------- --

    # check the maxtoken policy
    #   which restricts the number of tokens for the user in a realm

    check_maxtoken(method, user=user or authUser, param=param)

    # ---------------------------------------------------------------------- --

    if method == "show":
        log.debug("[checkPolicyPre] entering method %s", method)

        # the 'allowed to list the tokens' / 'admin/show' permission:
        #  the admin/show permission is an implicit permission by the means
        #  that an admin is allowed to list the tokens for any realm he is
        #  allowed to access via policies where any action is defined.

        policies = getAdminPolicies("")

        log.debug(
            "[checkPolicyPre] The admin >%r< may manage the "
            "following realms: %s",
            policies["admin"],
            policies["realms"],
        )

        if policies["active"] and len(policies["realms"]) == 0:
            log.error(
                "[checkPolicyPre] The admin >%r< has no rights in "
                "any realms!",
                policies["admin"],
            )

            raise PolicyException(
                _(
                    "You do not have any rights in any "
                    "realm! Check the policies."
                )
            )
        return {
            "realms": policies["realms"],
            "admin": policies["admin"],
            "active": policies["active"],
        }

    elif method == "totp_lookup":
        policies = getAdminPolicies("totp_lookup")

        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "the admin >%r< is not allowed to get token info for "
                " realm %r",
                policies["admin"],
                realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to get token info in "
                    "this realm!"
                )
            )

    elif method == "remove":
        policies = getAdminPolicies("remove")
        # FIXME: A token that belongs to multiple realms should not be
        #        deleted. Should it? If an admin has the right on this
        #        token, he might be allowed to delete it,
        #        even if the token is in other realms.
        # We could use fitAllRealms=True
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "the admin >%r< is not allowed to remove token %r for "
                "user %r@%r",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to remove token %r. Check the "
                    "policies."
                )
                % serial
            )

    elif method == "enable":
        policies = getAdminPolicies("enable")
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "[enable] the admin >%r< is not allowed to enable "
                "token %r for user %r@%r",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to enable token %s. Check the "
                    "policies."
                )
                % serial
            )

        if linotp.lib.support.check_license_restrictions():
            raise linotp.lib.support.LicenseException(
                _(
                    "No more tokens can be enabled"
                    " due to license restrictions"
                )
            )

        if not _check_token_count():
            log.error("The maximum token number is reached!")
            raise PolicyException(
                _(
                    "You may not enable any more tokens. "
                    "Your maximum token number is "
                    "reached!"
                )
            )

        # We need to check which realm the token will be in.
        realmList = linotp.lib.token.getTokenRealms(serial)
        for r in realmList:
            if not _check_token_count(realm=r):
                log.warning(
                    "the maximum tokens for the realm %s is exceeded.", r
                )

                raise PolicyException(
                    _(
                        "You may not enable any more tokens "
                        "in realm %s. Check the policy "
                        "'tokencount'"
                    )
                    % r
                )

    elif method == "disable":
        policies = getAdminPolicies("disable")
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "the admin >%s< is not allowed to disable token %s for"
                " user %s@%s",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to disable token %s. Check the "
                    "policies."
                )
                % serial
            )

    elif method == "copytokenpin":
        policies = getAdminPolicies("copytokenpin")
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "the admin >%s< is not allowed to copy token pin of "
                "token %s for user %s@%s",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to copy PIN of token %s. Check "
                    "the policies."
                )
                % serial
            )

    elif method == "copytokenuser":
        policies = getAdminPolicies("copytokenuser")
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "the admin >%s< is not allowed to copy token user of "
                "token %s for user %s@%s",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to copy user of token %s. Check "
                    "the policies."
                )
                % serial
            )

    elif method == "losttoken":
        policies = getAdminPolicies("losttoken")
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "the admin >%s< is not allowed to run "
                "the losttoken workflow for token %s for "
                "user %s@%s",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to run the losttoken workflow "
                    "for token %s. Check the "
                    "policies."
                )
                % serial
            )

    elif method == "getotp":
        policies = getAdminPolicies("getotp")
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "the admin >%s< is not allowed to run the getotp "
                "workflow for token %s for user %s@%s",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to run the getotp workflow for "
                    "token %s. Check the policies."
                )
                % serial
            )

    elif method == "getserial":
        policies = getAdminPolicies("getserial")
        # check if we want to search the token in certain realms
        if realm is not None:
            dummy_user = User("dummy", realm, None)
        else:
            dummy_user = User("", "", "")
            # We need to allow this, as no realm was passed at all.
            policies["realms"] = "*"
        if policies["active"] and not checkAdminAuthorization(
            policies, None, dummy_user
        ):
            log.warning(
                "the admin >%s< is not allowed to get serials for user"
                " %s@%s",
                policies["admin"],
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to get serials by OTPs in "
                    "this realm!"
                )
            )

    elif method == "init":
        ttype = param.get("type")
        # possible actions are:
        # initSPASS,     initHMAC,    initETNG, initSMS,     initMOTP
        policies = {}
        # default: we got HMAC / ETNG
        log.debug("[checkPolicyPre] checking init action")

        if linotp.lib.support.check_license_restrictions():
            raise linotp.lib.support.LicenseException(
                _(
                    "No more tokens can be enrolled"
                    " due to license restrictions"
                )
            )

        if (not ttype) or (ttype and (ttype.lower() == "hmac")):
            p1 = getAdminPolicies("initHMAC")
            p2 = getAdminPolicies("initETNG")
            policies = {
                "active": p1["active"],
                "admin": p1["admin"],
                "realms": list(set(p1["realms"] + p2["realms"])),
                "resolvers": p1["resolvers"] + p2["resolvers"],
            }
        else:
            # See if there is a policy like initSPASS or ....
            token_type_list = linotp.lib.token.get_token_type_list()
            token_type_found = False

            for tt in token_type_list:
                if tt.lower() == ttype.lower():
                    policies = getAdminPolicies("init%s" % tt.upper())
                    token_type_found = True
                    break

            if not token_type_found:
                policies = {}
                log.error("Unknown token type: %s", ttype)
                raise Exception(
                    _("The tokentype '%s' could not be found.") % ttype
                )

        # We need to assure, that an admin does not enroll a token into a
        # realm were he has no ACCESS! : -(
        # The admin may not enroll a token with a serial, that is already
        # assigned to a user outside of his realm

        # if a user is given, we need to check the realm of this user
        log.debug("checking realm of the user")
        if policies["active"] and (
            user.login != ""
            and not checkAdminAuthorization(policies, "", user)
        ):
            log.warning(
                "the admin >%s< is not allowed to enroll token %s of "
                "type %s to user %s@%s",
                policies["admin"],
                serial,
                ttype,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to init token %s of type %s to "
                    "user %s@%s. Check the policies."
                )
                % (serial, ttype, user.login, user.realm)
            )

        # no right to enroll token in any realm
        log.debug("checking enroll token at all")
        if policies["active"] and len(policies["realms"]) == 0:
            log.warning(
                "the admin >%s< is not allowed to enroll a token at all.",
                policies["admin"],
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to enroll tokens. Check the "
                    "policies."
                )
            )

        # the token is assigned to a user, not in the realm of the admin!
        # we only need to check this, if the token already exists. If
        # this is a new token, we do not need to check this.
        log.debug("checking for token existens")

        if policies["active"] and linotp.lib.token.tokenExist(serial):
            if not checkAdminAuthorization(policies, serial, ""):
                log.warning(
                    "the admin >%s< is not allowed to enroll token %s "
                    "of type %s.",
                    policies["admin"],
                    serial,
                    ttype,
                )

                raise PolicyException(
                    _(
                        "You do not have the administrative "
                        "right to init token %s of type %s."
                    )
                    % (serial, ttype)
                )

        log.debug("checking tokens in realm for user %r", user)
        if user and not _check_token_count(user=user):
            log.warning(
                "the admin >%s< is not allowed to enroll any more "
                "tokens for the realm %s",
                policies["admin"],
                user.realm,
            )

            raise PolicyException(
                _(
                    "The maximum allowed number of tokens "
                    "for the realm %r was reached. You can "
                    "not init any more tokens. Check the "
                    "policies scope=enrollment, "
                    "action=tokencount."
                )
                % user.realm
            )

        # ==== End of policy check 'init' ======
        ret["realms"] = policies["realms"]

    elif method == "unassign":
        policies = getAdminPolicies("unassign")
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "the admin >%s< is not allowed to unassign token %s "
                "for user %s@%s",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to unassign token %s. Check the "
                    "policies."
                )
                % serial
            )

    elif method == "assign":
        policies = getAdminPolicies("assign")

        # the token is assigned to a user, not in the realm of the admin!
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, ""
        ):
            log.warning(
                "the admin >%s< is not allowed to assign token %s. ",
                policies["admin"],
                serial,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to assign token %s. "
                    "Check the policies."
                )
                % (serial)
            )

        if linotp.lib.support.check_license_restrictions():
            raise linotp.lib.support.LicenseException(
                _(
                    "No more tokens can be assigned"
                    " due to license restrictions"
                )
            )

        # The user, the token should be assigned to,
        # is not in the admins realm
        if policies["active"] and not checkAdminAuthorization(
            policies, "", user
        ):
            log.warning(
                "the admin >%s< is not allowed to assign "
                "token %s for user %s@%s",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to assign token %s. Check the "
                    "policies."
                )
                % serial
            )

    elif method == "setPin":
        if "userpin" in param:
            if "userpin" not in param:
                raise ParameterError(
                    _("Missing parameter: %r") % "userpin", id=905
                )

            # check admin authorization
            policies1 = getAdminPolicies("setSCPIN")
            policies2 = getAdminPolicies("setMOTPPIN")
            _usr = User("", "", "")
            if (
                policies1["active"]
                and not (checkAdminAuthorization(policies1, serial, _usr))
            ) or (
                policies2["active"]
                and not (checkAdminAuthorization(policies2, serial, _usr))
            ):
                log.warning(
                    "the admin >%s< is not allowed to set MOTP PIN/SC "
                    "UserPIN for token %s.",
                    policies1["admin"],
                    serial,
                )

                raise PolicyException(
                    _(
                        "You do not have the administrative "
                        "right to set MOTP PIN/ SC UserPIN "
                        "for token %s. Check the policies."
                    )
                    % serial
                )

        if "sopin" in param:
            if "sopin" not in param:
                raise ParameterError(
                    _("Missing parameter: %r") % "sopin", id=905
                )

            # check admin authorization
            policies = getAdminPolicies("setSCPIN")
            if policies["active"] and not checkAdminAuthorization(
                policies, serial, User("", "", "")
            ):
                log.warning(
                    "the admin >%s< is not allowed to setPIN for token %s.",
                    policies["admin"],
                    serial,
                )

                raise PolicyException(
                    _(
                        "You do not have the administrative "
                        "right to set Smartcard PIN for "
                        "token %s. Check the policies."
                    )
                    % serial
                )

    elif method == "set":
        if "pin" in param:
            policies = getAdminPolicies("setOTPPIN")
            if policies["active"] and not checkAdminAuthorization(
                policies, serial, user
            ):
                log.warning(
                    "the admin >%s< is not allowed to set "
                    "OTP PIN for token %s for user %s@%s",
                    policies["admin"],
                    serial,
                    user.login,
                    user.realm,
                )

                raise PolicyException(
                    _(
                        "You do not have the administrative "
                        "right to set OTP PIN for token %s. "
                        "Check the policies."
                    )
                    % serial
                )

        if (
            "MaxFailCount".lower() in param
            or "SyncWindow".lower() in param
            or "CounterWindow".lower() in param
            or "OtpLen".lower() in param
        ):
            policies = getAdminPolicies("set")

            if policies["active"] and not checkAdminAuthorization(
                policies, serial, user
            ):
                log.warning(
                    "the admin >%s< is not allowed to set "
                    "token properites for %s for user %s@%s",
                    policies["admin"],
                    serial,
                    user.login,
                    user.realm,
                )

                raise PolicyException(
                    _(
                        "You do not have the administrative "
                        "right to set token properties for "
                        "%s. Check the policies."
                    )
                    % serial
                )

    elif method == "resync":
        policies = getAdminPolicies("resync")
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "the admin >%s< is not allowed to resync token %s for "
                "user %s@%s",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to resync token %s. Check the "
                    "policies."
                )
                % serial
            )

    elif method == "userlist":
        policies = getAdminPolicies("userlist")
        # check if the admin may view the users in this realm
        if policies["active"] and not checkAdminAuthorization(
            policies, "", user
        ):
            log.warning(
                "the admin >%s< is not allowed to list" " users in realm %r!",
                policies["admin"],
                realm,
            )
            admin_user = policies["admin"]

            raise PolicyException(
                _(
                    "You do not have the administrative"
                    " right to list users in realm %r."
                )
                % realm
            )

    elif method == "tokenowner":
        policies = getAdminPolicies("tokenowner")
        # check if the admin may view the users in this realm
        if policies["active"] and not checkAdminAuthorization(
            policies, "", user
        ):
            log.warning(
                "the admin >%r< is not allowed to get"
                " the token owner in realm %r!",
                policies["admin"],
                realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative"
                    " right to get the token owner in realm"
                    " %r."
                )
                % realm
            )

    elif method == "checkstatus":
        policies = getAdminPolicies("checkstatus")
        # check if the admin may view the users in this realm
        if policies["active"] and not checkAdminAuthorization(
            policies, "", user
        ):
            log.warning(
                "the admin >%r< is not allowed to show status of token"
                " challenges in realm %r!",
                policies["admin"],
                realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to show status of token "
                    "challenges in realm "
                    "%r."
                )
                % realm
            )

    elif method == "tokenrealm":
        log.debug("entering method %s", method)

        # The admin needs to have the right "manageToken" for all realms,
        # the token is currently in and all realm the Token should go into.
        policies = getAdminPolicies("manageToken")

        if "realms" not in param:
            raise ParameterError(_("Missing parameter: %r") % "realms", id=905)

        realms = param["realms"]

        # List of the new realms
        realmNewList = realms.split(",")
        # List of existing realms

        realmExistList = linotp.lib.token.getTokenRealms(serial)

        for r in realmExistList:
            if policies["active"] and not checkAdminAuthorization(
                policies, None, User("dummy", r, None)
            ):
                log.warning(
                    "the admin >%r< is not allowed "
                    "to manage tokens in realm %r",
                    policies["admin"],
                    r,
                )

                raise PolicyException(
                    _(
                        "You do not have the administrative "
                        "right to remove tokens from realm "
                        "%r. Check the policies."
                    )
                    % r
                )

        for r in realmNewList:
            if policies["active"] and not checkAdminAuthorization(
                policies, None, User("dummy", r, None)
            ):
                log.warning(
                    "the admin >%r< is not allowed "
                    "to manage tokens in realm %s",
                    policies["admin"],
                    r,
                )

                raise PolicyException(
                    _(
                        "You do not have the administrative "
                        "right to add tokens to realm %s. "
                        "Check the policies."
                    )
                    % r
                )

            if not _check_token_count(realm=r):
                log.warning(
                    "the maximum tokens for the realm %r is exceeded.", r
                )

                raise PolicyException(
                    _(
                        "You may not put any more tokens in "
                        "realm %r. Check the policy "
                        "'tokencount'"
                    )
                    % r
                )

    elif method == "reset":
        policies = getAdminPolicies("reset")
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "the admin >%r< is not allowed to reset "
                "token %r for user %r@%r",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to reset token %r. Check the "
                    "policies."
                )
                % serial
            )

    elif method == "import":
        policies = getAdminPolicies("import")

        # no right to import token in any realm
        log.debug("checking import token at all")

        if policies["active"] and len(policies["realms"]) == 0:
            log.warning(
                "the admin >%r< is not allowed to import a token at all.",
                policies["admin"],
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to import tokens. Check the "
                    "policies."
                )
            )

        ret["realms"] = policies["realms"]

    elif method == "loadtokens":
        # loadtokens is called in the sope of token import to
        # * to check that the user is allowed to upload the tokens into
        #   the target realm - the list of allowed target realms is taken
        #   from the realm defintion of th import policy
        # * verify that the amount of tokens in the target realm does not
        #   exceed the maxtoken policy and

        tokenrealm = param.get("tokenrealm")
        policies = getAdminPolicies("import")

        if policies["active"]:
            if not (
                "*" in policies["realms"] or tokenrealm in policies["realms"]
            ):
                log.warning(
                    "the admin >%r< is not allowed to "
                    "import token files to realm %r: %r",
                    policies["admin"],
                    tokenrealm,
                    policies,
                )

                raise PolicyException(
                    _(
                        "You do not have the administrative "
                        "right to import token files to realm %r"
                        ". Check the policies."
                    )
                    % tokenrealm
                )

        if linotp.lib.support.check_license_restrictions():
            raise linotp.lib.support.LicenseException(
                _(
                    "No more tokens can be loaded"
                    " due to license restrictions"
                )
            )

        if not _check_token_count(realm=tokenrealm):
            log.warning(
                "the maximum tokens for the realm %s is exceeded.",
                tokenrealm,
            )

            raise MaxTokenRealmPolicyException(
                _(
                    "The maximum number of allowed tokens in realm %r is"
                    " exceeded. Check policy tokencount!"
                )
                % tokenrealm
            )

    elif method == "unpair":
        policies = getAdminPolicies("unpair")
        if policies["active"] and not checkAdminAuthorization(
            policies, serial, user
        ):
            log.warning(
                "the admin >%r< is not allowed to unpair token %r "
                "for user %r@%r",
                policies["admin"],
                serial,
                user.login,
                user.realm,
            )

            raise PolicyException(
                _(
                    "You do not have the administrative "
                    "right to unpair token %r. Check the "
                    "policies."
                )
                % serial
            )

    else:
        # unknown method
        log.error("an unknown method <<%r>> was passed.", method)

        raise PolicyException(
            _("Failed to run checkPolicyPre. Unknown method: %r") % method
        )

    return ret


def _checkGetTokenPolicyPre(method, param=None, authUser=None, user=None):
    ret = {}

    if not param:
        param = {}

    if method[0 : len("max_count")] == "max_count":
        ret = 0
        serial = param.get("serial")

        ttype = linotp.lib.token.getTokenType(serial).lower()
        trealms = linotp.lib.token.getTokenRealms(serial)
        pol_action = MAP_TYPE_GETOTP_ACTION.get(ttype, "")

        admin_user = _getAuthenticatedUser()

        if pol_action == "":
            raise PolicyException(
                _(
                    "There is no policy gettoken/"
                    "max_count definable for the "
                    "tokentype %r"
                )
                % ttype
            )

        policies = {}
        for realm in trealms:
            pol = search_policy(
                {
                    "scope": "gettoken",
                    "realm": realm,
                    "user": admin_user,
                    "action": pol_action,
                }
            )

            log.error("got a policy: %r", policies)

            policies.update(pol)

        value = get_action_value(
            policies, scope="gettoken", action=pol_action, default=-1
        )

        log.debug("got all policies: %r: %r", policies, value)

        ret = value

    return ret


def _checkAuditPolicyPre(method, param=None, authUser=None, user=None):
    ret = {}

    if not param:
        param = {}

    admin_user = _getAuthenticatedUser()

    if method == "view":
        if not is_authorized(admin_user, "audit", "view"):
            log.warning(
                "the admin >%r< is not allowed to view the audit trail",
                admin_user,
            )

            ret = _(
                "You do not have the administrative right to view the "
                "audit trail. You are missing a policy "
                "scope=audit, action=view"
            )
            raise PolicyException(ret)
    else:
        log.error("an unknown method was passed in : %s", method)

        raise PolicyException(
            _("Failed to run checkPolicyPre. Unknown method: %r") % method
        )

    return ret


def _checkManagePolicyPre(method, param=None, authUser=None, user=None):
    controller = "manage"
    ret = {}
    log.debug("entering controller %s", controller)
    return ret


def _checkToolsPolicyPre(method, param=None, authUser=None, user=None):
    ret = {}

    if not param:
        param = {}

    admin_user = _getAuthenticatedUser()

    if not is_authorized(admin_user, "tools", method):
        log.warning(
            "the admin >%r< is not allowed to use action %s in the tools scope",
            admin_user,
            method,
        )

        ret = (
            _(
                "You do not have the administrative right to manage tools. "
                "You are missing a policy scope=tools, action=%s"
            )
            % method
        )

        raise PolicyException(ret)

    return True


def _checkSelfservicePolicyPre(method, param=None, authUser=None, user=None):
    ret = {}
    controller = "selfservice"
    client = _get_client()

    if not param:
        param = {}

    log.debug("entering controller %s", controller)

    # ---------------------------------------------------------------------- --

    # check the maxtoken policy
    #   which restricts the number of tokens for the user in a realm

    check_maxtoken(method, user=user or authUser, param=param)

    # ---------------------------------------------------------------------- --

    if method.startswith("max_count"):
        ret = 0
        serial = param.get("serial")
        ttype = linotp.lib.token.getTokenType(serial).lower()
        urealm = authUser.realm
        pol_action = MAP_TYPE_GETOTP_ACTION.get(ttype, "")

        if pol_action == "":
            raise PolicyException(
                _(
                    "There is no policy selfservice/"
                    "max_count definable for the token "
                    "type %s."
                )
                % ttype
            )

        policies = get_client_policy(
            client,
            scope="selfservice",
            action=pol_action,
            realm=urealm,
            user=authUser.login,
            userObj=authUser,
        )

        log.debug("[max_count] got a policy: %r", policies)

        if policies == {}:
            raise PolicyException(
                _(
                    "There is no policy selfservice/"
                    "max_count defined for the tokentype "
                    "%s in realm %s."
                )
                % (ttype, urealm)
            )

        value = get_action_value(
            policies, scope="selfservice", action=pol_action, default=-1
        )

        log.debug("[max_count] got all policies: %r: %r", policies, value)

        ret = value

    elif method == "usersetdescription":
        if not get_selfservice_actions(authUser, "setDescription"):
            log.warning(
                "user %s@%s is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you "
                    "to issue this request!"
                )
            )

    elif method == "usersetpin":
        if not get_selfservice_actions(authUser, "setOTPPIN"):
            log.warning(
                "user %s@%s is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you "
                    "to issue this request!"
                )
            )

    elif method == "userreset":
        if not get_selfservice_actions(authUser, "reset"):
            log.warning(
                "user %s@%s is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you "
                    "to issue this request!"
                )
            )

    elif method == "userresync":
        if not get_selfservice_actions(authUser, "resync"):
            log.warning(
                "user %s@%s is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you "
                    "to issue this request!"
                )
            )

    elif method == "userverify":
        if not get_selfservice_actions(authUser, "verify"):
            log.warning(
                "user %s@%s is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you "
                    "to issue this request!"
                )
            )

    elif method == "usersetmpin":
        if not get_selfservice_actions(authUser, "setMOTPPIN"):
            log.warning(
                "user %r@%r is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you "
                    "to issue this request!"
                )
            )

    elif method == "useractivateocra2token":
        if param.get("type").lower() == "ocra2":
            if get_selfservice_actions(authUser, "activate_OCRA2"):
                return ret

            if get_selfservice_actions(authUser, "activateQR2"):
                return ret

        log.warning(
            "user %r@%r is not allowed to call this function!",
            authUser.login,
            authUser.realm,
        )

        raise PolicyException(
            _("The policy settings do not allow you to issue this request!")
        )

    elif method == "userassign":
        if not get_selfservice_actions(authUser, "assign"):
            log.warning(
                "user %r@%r is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow "
                    "you to issue this request!"
                )
            )

        # Here we check, if the tokennum exceeds the tokens
        if not _check_token_count():
            log.error("The maximum token number is reached!")

            raise PolicyException(
                _(
                    "You may not enroll any more tokens. "
                    "Your maximum token number is reached!"
                )
            )

    elif method == "usergetserialbyotp":
        if not get_selfservice_actions(authUser, "getserial"):
            log.warning(
                "user %s@%s is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you to"
                    " request a serial by OTP!"
                )
            )

    elif method == "userdisable":
        if not get_selfservice_actions(authUser, "disable"):
            log.warning(
                "user %r@%r is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you "
                    "to issue this request!"
                )
            )

    elif method == "userenable":
        if not get_selfservice_actions(authUser, "enable"):
            log.warning(
                "user %s@%s is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you to"
                    " issue this request!"
                )
            )

    elif method == "userunassign":
        if not get_selfservice_actions(authUser, "unassign"):
            log.warning(
                "user %r@%r is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you "
                    "to issue this request!"
                )
            )

    elif method == "userdelete":
        if not get_selfservice_actions(authUser, "delete"):
            log.warning(
                "user %r@%r is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you "
                    "to issue this request!"
                )
            )

    elif method == "userwebprovision":
        typ = param.get("type").lower()

        if typ == "oathtoken" and get_selfservice_actions(
            authUser, "webprovisionOATH"
        ):
            return ret

        if typ == "googleauthenticator_time" and get_selfservice_actions(
            authUser, "webprovisionGOOGLEtime"
        ):
            return ret

        if typ == "googleauthenticator" and get_selfservice_actions(
            authUser, "webprovisionGOOGLE"
        ):
            return ret

        if typ == "ocra2" and get_selfservice_actions(authUser, "enrollOCRA2"):
            return ret

        log.warning(
            "[userwebprovision] user %r@%r is not allowed to "
            "call this function!",
            authUser.login,
            authUser.realm,
        )
        raise PolicyException(
            _("The policy settings do not allow you to issue this request!")
        )

        # Here we check, if the tokennum exceeds the allowed tokens
        if not _check_token_count():
            log.error("The maximum token number is reached!")

            raise PolicyException(
                _(
                    "You may not enroll any more tokens. "
                    "Your maximum token number "
                    "is reached!"
                )
            )

    elif method == "userhistory":
        if not get_selfservice_actions(authUser, "history"):
            log.warning(
                "user %r@%r is not allowed to call this function!",
                authUser.login,
                authUser.realm,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow you "
                    "to issue this request!"
                )
            )

    elif method == "userinit":
        typ = param["type"].lower()
        action = "enroll" + typ.upper()

        wpg = get_selfservice_actions(authUser, "webprovisionGOOGLE")
        wpgt = get_selfservice_actions(authUser, "webprovisionGOOGLEtime")

        if not (
            get_selfservice_actions(authUser, action)
            or (typ == "hmac" and wpg)
            or (typ == "totp" and wpgt)
        ):
            log.warning(
                "user %r@%r is not allowed to enroll %s!",
                authUser.login,
                authUser.realm,
                typ,
            )

            raise PolicyException(
                _(
                    "The policy settings do not allow "
                    "you to issue this request!"
                )
            )

        # Here we check, if the tokennum exceeds the allowed tokens
        if not _check_token_count():
            log.error("The maximum token number is reached!")

            raise PolicyException(
                _(
                    "You may not enroll any more tokens. "
                    "Your maximum token number "
                    "is reached!"
                )
            )

    else:
        log.error("Unknown method in selfservice: %s", method)

        raise PolicyException(_("Unknown method in selfservice: %s") % method)

    return ret


def _checkSystemPolicyPre(method, param=None, authUser=None, user=None):
    ret = {}

    if not param:
        param = {}

    admin_user = _getAuthenticatedUser()

    if method not in SYSTEM_ACTIONS:
        log.error("an unknown method was passed in system: %s", method)

        raise PolicyException(
            _("Failed to run checkPolicyPre. Unknown method: %r") % method
        )

    action = SYSTEM_ACTIONS[method]

    if not is_authorized(admin_user, "system", action):
        log.warning(
            "admin >%s< is not authorited to %s. Missing policy "
            "scope=system, action=%s",
            admin_user,
            method,
            action,
        )

        raise PolicyException(
            _(
                "Policy check failed. You are not allowed "
                "to %s system config."
            )
            % action
        )

    return ret


def getAdminPolicies(action, scope="admin"):
    """
    This internal function returns the policies (default: of scope=admin)
    for the currently authenticated administrativ user.__builtins__

    :param action: this is the action (like enable, disable, init...)
    :param scope: scope of the policies,
                    might be admin, monitoring, reporting.access

    :return: a dictionary with the following keys:

        - active (if policies are used)
        - realms (the realms, in which the admin is allowed to do this action)
        - resolvers (the resolvers in which the admin is allowed to perform
          this action)
        - admin (the name of the authenticated admin user)
    """
    active = True

    # We may change this later to other authentication schemes
    admin_user = _getAuthenticatedUser()
    log.info("Evaluating policies for the user: %r", admin_user)

    # check if we got admin policies at all
    p_at_all = search_policy({"scope": scope})

    if not p_at_all:
        log.info(
            "No policies in scope admin found."
            " Admin authorization will be disabled."
        )
        active = False
        realms = []
        resolvers = []

    else:
        pol_request = {"user": admin_user, "scope": scope}
        if action:
            pol_request["action"] = action

        policies = getPolicy(pol_request)
        log.debug("Found the following policies: %r", policies)

        realms = get_realm_from_policies(policies)
        resolvers = get_resolvers_for_realms(realms)

    log.debug("Found the following resolvers in the policy: %r", resolvers)

    return {
        "active": active,
        "realms": realms,
        "resolvers": resolvers,
        "admin": admin_user,
    }


def checkAdminAuthorization(policies, serial, user, fitAllRealms=False):
    """
    This function checks if the token object defined by either "serial"
    or "user" is in the corresponding realm, where the admin has access to /
    fits to the given policy.

    fitAllRealms: If set to True, then the administrator must have rights
                    in all realms of the token. e.g. for deleting tokens.

    returns:
        True: if admin is allowed
        False: if admin is not allowed
    """

    log.info("policies: %r", policies)

    # in case there are absolutely no policies
    if not policies["active"]:
        return True

    # If the policy is valid for all realms
    if "*" in policies["realms"]:
        return True

    # convert realms and resolvers to lowercase
    policies["realms"] = [x.lower() for x in policies["realms"]]

    # in case we got a serial
    if serial != "" and serial is not None:
        realms = linotp.lib.token.getTokenRealms(serial)

        log.debug(
            "the token %r is contained in the realms: %r", serial, realms
        )

        log.debug("the policy contains the realms: %r", policies["realms"])

        for r in realms:
            if fitAllRealms:
                if r not in policies["realms"]:
                    return False
            else:
                if r in policies["realms"]:
                    return True

        return fitAllRealms

    # in case of the admin policies - no user name is verified:
    # the username could be empty (not dummy) which prevents an
    # unnecessar resolver lookup

    # default realm user
    if not user.realm and not user.resolver_config_identifier:
        return _getDefaultRealm() in policies["realms"]
    # we got a realm:
    if user.realm != "":
        return user.realm.lower() in policies["realms"]
    if user.resolver_config_identifier != "":
        return user.resolver_config_identifier in policies["resolvers"]

    # catch all
    return False


def _check_token_count(user=None, realm=None, post_check=False):
    """Internal function: checks the number of tokens for a certain realm.

    Therefore it checks the policy
        "scope = enrollment", action = "tokencount = <number>"

    if there are more tokens assigned than in tokencount of the policy
    mentioned, return will be false

        # 1. alle resolver aus dem Realm holen.
        # 2. fuer jeden Resolver die tNum holen.
        # 3. die Policy holen und gegen die tNum checken.

    :param user: the user in the realm
    :param realm: the relevant realm
    :return: boolean - False if token count is violated
    """

    # ---------------------------------------------------------------------- --

    # in case of the pre action (init, assign, ..) there must be at least
    # one token available without hitting the tocken count limit
    # - we use the to simplify the algorithm

    count_offset = 1
    if post_check:
        count_offset = 0

    # ---------------------------------------------------------------------- --

    # determin the realm in which the tokencount should be evaluated
    # either derived from the user or directly specified or if none, we check
    # that all realms are not violating the limit - does this make sense?

    if user and user.login:
        log.debug(
            "checking token num in realm: %r, resolver: %r",
            user.realm,
            user.resolver_config_identifier,
        )

        lookup_realms = _getUserRealms(user)

    elif user and user.realm:
        log.debug(
            "checking token num in realm: %r, resolver: %r",
            user.realm,
            user.resolver_config_identifier,
        )

        lookup_realms = getRealms(user.realm)

    elif realm:
        lookup_realms = getRealms(realm)

    else:
        log.debug("no realm defined - skiping tokencount check")
        return True

    log.debug("checking token count in realm: %r", lookup_realms)

    token_count = "tokencount"
    policy_def = {"scope": "enrollment", "action": token_count}

    # ---------------------------------------------------------------------- --

    # depending on the license, we use a different function pointer
    # to check the tokens or token users per realm

    token_count_function = linotp.lib.token.getTokenInRealm
    if linotp.lib.support.get_license_type() == "user-num":
        token_count_function = linotp.lib.token.getNumTokenUsers

    # Now we are checking the policy for every Realm

    for lookup_realm in lookup_realms:
        # ------------------------------------------------------------------ --

        # first check if there is a policy at all, if not, we can skip
        # to the next realm

        policy_def["realm"] = lookup_realm
        policy = getPolicy(policy_def)
        policy_token_count = get_action_value(
            policy, scope="enrollment", action=token_count, default=-1
        )

        if policy_token_count < 0:
            log.debug(
                "there is no scope=enrollment, action=tokencount policy "
                "for the realm %r",
                lookup_realm,
            )
            continue

        # ------------------------------------------------------------------ --

        # if there is a policy, we query the token amount of this realm

        token_in_realm = token_count_function(realm=lookup_realm)
        log.debug(
            "There are %r tokens in realm %r", token_in_realm, lookup_realm
        )

        # ------------------------------------------------------------------ --

        # now check if the limit is violated

        log.info(
            "Realm: %r, max: %r, tokens in realm: %r",
            lookup_realm,
            policy_token_count,
            token_in_realm,
        )

        if token_in_realm + count_offset > policy_token_count:
            return False

    return True


def get_tokenissuer(serial, user="", realm="", description=""):
    """Get the token issuer.

    This internal function returns the issuer of the token as defined in policy
    scope = enrollment, action = tokenissuer = <string>
    The string can have the following variables:
        <u>: user
        <r>: realm
        <s>: token serial
        <d>: the token description

    This function is used to create 'otpauth' tokens

    :param user: the user login string
    :param realm: the realm of the user
    :param serial: the token serial
    :param description: the token description
    :return: the tokenlabel string - default is 'LinOTP'
    """

    action = "tokenissuer"
    client = _get_client()

    pol = has_client_policy(
        client, scope="enrollment", action=action, realm=realm, user=user
    )

    tokenissuer = get_action_value(
        pol, scope="enrollment", action=action, default=""
    )

    if tokenissuer:
        tokenissuer = re.sub("<u>", user, tokenissuer)
        tokenissuer = re.sub("<r>", realm, tokenissuer)
        tokenissuer = re.sub("<s>", serial, tokenissuer)
        tokenissuer = re.sub("<d>", description, tokenissuer)

        log.debug("providing tokenissuer = %r", tokenissuer)
        return tokenissuer

    return "LinOTP"


def get_tokenlabel(serial, user="", realm="", description=""):
    """Get the label for a token.

    This internal function returns the naming of the token as defined in policy
    scope = enrollment, action = tokenname = <string>
    The string can have the following variables:
    - <u>: user
    - <r>: realm
    - <s>: token serial
    - <d>: the token description

    This function is used to create 'otpauth' tokens

    :param user: the user login string
    :param realm: the realm of the user
    :param serial: the token serial
    :param description: the token description
    :return: the tokenlabel string - default is user or serial
    """

    action = "tokenlabel"
    client = _get_client()

    pol = has_client_policy(
        client, scope="enrollment", action=action, realm=realm, user=user
    )

    tokenlabel = get_action_value(
        pol, scope="enrollment", action=action, default=""
    )

    if tokenlabel:
        tokenlabel = re.sub("<u>", user, tokenlabel)
        tokenlabel = re.sub("<r>", realm, tokenlabel)
        tokenlabel = re.sub("<s>", serial, tokenlabel)
        tokenlabel = re.sub("<d>", description, tokenlabel)

        return tokenlabel

    # if there is no token label we do a fallback to user or serial

    if user:
        return user

    return serial


def get_autoassignment_from_realm(user):
    """
    this function checks the policy scope=enrollment,
                                    action=autoassignment_from_realm

    :return: the realm where the tokens should be taken from
    """

    token_src_realm_action = "autoassignment_from_realm"
    client = _get_client()

    pol = get_client_policy(
        client=client,
        scope="enrollment",
        action=token_src_realm_action,
        realm=user.realm,
        user=user.login,
        userObj=user,
    )

    realm = get_action_value(
        pol, scope="enrollment", action=token_src_realm_action, default=""
    )

    log.debug("got the %s: %r", token_src_realm_action, realm)
    return realm.strip()


def get_autoassignment_without_pass(user):
    """Check if autoassigment without password for the user is allowed.

    :return: boolean
    """

    client = _get_client()
    action_name = "autoassignment_without_password"

    pol = get_client_policy(
        client=client,
        scope="enrollment",
        action=action_name,
        realm=user.realm,
        user=user.login,
        userObj=user,
    )

    return get_action_value(
        pol, scope="enrollment", action=action_name, default=False
    )


def get_autoassignment(user):
    """
    this function checks the policy scope=enrollment, action=autoassignment
    This is a boolean policy.
    The function returns true, if autoassignment is defined.
    """

    client = _get_client()

    pol = has_client_policy(
        client,
        scope="enrollment",
        action="autoassignment",
        realm=user.realm,
        user=user.login,
        userObj=user,
    )

    ret = get_action_value(
        pol, scope="enrollment", action="autoassignment", default=False
    )

    log.debug("got the autoassignement %r", ret)
    return ret


def get_auto_enrollment(user):
    """
    this function checks the policy scope=enrollment, action=autoenrollment
    This policy policy returns the tokentyp: sms or email
    The function returns true, if autoenrollment is defined.
    """

    action = "autoenrollment"
    client = _get_client()

    pol = has_client_policy(
        client,
        scope="enrollment",
        action=action,
        realm=user.realm,
        user=user.login,
        userObj=user,
    )

    t_typ = get_action_value(
        pol, scope="enrollment", action=action, default=""
    )

    token_types = [x.strip() for x in t_typ.lower().split()]

    if token_types and set(token_types).issubset(set(["sms", "email", "*"])):
        log.info("token type for auto enrollment: %r", t_typ)
        return True, token_types

    log.info("unsupported token type for auto enrollment %r", t_typ)
    return False, ""


def autoassignment_forward(user):
    """Return the status of autoassigment forwarding.

    this function checks the policy scope=enrollment, action=autoassignment
    This is a boolean policy.
    The function returns true, if autoassignment is defined.
    """

    client = _get_client()

    pol = get_client_policy(
        client,
        scope="enrollment",
        action="autoassignment_forward",
        realm=user.realm,
        user=user.login,
        userObj=user,
    )

    return get_action_value(
        pol, scope="enrollment", action="autoassignment_forward", default=False
    )


def purge_enrollment_token(user, realm=None):
    """Get status of enrollment token purging.

    lookup in the policies if the rollout token should be removed
    after the successfull login with a second token

    :param user: the token owner
    :return: boolean
    """
    client = _get_client()

    policies = get_client_policy(
        client=client,
        scope="enrollment",
        action="purge_rollout_token",
        realm=realm,
        userObj=user,
    )

    return get_action_value(
        policies,
        scope="enrollment",
        action="purge_rollout_token",
        default=False,
    )


def ignore_autoassignment_pin(user):
    """Should autoassignment pin be ignored?

    This function checks the policy
        scope=enrollment, action=ignore_autoassignment_pin
    This is a boolean policy.
    The function returns true, if the password used in the autoassignment
    should not be set as token pin.
    """
    client = _get_client()

    policies = get_client_policy(
        client,
        scope="enrollment",
        action="ignore_autoassignment_pin",
        realm=user.realm,
        user=user.login,
        userObj=user,
    )

    return get_action_value(
        policies,
        scope="enrollment",
        action="ignore_autoassignment_pin",
        default=False,
    )


def _getRandomOTPPINLength(user):
    """Return the length of the random otp pin.

    This internal function returns the length of the random otp pin that is
    define in policy scope = enrollment, action = otp_pin_random = 111
    """

    all_pin_length = []
    client = _get_client()

    for R in _getUserRealms(user):
        policies = get_client_policy(
            client,
            scope="enrollment",
            action="otp_pin_random",
            realm=R,
            user=user.login,
            userObj=user,
        )

        pin_length = get_action_value(
            policies, scope="enrollment", action="otp_pin_random", default=-1
        )

        all_pin_length.append(pin_length)

        log.debug("found policy with otp_pin_random = %r", pin_length)

    return max(all_pin_length)


def _getRandomOTPPINContent(user):
    """Get the length of the random otp pin

    This internal function returns the length of the random otp pin that is
    defined in policy scope = enrollment, action = otp_pin_random = 111
    """
    client = _get_client()

    for R in _getUserRealms(user):
        policies = has_client_policy(
            client,
            scope="enrollment",
            action="otp_pin_random_content",
            realm=R,
            user=user.login,
            userObj=user,
        )

        otp_pin_random_content = get_action_value(
            policies,
            scope="enrollment",
            action="otp_pin_random_content",
            default="",
        )

        if otp_pin_random_content:
            return otp_pin_random_content

    return ""


def getOTPPINEncrypt(serial=None, user=None):
    """
    This function returns, if the otppin should be stored as
    an encrpyted value
    """

    client = _get_client()

    Realms = []
    if serial:
        Realms = linotp.lib.token.getTokenRealms(serial)
    elif user:
        Realms = _getUserRealms(user)

    log.debug("checking realms: %r", Realms)

    for realm in Realms:
        policies = get_client_policy(
            client=client,
            scope="enrollment",
            action="otp_pin_encrypt",
            realm=realm,
            user=user,
        )

        log.debug("realm: %r, pol: %r", realm, policies)

        if get_action_value(
            policies, scope="enrollment", action="otp_pin_encrypt", default=0
        ):
            return 1

    return 0


def _getOTPPINPolicies(user, scope="selfservice"):
    """get the PIN policies for a realm.

    This internal function returns the PIN policies for a realm.
    These policies can either be in the scope "selfservice" or "admin"
    The policy define when reseting an OTP PIN:

    - what should be the length of the otp pin
    - what should be the contents of the otp pin by the actions:

      - otp_pin_minlength =
      - otp_pin_maxlength =
      - otp_pin_contents = [cns] (character, number, special character)

    :return: dictionary like {contents: "cns", min: 7, max: 10}
    """
    log.debug("[getOTPPINPolicies]")
    client = _get_client()

    ret = {"min": -1, "max": -1, "contents": ""}

    log.debug("searching for OTP PIN policies in scope=%r policies.", scope)
    for R in _getUserRealms(user):
        pol = get_client_policy(
            client,
            scope=scope,
            action="otp_pin_maxlength",
            realm=R,
            user=user.login,
            userObj=user,
        )
        n_max = get_action_value(
            pol, scope=scope, action="otp_pin_maxlength", default=-1
        )

        pol = get_client_policy(
            client,
            scope=scope,
            action="otp_pin_minlength",
            realm=R,
            user=user.login,
            userObj=user,
        )
        n_min = get_action_value(
            pol, scope=scope, action="otp_pin_minlength", default=-1
        )

        pol = get_client_policy(
            client,
            scope=scope,
            action="otp_pin_contents",
            realm=R,
            user=user.login,
            userObj=user,
        )
        n_contents = get_action_value(
            pol, scope=scope, action="otp_pin_contents", default=""
        )

        # find the maximum length
        log.debug("find the maximum length for OTP PINs.")
        if int(n_max) > ret["max"]:
            ret["max"] = n_max

        # find the minimum length
        log.debug("find the minimum length for OTP_PINs")
        if not n_min == -1:
            if ret["min"] == -1:
                ret["min"] = n_min
            elif n_min < ret["min"]:
                ret["min"] = n_min

        # find all contents
        log.debug("find the allowed contents for OTP PINs")
        for k in n_contents:
            if k not in ret["contents"]:
                ret["contents"] += k

    return ret


def checkOTPPINPolicy(pin, user):
    """
    This function checks the given PIN (OTP PIN) against the policy
    returned by the function

    getOTPPINPolicy

    It returns a dictionary:
        {'success': True/False,
          'error': errortext}

    At the moment this works for the selfservice portal
    """

    log.debug("[checkOTPPINPolicy]")

    pol = _getOTPPINPolicies(user)
    log.debug("checking for otp_pin_minlength")
    if pol["min"] != -1:
        if pol["min"] > len(pin):
            return {
                "success": False,
                "error": _(
                    "The provided PIN is too short. It should be "
                    "at least %i characters."
                )
                % pol["min"],
            }

    log.debug("checking for otp_pin_maxlength")
    if pol["max"] != -1:
        if pol["max"] < len(pin):
            return {
                "success": False,
                "error": (
                    _(
                        "The provided PIN is too long. It should not "
                        "be longer than %i characters."
                    )
                    % pol["max"]
                ),
            }

    log.debug("checking for otp_pin_contents")
    if pol["contents"]:
        policy_c = "c" in pol["contents"]
        policy_n = "n" in pol["contents"]
        policy_s = "s" in pol["contents"]
        policy_o = "o" in pol["contents"]

        contains_c = False
        contains_n = False
        contains_s = False
        contains_other = False

        REG_POLICY_C, REG_POLICY_N, REG_POLICY_S = _get_pin_values(
            context["Config"]
        )

        for c in pin:
            if re.search(REG_POLICY_C, c):
                contains_c = True
            elif re.search(REG_POLICY_N, c):
                contains_n = True
            elif re.search(REG_POLICY_S, c):
                contains_s = True
            else:
                contains_other = True

        if pol["contents"][0] == "+":
            log.debug(
                "checking for an additive character group: %s",
                pol["contents"],
            )
            if (
                not (
                    (policy_c and contains_c)
                    or (policy_s and contains_s)
                    or (policy_o and contains_other)
                    or (policy_n and contains_n)
                )
            ) or (
                (not policy_c and contains_c)
                or (not policy_s and contains_s)
                or (not policy_n and contains_n)
                or (not policy_o and contains_other)
            ):
                return {
                    "success": False,
                    "error": _(
                        "The provided PIN does not contain "
                        "characters of the group or it does "
                        "contains characters that are not in the "
                        "group %s"
                    )
                    % pol["contents"],
                }
        else:
            log.debug("[checkOTPPINPolicy] normal check: %s", pol["contents"])
            if policy_c and not contains_c:
                return {
                    "success": False,
                    "error": _(
                        "The provided PIN does not contain any "
                        "letters. Check policy otp_pin_contents."
                    ),
                }
            if policy_n and not contains_n:
                return {
                    "success": False,
                    "error": _(
                        "The provided PIN does not contain any "
                        "numbers. Check policy otp_pin_contents."
                    ),
                }
            if policy_s and not contains_s:
                return {
                    "success": False,
                    "error": _(
                        "The provided PIN does not contain any "
                        "special characters. It should contain "
                        "some of these characters like "
                        ".: ,;-_<>+*~!/()=?$. Check policy "
                        "otp_pin_contents."
                    ),
                }
            if policy_o and not contains_other:
                return {
                    "success": False,
                    "error": _(
                        "The provided PIN does not contain any "
                        "other characters. It should contain some"
                        " of these characters that are not "
                        "contained in letters, digits and the "
                        "defined special characters. Check policy "
                        "otp_pin_contents."
                    ),
                }

            # Additionally: in case of -cn the PIN must not contain "s" or "o"
            if pol["contents"][0] == "-":
                if not policy_c and contains_c:
                    return {
                        "success": False,
                        "error": _(
                            "The PIN contains letters, although it "
                            "should not! (%s)"
                        )
                        % pol["contents"],
                    }
                if not policy_n and contains_n:
                    return {
                        "success": False,
                        "error": _(
                            "The PIN contains digits, although it "
                            "should not! (%s)"
                        )
                        % pol["contents"],
                    }
                if not policy_s and contains_s:
                    return {
                        "success": False,
                        "error": _(
                            "The PIN contains special characters, "
                            "although it should not! "
                            "(%s)"
                        )
                        % pol["contents"],
                    }
                if not policy_o and contains_other:
                    return {
                        "success": False,
                        "error": _(
                            "The PIN contains other characters, "
                            "although it should not! "
                            "(%s)"
                        )
                        % pol["contents"],
                    }

    return {"success": True, "error": ""}


def createRandomPin(user, min_pin_length):
    """
    create a random pin

    :param min_pin_length: the requested minimum pin length
    :param user: user defines the realm/user policy selection
    :return: the new pin
    """
    character_pool = letters + digits

    pin_length = max(min_pin_length, _getRandomOTPPINLength(user))

    contents = _getRandomOTPPINContent(user)

    if contents:
        character_pool = ""
        if "c" in contents:
            character_pool += ascii_lowercase
        if "C" in contents:
            character_pool += ascii_uppercase
        if "n" in contents:
            character_pool += digits
        if "s" in contents:
            character_pool += special_characters

    return generate_password(size=pin_length, characters=character_pool)


def checkToolsAuthorisation(method, param=None):
    # TODO: fix the semantic of the realm in the policy!

    auth_user = _getAuthenticatedUser()

    if not param:
        param = {}

    _checkToolsPolicyPre(method, param=param, authUser=auth_user, user=None)


def checkPolicyPre(controller, method, param=None, authUser=None, user=None):
    """
    This function will check for all policy definition for a certain
    controller/method It is run directly before doing the action in the
    controller. I will raise an exception, if it fails.

    :param param: This is a dictionary with the necessary parameters.

    :return: dictionary with the necessary results. These depend on
             the controller.
    """
    ret = {}

    if not param:
        param = {}

    log.debug("entering controller %s", controller)
    log.debug("entering method %s", method)

    if controller == "admin":
        ret = _checkAdminPolicyPre(
            method=method, param=param, authUser=authUser, user=user
        )

    elif controller == "gettoken":
        ret = _checkGetTokenPolicyPre(
            method=method, param=param, authUser=authUser, user=user
        )
    elif controller == "audit":
        ret = _checkAuditPolicyPre(
            method=method, param=param, authUser=authUser, user=user
        )

    elif controller == "manage":
        ret = _checkManagePolicyPre(
            method=method, param=param, authUser=authUser, user=user
        )

    elif controller == "tools":
        ret = _checkToolsPolicyPre(
            method=method, param=param, authUser=authUser, user=user
        )

    elif controller == "selfservice":
        ret = _checkSelfservicePolicyPre(
            method=method, param=param, authUser=authUser, user=user
        )

    elif controller == "system":
        ret = _checkSystemPolicyPre(
            method=method, param=param, authUser=authUser, user=user
        )

    else:
        # unknown controller
        log.error("an unknown controller <<%r>> was passed.", controller)

        raise PolicyException(
            _("Failed to run getPolicyPre. Unknown controller: %s")
            % controller
        )

    return ret


##############################################################################


def checkPolicyPost(controller, method, param=None, user=None):
    """
    This function will check policies after a successful action in a
    controller. E.g. this can be setting a random PIN after successfully
    enrolling a token.

    :param controller: the controller context
    :param method: the calling action
    :param param: This is a dictionary with the necessary parameters.
    :param auth_user: This is the authenticated user. For the selfservice this
                      will be the user in the selfservice portal, for admin or
                      manage it will be the administrator


    :return: It returns a dictionary with the necessary results. These depend
             on the controller.
    """
    ret = {}

    if param is None:
        param = {}

    if controller == "admin":
        ret = _checkAdminPolicyPost(method, param=param, user=user)

    elif controller == "system":
        ret = _checkSystemPolicyPost(method, param=param, user=user)

    elif controller == "selfservice":
        ret = _checkSelfservicePolicyPost(method, param=param, user=user)

    else:
        # unknown controller
        log.error("an unknown constroller <<%s>> was passed.", controller)

        raise PolicyException(
            _("Failed to run getPolicyPost. Unknown controller: %s")
            % controller
        )

    return ret


###############################################################################
#
# Client Policies
#


def set_realm(login, realm, exception=False):
    """
    this function reads the policy scope: authorization, client: x.y.z,
    action: setrealm=new_realm and overwrites the existing realm of the user
    with the new_realm.
    This can be used, if the client is not able to pass a realm and the users
    are not be located in the default realm.

    returns:
        realm    - name of the new realm taken from the policy
    """

    client = _get_client()

    log.debug("got the client %s", client)
    log.debug("users %s original realm is %s", login, realm)

    policies = get_client_policy(
        client,
        scope="authorization",
        action="setrealm",
        realm=realm,
        user=login,
        find_resolver=False,
    )

    new_realm = get_action_value(
        policies, scope="authorization", action="setrealm", default=realm
    )

    log.debug("users %s new realm is %s", login, new_realm)
    return new_realm


def check_user_authorization(login, realm, exception=False):
    """
    check if the given user/realm is in the given policy.
    The realm may contain the wildcard '*', then the policy holds for
    all realms. If no username or '*' is given, the policy holds for all users.

    attributes:
        login    - loginname of the user
        realm    - realm of the user
        exception    - wether it should return True/False or raise an Exception
    """
    res = False
    client = _get_client()

    # if there is absolutely NO policy in scope authorization,
    # we return immediately
    if (
        len(search_policy({"scope": "authorization", "action": "authorize"}))
        == 0
    ):
        log.debug("absolutely no authorization policy.")
        return True

    log.debug("got the client %s", client)

    policies = get_client_policy(
        client,
        scope="authorization",
        action="authorize",
        realm=realm,
        user=login,
    )

    log.debug("got policies %s for user %s", policies, login)

    if len(policies):
        res = True

    if res is False and exception:
        raise AuthorizeException(
            "Authorization on client %s failed "
            "for %s@%s." % (client, login, realm)
        )

    return res


###############################################################################
#
#  Authentication stuff
#
def get_auth_passthru(user):
    """
    returns True, if the user in this realm should be authenticated against
    the UserIdResolver in case the user has no tokens assigned.
    """
    ret = False
    client = _get_client()

    pol = get_client_policy(
        client,
        scope="authentication",
        action="passthru",
        realm=user.realm,
        user=user.login,
        userObj=user,
    )

    if len(pol) > 0:
        ret = True
    return ret


def get_auth_forward(user):
    """Returns the list of all forwarding servers."""
    client = _get_client()

    policies = get_client_policy(
        client,
        scope="authentication",
        action="forward_server",
        realm=user.realm,
        user=user.login,
        userObj=user,
    )

    return get_action_value(
        policies, scope="authentication", action="forward_server", default=None
    )


def get_auth_forward_on_no_token(user):
    """
    returns True, if the user in this realm should be forwarded
    in case the user has no tokens assigned.
    """
    client = _get_client()

    policies = get_client_policy(
        client,
        scope="authentication",
        action="forward_on_no_token",
        realm=user.realm,
        user=user.login,
        userObj=user,
    )

    return get_action_value(
        policies,
        scope="authentication",
        action="forward_on_no_token",
        default=False,
    )


def get_auth_passOnNoToken(user):
    """
    returns True, if the user in this realm should be always authenticated
    in case the user has no tokens assigned.
    """

    client = _get_client()

    policies = has_client_policy(
        client,
        scope="authentication",
        action="passOnNoToken",
        realm=user.realm,
        user=user.login,
        userObj=user,
    )

    return get_action_value(
        policies, scope="authentication", action="passOnNoToken", default=False
    )


def disable_on_authentication_exceed(user, realms=None):
    """
    returns True if the token should be disable, if max auth count is reached
    """
    ppargs = {}
    action = "disable_on_authentication_exceed"
    client = _get_client()

    if not realms:
        realms = [user.realm]

    if user.login:
        ppargs["user"] = user.login
        ppargs["userObj"] = user

    for realm in realms:
        policies = get_client_policy(
            client,
            scope="authentication",
            action=action,
            realm=realm,
            **ppargs
        )

        if get_action_value(
            policies, scope="authentication", action=action, default=False
        ):
            return True

    return False


def delete_on_authentication_exceed(user, realms=None):
    """
    returns True if the token should be disable, if max auth count is reached
    """
    ppargs = {}
    action = "delete_on_authentication_exceed"
    client = _get_client()

    if not realms:
        realms = [user.realm]

    if user.login:
        ppargs["user"] = user.login
        ppargs["userObj"] = user

    for realm in realms:
        policies = get_client_policy(
            client,
            scope="authentication",
            action=action,
            realm=realm,
            **ppargs
        )

        if get_action_value(
            policies, scope="authentication", action=action, default=False
        ):
            return True

    return False


def trigger_sms(realms=None):
    """Status, if a check_s should be allowed to trigger an sms."""

    client = _get_client()
    user = _getUserFromParam()

    login = user.login
    if realms is None:
        realm = user.realm or _getDefaultRealm()
        realms = [realm]

    ret = False
    for realm in realms:
        pol = has_client_policy(
            client,
            scope="authentication",
            action="trigger_sms",
            realm=realm,
            user=login,
            userObj=user,
        )

        if len(pol) > 0:
            log.debug("found policy in realm %s", realm)
            ret = True

    return ret


def trigger_phone_call_on_empty_pin(realms=None):
    """Trigger a phone call on empty pin?

    returns true if a check_s should be allowed to trigger an phone call
    for the voice token
    """
    client = _get_client()
    user = _getUserFromParam()

    login = user.login
    if realms is None:
        realm = user.realm or _getDefaultRealm()
        realms = [realm]

    ret = False
    for realm in realms:
        pol = has_client_policy(
            client,
            scope="authentication",
            action="trigger_voice",
            realm=realm,
            user=login,
            userObj=user,
        )

        if len(pol) > 0:
            log.debug("found policy in realm %s", realm)
            ret = True

    return ret


def get_auth_AutoSMSPolicy(realms=None):
    """Returns true, if the autosms policy is set in one of the realms.

    return:
        True or False

    input:
        list of realms
    """
    log.debug("checking realms %r ", realms)
    client = _get_client()

    user = _getUserFromParam()
    login = user.login
    if realms is None:
        realm = user.realm or _getDefaultRealm()
        realms = [realm]

    ret = False
    for realm in realms:
        pol = has_client_policy(
            client,
            scope="authentication",
            action="autosms",
            realm=realm,
            user=login,
            userObj=user,
        )

        if len(pol) > 0:
            log.debug("found policy in realm %s", realm)
            ret = True

    return ret


def get_auth_challenge_response(user, ttype):
    """
    returns True, if the user in this realm with this token type should be
    authenticated via Challenge Response

    :param user: the user object
    :param ttype: the type of the token

    :return: bool
    """

    ret = False
    p_user = None
    p_realm = None
    action = "challenge_response"

    if user is not None:
        p_user = user.login
        p_realm = user.realm

    client = _get_client()

    pol = get_client_policy(
        client,
        scope="authentication",
        action=action,
        realm=p_realm,
        user=p_user,
        userObj=user,
    )

    log.debug(
        "got policy %r for user %r@%r from client %r",
        pol,
        p_user,
        p_realm,
        client,
    )

    Token_Types = get_action_value(
        pol, scope="authentication", action=action, default=""
    )

    token_types = [t.lower() for t in Token_Types.split()]

    if request_context["Path"] == "/userservice/login":
        token_types = "*"

    if ttype.lower() in token_types or "*" in token_types:
        log.debug("found matching token type %s", ttype)

        ret = True

    return ret


def _get_auth_PinPolicy(realm=None, user=None):
    """tell how the OTP PIN is to be verified within the given realm.

    Returns the PIN policy, that defines, how the OTP PIN is to be verified
    within the given realm

    :return:
        - 0 verify against fixed OTP PIN
        - 1 verify the password component against the
          UserResolver (LPAP Password etc.)
        - 2 verify no OTP PIN at all! Only OTP value!

    The policy is defined via::

        scope : authentication
        realm : ....
        action: otppin=0/1/2
        client: IP
        user  : some user
    """

    #
    #    policy value mapping - from policy defintion:
    #        'value': [0, 1, 2, "token_pin", "password", "only_otp"],

    pin_policy_lookup = {
        "token_pin": 0,
        "password": 1,
        "only_otp": 2,
    }

    log.debug("[get_auth_PinPolicy]")
    client = _get_client()

    if user is None:
        user = _getUserFromParam()
    login = user.login
    if realm is None:
        realm = user.realm or _getDefaultRealm()

    pol = get_client_policy(
        client,
        scope="authentication",
        action="otppin",
        realm=realm,
        user=login,
        userObj=user,
    )

    pin_check = get_action_value(
        pol, scope="authentication", action="otppin", default="token_pin"
    )

    # we map the named values back, to provide interface compatibility
    if pin_check in pin_policy_lookup:
        pin_check = pin_policy_lookup[pin_check]

    return pin_check


###############################################################################
#
#  Authorization
#
def check_auth_tokentype(serial, exception=False, user=None):
    """Checks if the token type of the given serial matches the tokentype policy.

    :return: True/False - returns true or false or raises an exception
                          if exception=True
    """

    log.debug("[check_auth_tokentype]")
    if serial is None:
        # if no serial is given, we return True right away
        log.debug("We have got no serial. Obviously doing passthru.")
        return True

    client = _get_client()

    if user is None:
        user = _getUserFromParam()
    login = user.login
    realm = user.realm or _getDefaultRealm()
    tokentypes = []
    tokentype = ""
    res = False

    pol = get_client_policy(
        client,
        scope="authorization",
        action="tokentype",
        realm=realm,
        user=login,
        userObj=user,
    )

    log.debug(
        "got policy %s for user %s@%s  client %s", pol, login, realm, client
    )

    t_type = get_action_value(
        pol, scope="authorization", action="tokentype", default=""
    )

    if len(t_type) > 0:
        tokentypes = [t.strip() for t in t_type.lower().split(" ")]

    log.debug("found these tokentypes: <%s>", tokentypes)

    toks = linotp.lib.token.get_tokens(None, serial)
    if len(toks) > 1:
        log.error(
            "multiple tokens with serial %s found - cannot get OTP!", serial
        )

        raise PolicyException(
            _("multiple tokens found - cannot determine tokentype!")
        )

    elif len(toks) == 1:
        log.debug("found one token with serial %s", serial)
        tokentype = toks[0].getType().lower()

        log.debug("got the type %s for token %s", tokentype, serial)

        if (
            tokentype in tokentypes
            or "*" in tokentypes
            or len(tokentypes) == 0
        ):
            res = True
    elif len(toks) == 0:
        # TODO if the user does not exist or does have no token
        # ---- WHAT DO WE DO? -- --
        #  At the moment we pass through: This is the old behaviour...
        res = True

    if res is False and exception:
        g.audit[
            "action_detail"
        ] = "failed due to authorization/tokentype policy"

        raise AuthorizeException(
            "Authorization for token %s with type %s "
            "failed on client %s" % (serial, tokentype, client)
        )

    return res


def check_auth_serial(serial, exception=False, user=None):
    """
    Checks if the token with the serial number matches the serial
    authorize policy scope=authoriztaion, action=serial

    :param serial: The serial number of the token to check
    :type serial: string
    :param exception: If "True" an exception is raised instead of
                      returning False
    :type exception: boolean
    :param user: User to narrow down the policy
    :type user: User object

    :return: result
    :rtype: boolean
    """

    if serial is None:
        # if no serial is given, we return True right away
        log.debug("We have got no serial. Obviously doing passthru.")
        return True

    client = _get_client()

    if user is None:
        user = _getUserFromParam()
    login = user.login
    realm = user.realm or _getDefaultRealm()
    res = False

    pol = has_client_policy(
        client,
        scope="authorization",
        action="serial",
        realm=realm,
        user=login,
        userObj=user,
    )

    if len(pol) == 0:
        # No policy found, so we skip the rest
        log.debug(
            "No policy scope=authorize, action=serial for user %r, "
            "realm %r, client %r",
            login,
            realm,
            client,
        )
        return True

    log.debug(
        "got policy %s for user %s@%s  client %s", pol, login, realm, client
    )

    # extract the value from the policy
    serial_regexp = get_action_value(
        pol, scope="authorization", action="serial", default=""
    )

    log.debug(
        "found this regexp /%r/ for the serial %r", serial_regexp, serial
    )

    if re.search(serial_regexp, serial):
        log.debug("regexp matches.")
        res = True

    if res is False and exception:
        g.audit["action_detail"] = "failed due to authorization/serial policy"
        raise AuthorizeException(
            "Authorization for token %s failed on "
            "client %s" % (serial, client)
        )

    return res


def is_auth_return(success=True, user=None):
    """
    returns True if the policy
        scope = authorization
        action = detail_on_success/detail_on_fail
        is set.

    :param success: Defines if we should check of the policy
                    detaul_on_success (True) or detail_on_fail (False)
    :type success: bool
    """
    ret = False

    client = _get_client()

    if user is None:
        user = _getUserFromParam()

    login = user.login
    realm = user.realm or _getDefaultRealm()
    if success:
        pol = has_client_policy(
            client,
            scope="authorization",
            action="detail_on_success",
            realm=realm,
            user=login,
            userObj=user,
        )
    else:
        pol = has_client_policy(
            client,
            scope="authorization",
            action="detail_on_fail",
            realm=realm,
            user=login,
            userObj=user,
        )

    if len(pol):
        ret = True

    return ret


# helper ################################
def get_pin_policies(user):
    """
    lookup for the pin policies - the list of policies
    is preserved for repeated lookups

    : raises: exception, if more then one pin policies are matching

    :param user: the policies which are applicable to the user
    :return: list of otppin id's
    """
    pin_policies = []

    pin_policies.append(_get_auth_PinPolicy(user=user))
    pin_policies = list(set(pin_policies))

    # ---------------------------------------------------------------------- --

    # in the context of the selfservice login we precheck the password
    # so thate the password could be ignored at all

    if request_context["Path"] == "/userservice/login":
        pin_policies = [1]

    if request_context["Path"] == "/userservice/verify":
        pin_policies = [3]

    if len(pin_policies) > 1:
        msg = (
            "conflicting authentication polices. "
            "Check scope=authentication. policies: %r" % pin_policies
        )

        log.error("[__checkToken] %r", msg)
        raise Exception("multiple pin policies found")

    return pin_policies


def get_active_token_statuses_for_reporting(realm):
    """
    parse reporting policies for given realm and user
    :param realm: the realm to be reported
    :return: list of status like [assigned, active&unassigned, total]
    """

    if not realm:
        realm = None

    report_policies = getPolicy({"scope": "reporting", "realm": realm})
    unique_statuses = set()

    for polname, policy in sorted(report_policies.items()):
        actions = str(policy.get("action", "")).split(",")

        for act in actions:
            if "token_total" in act:
                unique_statuses.add("total")
            if "token_user_total" in act:
                unique_statuses.add("total users")
            if "token_status" in act:
                status = act.split("=")[1]
                unique_statuses.add(status)
            if act == "*":
                all_status_values = [
                    "active",
                    "inactive",
                    "assigned",
                    "unassigned",
                    "active&assigned",
                    "active&unassigned",
                    "inactive&assigned",
                    "inactive&unassigned",
                    "total",
                    "total users",
                ]
                unique_statuses.update(all_status_values)
    return list(unique_statuses)


def supports_offline(realms, token):
    """Check if offline is allowed for the given token.

    :param realms: the realms to be checked
    :param token: the token to be checked

    :returns bool
    """
    client = _get_client()

    if realms is None or len(realms) == 0:
        realms = ["/:no realm:/"]

    for realm in realms:
        policy = get_client_policy(
            client=client,
            scope="authentication",
            action="support_offline",
            realm=realm,
        )

        action_value = get_action_value(
            policy,
            scope="authentication",
            action="support_offline",
            default="",
        )

        if action_value:
            token_types = action_value.split()
            if token.getType() in token_types:
                return True

    return False


def get_partition(realms, user):
    """Get the partition (key pair identifier) that should be used."""

    login = None
    action_values = set()

    client = _get_client()

    if realms is None or len(realms) == 0:
        realms = ["/:no realm:/"]

    for realm in realms:
        policy = get_client_policy(
            client=client,
            scope="enrollment",
            action="partition",
            realm=realm,
            user=login,
        )

        action_value = get_action_value(
            policy, scope="enrollment", action="partition", default=0
        )

        if action_value:
            action_values.add(action_value)

    if not action_values:
        return 0

    if len(action_values) > 1:
        raise Exception(
            "conflicting policy values %r found for "
            "realm set: %r" % (action_values, realms)
        )

    return action_values.pop()


def get_single_auth_policy(policy_name, user=None, realms=None):
    """Retrieves a policy value and checks if the value is consistent across realms.

    :param policy_name: the name of the policy, e.g:
        * qrtoken_pairing_callback_url
        * qrtoken_pairing_callback_sms
        * qrtoken_challenge_response_url
        * qrtoken_challenge_response_sms

    :param realms: the realms that his policy should be effective in
    """

    login = None
    action_values = set()
    client = _get_client()

    if user and user.login and user.realm:
        realms = [user.realm]
        login = user.login

    if realms is None or len(realms) == 0:
        realms = ["/:no realm:/"]

    for realm in realms:
        policy = get_client_policy(
            client=client,
            scope="authentication",
            action=policy_name,
            realm=realm,
            user=login,
            userObj=user,
        )

        action_value = get_action_value(
            policy, scope="authentication", action=policy_name, default=""
        )

        if action_value:
            action_values.add(action_value)

    if not action_values:
        return None

    if len(action_values) > 1:
        raise Exception(
            "conflicting policy values %r found for "
            "realm set: %r" % (action_values, realms)
        )

    return action_values.pop()


# eof ####################################################################

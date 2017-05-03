# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
""" policy processing """

import logging

import re

from copy import deepcopy

import linotp

from linotp.lib.user import User
from linotp.lib.user import getResolversOfUser

from linotp.lib.error import LinotpError
from linotp.lib.error import ParameterError

from linotp.lib.context import request_context as context

from linotp.lib.policy.definitions import SYSTEM_ACTIONS

from linotp.lib.policy.processing import _getAuthorization
from linotp.lib.policy.processing import getPolicy
from linotp.lib.policy.processing import get_client_policy
from linotp.lib.policy.processing import search_policy
from linotp.lib.policy.processing import has_client_policy

from linotp.lib.policy.util import get_realm_from_policies
from linotp.lib.policy.util import get_resolvers_for_realms
from linotp.lib.policy.util import getPolicyActionValue
from linotp.lib.policy.util import _getAuthenticatedUser
from linotp.lib.policy.util import _get_client
from linotp.lib.policy.util import _get_pin_values
from linotp.lib.policy.util import _getDefaultRealm
from linotp.lib.policy.util import _getLinotpConfig
from linotp.lib.policy.util import _getRealms
from linotp.lib.policy.util import _getUserFromParam
from linotp.lib.policy.util import _getUserRealms
from linotp.lib.policy.util import letters
from linotp.lib.policy.util import digits

# for generating random passwords
from linotp.lib.crypto import urandom
from linotp.lib.util import uniquify


log = logging.getLogger(__name__)

# This dictionary maps the token_types to actions in the scope gettoken,
# that define the maximum allowed otp valies in case of getotp/getmultiotp
MAP_TYPE_GETOTP_ACTION = {"dpw": "max_count_dpw",
                          "hmac": "max_count_hotp",
                          "totp": "max_count_totp", }


class PolicyException(LinotpError):
    def __init__(self, description="unspecified error!"):
        LinotpError.__init__(self, description=description, id=410)


class AuthorizeException(LinotpError):
    def __init__(self, description="unspecified error!"):
        LinotpError.__init__(self, description=description, id=510)


def checkAuthorisation(scope, method):
    """
    check if the authenticated user has the right to do the given action
    :param scope: scope of the policy to be checked
    :param method: the requested action
    :return: nothing if authorized, else raise PolicyException
    """
    _ = context['translate']

    auth = _getAuthorization(scope, method)
    if auth['active'] and not auth['auth']:
        log.warning("the user >%r< is not allowed to "
                    "do %s", auth['admin'], scope)

        ret = _("You do not have the administrative right to do this. You are "
                "missing a policy scope=%s, action=%s") % (scope, method)

        raise PolicyException(ret)


def _checkAdminPolicyPost(method, param=None, user=None):
    ret = {}
    controller = 'admin'
    _ = context['translate']

    log.debug("entering controller %s", controller)
    log.debug("entering method %s", method)
    log.debug("using params %s", param)

    serial = param.get("serial")

    if user is None:
        user = _getUserFromParam()

    if method in ['init', 'assign', 'setPin', 'loadtokens']:
        # check if we are supposed to genereate a random OTP PIN
        randomPINLength = _getRandomOTPPINLength(user)

        if randomPINLength > 0:
            newpin = _getRandomPin(randomPINLength)

            log.debug("setting random pin for token with serial %s and user: "
                      "%s", serial, user)

            linotp.lib.token.setPin(newpin, None, serial)
            log.debug("pin set")
            # TODO: This random PIN could be processed and
            # printed in a PIN letter

        if method == 'assign':
            if not _checkTokenNum(realm=user.realm, post_check=True):
                admin = context['AuthUser']

                log.warning("the admin >%s< is not allowed to enroll any more "
                            "tokens for the realm %s", admin, user.realm)

                raise PolicyException(_("The maximum allowed number of tokens "
                                        "for the realm %s was reached. You can"
                                        " not init any more tokens. Check the "
                                        "policies scope=enrollment, "
                                        "action=tokencount.") % user.realm)

    elif method == 'getserial':
        # check if the serial/token, that was returned is in
        # the realms of the admin!
        policies = getAdminPolicies("getserial")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial,
                                        User('', '', ''))):

            log.warning("the admin >%s< is not allowed to get "
                        "serial of token %s", policies['admin'], serial)

            raise PolicyException(_("You do not have the administrative "
                                    "right to get serials from this realm!"))
    else:
        # unknown method
        log.error("an unknown method <<%s>> was passed.", method)

        raise PolicyException(_("Failed to run getPolicyPost. "
                                "Unknown method: %s") % method)
    return ret


def _checkSystemPolicyPost(method, param=None, user=None):

    ret = {}
    controller = 'system'
    _ = context['translate']

    log.debug("entering controller %s", controller)

    if method == 'getRealms':
        systemReadRights = False
        res = param['realms']
        auth = _getAuthorization('system', 'read')
        if auth['auth']:
            systemReadRights = True

        if not systemReadRights:
            # If the admin is not allowed to see all realms,
            # (policy scope=system, action=read)
            # the realms, where he has no administrative rights need,
            # to be stripped.
            pol = getAdminPolicies('')
            if pol['active']:
                log.debug("the admin has policies "
                          "in these realms: %r", pol['realms'])

                lowerRealms = uniquify(pol['realms'])
                for realm, _v in res.items():
                    if (realm.lower() not in lowerRealms and
                       '*' not in lowerRealms):

                        log.debug("the admin has no policy in realm %r. "
                                  "Deleting it: %r", realm, res)

                        del res[realm]
            else:

                log.error("system: : getRealms: The admin >%s< is not "
                          "allowed to read system config and has not "
                          "realm administrative rights!", auth['admin'])

                raise PolicyException(_("You do not have system config read "
                                        "rights and not realm admin "
                                        "policies."))

        ret['realms'] = res
    return ret


def _checkSelfservicePolicyPost(method, param=None, user=None):

    ret = {}
    _ = context['translate']
    controller = 'selfservice'

    log.debug("entering controller %s", controller)
    log.debug("entering method %s", method)
    log.debug("using params %s", param)

    serial = param.get("serial")

    if user is None:
        user = _getUserFromParam()

    if method == 'enroll':
        # check if we are supposed to genereate a random OTP PIN
        randomPINLength = _getRandomOTPPINLength(user)
        if randomPINLength > 0:
            newpin = _getRandomPin(randomPINLength)

            log.debug("setting random pin for token with serial "
                      "%s and user: %s", serial, user)

            linotp.lib.token.setPin(newpin, None, serial)
            log.debug("[init] pin set")
            # TODO: This random PIN could be processed and
            # printed in a PIN letter

    return ret


def _checkAdminPolicyPre(method, param=None, authUser=None, user=None):
    ret = {}
    _ = context['translate']

    if not param:
        param = {}

    serial = param.get("serial")
    if user is None:
        user = _getUserFromParam()

    realm = param.get("realm")
    if realm is None or len(realm) == 0:
        realm = _getDefaultRealm()

    if method == "show":
        log.debug("[checkPolicyPre] entering method %s", method)

        # get the realms for this administrator
        policies = getAdminPolicies('')

        log.debug("[checkPolicyPre] The admin >%s< may manage the "
                  "following realms: %s",
                  policies['admin'], policies['realms'])

        if policies['active'] and len(policies['realms']) == 0:

            log.error("[checkPolicyPre] The admin >%s< has no rights in "
                      "any realms!", policies['admin'])

            raise PolicyException(_("You do not have any rights in any "
                                    "realm! Check the policies."))
        return {'realms': policies['realms'], 'admin': policies['admin'],
                "active": policies['active']}

    elif method == 'token_method':

        log.debug("[checkPolicyPre] entering method %s", method)

        # get the realms for this administrator
        policies = getAdminPolicies('token_method')

        log.debug("[checkPolicyPre] The admin >%s< may manage the "
                  "following realms: %s",
                  policies['admin'], policies['realms'])

        if policies['active'] and len(policies['realms']) == 0:

            log.error("[checkPolicyPre] The admin >%s< has no rights in "
                      "any realms!", policies['admin'])

            raise PolicyException(_("You do not have any rights in any "
                                    "realm! Check the policies."))

        return {'realms': policies['realms'], 'admin': policies['admin'],
                "active": policies['active']}

    elif method == 'remove':
        policies = getAdminPolicies("remove")
        # FIXME: A token that belongs to multiple realms should not be
        #        deleted. Should it? If an admin has the right on this
        #        token, he might be allowed to delete it,
        #        even if the token is in other realms.
        # We could use fitAllRealms=True
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):

            log.warning("the admin >%s< is not allowed to remove token %s for "
                        "user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to remove token %s. Check the "
                                    "policies.") % serial)

    elif method == 'enable':
        policies = getAdminPolicies("enable")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):

            log.warning("[enable] the admin >%s< is not allowed to enable "
                        "token %s for user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to enable token %s. Check the "
                                    "policies.") % serial)

        if not _checkTokenNum():
            log.error("The maximum token number is reached!")
            raise PolicyException(_("You may not enable any more tokens. "
                                    "Your maximum token number is "
                                    "reached!"))

        # We need to check which realm the token will be in.
        realmList = linotp.lib.token.getTokenRealms(serial)
        for r in realmList:
            if not _checkTokenNum(realm=r):

                log.warning("the maximum tokens for the realm %s is "
                            "exceeded.", r)

                raise PolicyException(_("You may not enable any more tokens "
                                        "in realm %s. Check the policy "
                                        "'tokencount'") % r)

    elif method == 'disable':
        policies = getAdminPolicies("disable")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):

            log.warning("the admin >%s< is not allowed to disable token %s for"
                        " user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to disable token %s. Check the "
                                    "policies.") % serial)

    elif method == 'copytokenpin':
        policies = getAdminPolicies("copytokenpin")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):

            log.warning("the admin >%s< is not allowed to copy token pin of "
                        "token %s for user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to copy PIN of token %s. Check "
                                    "the policies.") % serial)

    elif method == 'copytokenuser':
        policies = getAdminPolicies("copytokenuser")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):

            log.warning("the admin >%s< is not allowed to copy token user of "
                        "token %s for user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to copy user of token %s. Check "
                                    "the policies.") % serial)

    elif method == 'losttoken':
        policies = getAdminPolicies("losttoken")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):

            log.warning("the admin >%s< is not allowed to run "
                        "the losttoken workflow for token %s for "
                        "user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to run the losttoken workflow "
                                    "for token %s. Check the "
                                    "policies.") % serial)

    elif method == 'getotp':
        policies = getAdminPolicies("getotp")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):

            log.warning("the admin >%s< is not allowed to run the getotp "
                        "workflow for token %s for user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to run the getotp workflow for "
                                    "token %s. Check the policies.") % serial)

    elif method == 'getserial':
        policies = getAdminPolicies("getserial")
        # check if we want to search the token in certain realms
        if realm is not None:
            dummy_user = User('dummy', realm, None)
        else:
            dummy_user = User('', '', '')
            # We need to allow this, as no realm was passed at all.
            policies['realms'] = '*'
        if (policies['active'] and not
                checkAdminAuthorization(policies, None, dummy_user)):

            log.warning("the admin >%s< is not allowed to get serials for user"
                        " %s@%s", policies['admin'], user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to get serials by OTPs in "
                                    "this realm!"))

    elif method == 'init':
        ttype = param.get("type")
        # possible actions are:
        # initSPASS,     initHMAC,    initETNG, initSMS,     initMOTP
        policies = {}
        # default: we got HMAC / ETNG
        log.debug("[checkPolicyPre] checking init action")

        from linotp.lib.support import check_license_restrictions
        if linotp.lib.support.check_license_restrictions():
            raise PolicyException(_("Due to license restrictions no more"
                                    " tokens could be enrolled!"))

        if ((not ttype) or
                (ttype and (ttype.lower() == "hmac"))):
            p1 = getAdminPolicies("initHMAC")
            p2 = getAdminPolicies("initETNG")
            policies = {'active': p1['active'],
                        'admin': p1['admin'],
                        'realms': p1['realms'] + p2['realms'],
                        'resolvers': p1['resolvers'] + p2['resolvers']}
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
                raise Exception(_("The tokentype '%s' could not be "
                                  "found.") % ttype)

        # We need to assure, that an admin does not enroll a token into a
        # realm were he has no ACCESS! : -(
        # The admin may not enroll a token with a serial, that is already
        # assigned to a user outside of his realm

        # if a user is given, we need to check the realm of this user
        log.debug("checking realm of the user")
        if (policies['active'] and (user.login != "" and not
           checkAdminAuthorization(policies, "", user))):

            log.warning("the admin >%s< is not allowed to enroll token %s of "
                        "type %s to user %s@%s", policies['admin'],
                        serial, ttype, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to init token %s of type %s to "
                                    "user %s@%s. Check the policies.") % (
                                        serial, ttype, user.login, user.realm))

        # no right to enroll token in any realm
        log.debug("checking enroll token at all")
        if policies['active'] and len(policies['realms']) == 0:

            log.warning("the admin >%s< is not allowed to enroll "
                        "a token at all.", policies['admin'])

            raise PolicyException(_("You do not have the administrative "
                                    "right to enroll tokens. Check the "
                                    "policies."))

        # the token is assigned to a user, not in the realm of the admin!
        # we only need to check this, if the token already exists. If
        # this is a new token, we do not need to check this.
        log.debug("checking for token existens")

        if policies['active'] and linotp.lib.token.tokenExist(serial):
            if not checkAdminAuthorization(policies, serial, ""):

                log.warning("the admin >%s< is not allowed to enroll token %s "
                            "of type %s.", policies['admin'], serial, ttype)

                raise PolicyException(_("You do not have the administrative "
                                        "right to init token %s of type %s.")
                                      % (serial, ttype))

        # Here we check, if the tokennum exceeded
        log.debug("checking number of tokens")
        if not _checkTokenNum():
            log.error("The maximum token number is reached!")
            raise PolicyException(_("You may not enroll any more tokens. "
                                    "Your maximum token number is reached!"))

        # if a policy restricts the tokennumber for a realm
        log.debug("checking tokens in realms %s", policies['realms'])
        for _realm in policies['realms']:

            if not _checkTokenNum(realm=_realm):

                log.warning("the admin >%s< is not allowed to enroll any more "
                            "tokens for the realm %s",
                            policies['admin'], _realm)

                raise PolicyException(_("The maximum allowed number of "
                                        "tokens for the realm %s was "
                                        "reached. You can not init any more "
                                        "tokens. Check the policies "
                                        "scope=enrollment, "
                                        "action=tokencount.") % _realm)

        log.debug("checking tokens in realm for user %s", user)
        if not _checkTokenNum(user=user):

            log.warning("the admin >%s< is not allowed to enroll any more "
                        "tokens for the realm %s",
                        policies['admin'], user.realm)

            raise PolicyException(_("The maximum allowed number of tokens "
                                    "for the realm %s was reached. You can "
                                    "not init any more tokens. Check the "
                                    "policies scope=enrollment, "
                                    "action=tokencount.") % user.realm)

        log.debug("checking tokens of user")
        # if a policy restricts the tokennumber for the user in a realm
        if not _checkTokenAssigned(user):

            log.warning("the maximum number of allowed tokens per user is "
                        "exceeded. Check the policies")

            raise PolicyException(_("The maximum number of allowed tokens "
                                    "per user is exceeded. Check the "
                                    "policies scope=enrollment, "
                                    "action=maxtoken"))
        # ==== End of policy check 'init' ======
        ret['realms'] = policies['realms']

    elif method == 'unassign':

        policies = getAdminPolicies("unassign")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):

            log.warning("the admin >%s< is not allowed to unassign token %s "
                        "for user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to unassign token %s. Check the "
                                    "policies.") % serial)

    elif method == 'assign':
        policies = getAdminPolicies("assign")

        # the token is assigned to a user, not in the realm of the admin!
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, "")):

            log.warning("the admin >%s< is not allowed to assign token %s. ",
                        policies['admin'], serial)

            raise PolicyException(_("You do not have the administrative "
                                    "right to assign token %s. "
                                    "Check the policies.") % (serial))

        # The user, the token should be assigned to,
        # is not in the admins realm
        if (policies['active'] and not
                checkAdminAuthorization(policies, "", user)):

            log.warning("the admin >%s< is not allowed to assign "
                        "token %s for user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to assign token %s. Check the "
                                    "policies.") % serial)

        # check the number of assigned tokens
        if not _checkTokenAssigned(user):

            log.warning("the maximum number of allowed tokens is exceeded. "
                        "Check the policies")

            raise PolicyException(_("the maximum number of allowed tokens "
                                    "is exceeded. Check the policies"))

    elif method == 'setPin':

        if "userpin" in param:
            if "userpin" not in param:
                raise ParameterError(_("Missing parameter: %r")
                                     % "userpin", id=905)

            # check admin authorization
            policies1 = getAdminPolicies("setSCPIN")
            policies2 = getAdminPolicies("setMOTPPIN")
            _usr = User("", "", "")
            if ((policies1['active'] and not
                 (checkAdminAuthorization(policies1, serial, _usr))) or
                (policies2['active'] and not
                 (checkAdminAuthorization(policies2, serial, _usr)))):

                log.warning("the admin >%s< is not allowed to set MOTP PIN/SC "
                            "UserPIN for token %s.",
                            policies1['admin'], serial)

                raise PolicyException(_("You do not have the administrative "
                                        "right to set MOTP PIN/ SC UserPIN "
                                        "for token %s. Check the policies.")
                                      % serial)

        if "sopin" in param:
            if "sopin" not in param:
                raise ParameterError(_("Missing parameter: %r")
                                     % "sopin", id=905)

            # check admin authorization
            policies = getAdminPolicies("setSCPIN")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial,
                                            User("", "", ""))):

                log.warning("the admin >%s< is not allowed to setPIN for "
                            "token %s.", policies['admin'], serial)

                raise PolicyException(_("You do not have the administrative "
                                        "right to set Smartcard PIN for "
                                        "token %s. Check the policies.")
                                      % serial)

    elif method == 'set':

        if "pin" in param:
            policies = getAdminPolicies("setOTPPIN")
            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):

                log.warning("the admin >%s< is not allowed to set "
                            "OTP PIN for token %s for user %s@%s",
                            policies['admin'], serial, user.login, user.realm)

                raise PolicyException(_("You do not have the administrative "
                                        "right to set OTP PIN for token %s. "
                                        "Check the policies.") % serial)

        if ("MaxFailCount".lower() in param or "SyncWindow".lower() in param or
           "CounterWindow".lower() in param or "OtpLen".lower() in param):

            policies = getAdminPolicies("set")

            if (policies['active'] and not
                    checkAdminAuthorization(policies, serial, user)):

                log.warning("the admin >%s< is not allowed to set "
                            "token properites for %s for user %s@%s",
                            policies['admin'], serial, user.login, user.realm)

                raise PolicyException(_("You do not have the administrative "
                                        "right to set token properties for "
                                        "%s. Check the policies.") % serial)

    elif method == 'resync':

        policies = getAdminPolicies("resync")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):

            log.warning("the admin >%s< is not allowed to resync token %s for "
                        "user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to resync token %s. Check the "
                                    "policies.") % serial)

    elif method == 'userlist':
        policies = getAdminPolicies("userlist")
        # check if the admin may view the users in this realm
        if (policies['active'] and
                not checkAdminAuthorization(policies, "", user)):

            log.warning("the admin >%s< is not allowed to list"
                        " users in realm %s(%s)!", policies['admin'],
                        user.realm, user.resolver_config_identifier)

            raise PolicyException(_("You do not have the administrative"
                                  " right to list users in realm %s(%s).")
                                  % (user.realm,
                                  user.resolver_config_identifier))

    elif method == 'tokenowner':
        policies = getAdminPolicies("tokenowner")
        # check if the admin may view the users in this realm
        if (policies['active'] and
                not checkAdminAuthorization(policies, "", user)):

            log.warning("the admin >%s< is not allowed to get"
                        " the token owner in realm %s(%s)!",
                        policies['admin'], user.realm,
                        user.resolver_config_identifier)

            raise PolicyException(_("You do not have the administrative"
                                    " right to get the token owner in realm"
                                    " %s(%s).") % (user.realm,
                                    user.resolver_config_identifier))

    elif method == 'checkstatus':
        policies = getAdminPolicies("checkstatus")
        # check if the admin may view the users in this realm
        if (policies['active'] and not
                checkAdminAuthorization(policies, "", user)):

            log.warning("the admin >%s< is not allowed to show status of token"
                        " challenges in realm %s(%s)!", policies['admin'],
                        user.realm, user.resolver_config_identifier)

            raise PolicyException(_("You do not have the administrative "
                                    "right to show status of token "
                                    "challenges in realm "
                                    "%s(%s).")
                                  % (user.realm,
                                     user.resolver_config_identifier))

    elif method == 'tokenrealm':

        log.debug("entering method %s", method)

        # The admin needs to have the right "manageToken" for all realms,
        # the token is currently in and all realm the Token should go into.
        policies = getAdminPolicies("manageToken")

        if "realms" not in param:
            raise ParameterError(_("Missing parameter: %r")
                                 % "realms", id=905)

        realms = param["realms"]

        # List of the new realms
        realmNewList = realms.split(',')
        # List of existing realms
        realmExistList = linotp.lib.token.getTokenRealms(serial)

        for r in realmExistList:
            if (policies['active'] and not
                checkAdminAuthorization(policies, None,
                                        User("dummy", r, None))):

                log.warning("the admin >%s< is not allowed "
                            "to manage tokens in realm %s",
                            policies['admin'], r)

                raise PolicyException(_("You do not have the administrative "
                                        "right to remove tokens from realm "
                                        "%s. Check the policies.") % r)

        for r in realmNewList:
            if (policies['active'] and not
                checkAdminAuthorization(policies, None,
                                        User("dummy", r, None))):

                log.warning("the admin >%s< is not allowed "
                            "to manage tokens in realm %s",
                            policies['admin'], r)

                raise PolicyException(_("You do not have the administrative "
                                        "right to add tokens to realm %s. "
                                        "Check the policies.") % r)

            if not _checkTokenNum(realm=r):

                log.warning("the maximum tokens for the "
                            "realm %s is exceeded.", r)

                raise PolicyException(_("You may not put any more tokens in "
                                        "realm %s. Check the policy "
                                        "'tokencount'") % r)

    elif method == 'reset':

        policies = getAdminPolicies("reset")
        if (policies['active'] and not
                checkAdminAuthorization(policies, serial, user)):

            log.warning("the admin >%s< is not allowed to reset "
                        "token %s for user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to reset token %s. Check the "
                                    "policies.") % serial)

    elif method == 'import':
        policies = getAdminPolicies("import")

        # no right to import token in any realm
        log.debug("checking import token at all")

        if policies['active'] and len(policies['realms']) == 0:

            log.warning("the admin >%s< is not allowed to import a "
                        "token at all.", policies['admin'])

            raise PolicyException(_("You do not have the administrative "
                                    "right to import tokens. Check the "
                                    "policies."))

        ret['realms'] = policies['realms']

    elif method == 'loadtokens':
        tokenrealm = param.get('tokenrealm')
        policies = getAdminPolicies("import")

        if policies['active'] and tokenrealm not in policies['realms']:

            log.warning("the admin >%s< is not allowed to "
                        "import token files to realm %s: %s",
                        policies['admin'], tokenrealm, policies)

            raise PolicyException(_("You do not have the administrative "
                                    "right to import token files to realm %s"
                                    ". Check the policies.") % tokenrealm)

        if not _checkTokenNum(realm=tokenrealm):

            log.warning("the maximum tokens for the realm "
                        "%s is exceeded.", tokenrealm)

            raise PolicyException(_("The maximum number of allowed tokens "
                                    "in realm %s is exceeded. Check policy "
                                    "tokencount!") % tokenrealm)

    elif method == 'unpair':

        policies = getAdminPolicies("unpair")
        if (policies['active'] and not
           checkAdminAuthorization(policies, serial, user)):

            log.warning("the admin >%s< is not allowed to unpair token %s "
                        "for user %s@%s",
                        policies['admin'], serial, user.login, user.realm)

            raise PolicyException(_("You do not have the administrative "
                                    "right to unpair token %s. Check the "
                                    "policies.") % serial)

    else:
        # unknown method
        log.error("an unknown method <<%s>> was passed.", method)

        raise PolicyException(_("Failed to run checkPolicyPre. "
                                "Unknown method: %s") % method)

    return ret


def _checkGetTokenPolicyPre(method, param=None, authUser=None, user=None):
    ret = {}
    _ = context['translate']

    if not param:
        param = {}

    if method[0: len('max_count')] == 'max_count':
        ret = 0
        serial = param.get("serial")

        ttype = linotp.lib.token.getTokenType(serial).lower()
        trealms = linotp.lib.token.getTokenRealms(serial)
        pol_action = MAP_TYPE_GETOTP_ACTION.get(ttype, "")
        admin_user = _getAuthenticatedUser()

        if pol_action == "":
            raise PolicyException(_("There is no policy gettoken/"
                                    "max_count definable for the "
                                    "tokentype %r") % ttype)

        policies = {}
        for realm in trealms:
            pol = getPolicy({'scope': 'gettoken', 'realm': realm,
                             'user': admin_user['login'],
                             'action': pol_action})

            log.error("got a policy: %r", policies)

            policies.update(pol)

        value = getPolicyActionValue(policies, pol_action)

        log.debug("got all policies: %r: %r", policies, value)

        ret = value

    return ret


def _checkAuditPolicyPre(method, param=None, authUser=None, user=None):

    ret = {}
    _ = context['translate']

    if not param:
        param = {}

    if method == 'view':
        auth = _getAuthorization("audit", "view")
        if auth['active'] and not auth['auth']:

            log.warning("the admin >%r< is not allowed to "
                        "view the audit trail", auth['admin'])

            ret = _("You do not have the administrative right to view the "
                    "audit trail. You are missing a policy "
                    "scope=audit, action=view")
            raise PolicyException(ret)
    else:
        log.error("an unknown method was passed in : %s", method)

        raise PolicyException(_("Failed to run checkPolicyPre. Unknown "
                                "method: %s") % method)

    return ret


def _checkManagePolicyPre(method, param=None, authUser=None, user=None):
    controller = 'manage'
    ret = {}
    log.debug("entering controller %s", controller)
    return ret


def _checkOcraPolicyPre(method, param=None, authUser=None, user=None):

    ret = {}
    _ = context['translate']
    client = _get_client()

    if not param:
        param = {}

    method_map = {'request': 'request',
                  'status': 'checkstatus',
                  'activationcode': 'getActivationCode',
                  'calcOTP': 'calculateOtp'}

    admin_user = _getAuthenticatedUser()

    policies = getPolicy({'user': admin_user.get('login'),
                          'scope': 'ocra',
                          'action': method,
                          'client': client})

    if len(policies) == 0:

        log.warning("the admin >%r< is not allowed to do an ocra/%r",
                    admin_user.get('login'), method_map.get(method))

        raise PolicyException(_("You do not have the administrative right to"
                                " do an ocra/%s") % method_map.get(method))

    return ret


def _checkToolsPolicyPre(method, param=None, authUser=None, user=None):
    ret = {}
    _ = context['translate']

    if not param:
        param = {}

    auth = _getAuthorization("tools", method)
    if auth['active'] and not auth['auth']:

        log.warning("the admin >%r< is not allowed to "
                    "view the audit trail", auth['admin'])

        ret = _("You do not have the administrative right to manage tools. "
                "You are missing a policy scope=tools, action=%s") % method

        raise PolicyException(ret)

    return True


def _checkSelfservicePolicyPre(method, param=None, authUser=None, user=None):

    ret = {}
    _ = context['translate']
    controller = 'selfservice'
    client = _get_client()

    if not param:
        param = {}

    log.debug("entering controller %s", controller)

    if method[0: len('max_count')] == 'max_count':
        ret = 0
        serial = param.get("serial")
        ttype = linotp.lib.token.getTokenType(serial).lower()
        urealm = authUser.realm
        pol_action = MAP_TYPE_GETOTP_ACTION.get(ttype, "")

        if pol_action == "":
            raise PolicyException(_("There is no policy selfservice/"
                                    "max_count definable for the token "
                                    "type %s.") % ttype)

        policies = get_client_policy(client, scope='selfservice',
                                     realm=urealm, user=authUser.login,
                                     userObj=authUser)

        log.debug("[max_count] got a policy: %r", policies)

        if policies == {}:
            raise PolicyException(_("There is no policy selfservice/"
                                    "max_count defined for the tokentype "
                                    "%s in realm %s.") % (ttype, urealm))

        value = getPolicyActionValue(policies, pol_action)

        log.debug("[max_count] got all policies: %r: %r", policies, value)

        ret = value

    elif method == 'usersetpin':

        if 'setOTPPIN' not in getSelfserviceActions(authUser):

            log.warning("user %s@%s is not allowed to call this function!",
                        authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif method == 'userreset':

        if 'reset' not in getSelfserviceActions(authUser):

            log.warning("user %s@%s is not allowed to call this function!",
                        authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you '
                                    'to issue this request!'))

    elif method == 'userresync':

        if 'resync' not in getSelfserviceActions(authUser):

            log.warning("user %s@%s is not allowed to call this function!",
                        authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you '
                                    'to issue this request!'))

    elif method == 'usersetmpin':

        if 'setMOTPPIN' not in getSelfserviceActions(authUser):

            log.warning("user %r@%r is not allowed to call this function!",
                        authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif method == 'useractivateocratoken':

        user_selfservice_actions = getSelfserviceActions(authUser)
        typ = param.get('type').lower()

        if (typ == 'ocra' and 'activateQR' not in user_selfservice_actions):

            log.warning("user %r@%r is not allowed to call this function!",
                        authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif method == 'useractivateocra2token':

        user_selfservice_actions = getSelfserviceActions(authUser)
        typ = param.get('type').lower()

        if typ == 'ocra2' and 'activateQR2' not in user_selfservice_actions:

            log.warning("user %r@%r is not allowed to call "
                        "this function!", authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif method == 'userassign':

        if 'assign' not in getSelfserviceActions(authUser):

            log.warning("user %r@%r is not allowed to call "
                        "this function!", authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow '
                                  'you to issue this request!'))

        # Here we check, if the tokennum exceeds the tokens
        if not _checkTokenNum():

            log.error("The maximum token number is reached!")

            raise PolicyException(_("You may not enroll any more tokens. "
                                    "Your maximum token number is reached!"))

        if not _checkTokenAssigned(authUser):

            log.warning("the maximum number of allowed tokens is"
                        " exceeded. Check the policies")

            raise PolicyException(_("The maximum number of allowed tokens "
                                  "is exceeded. Check the policies"))

    elif method == 'usergetserialbyotp':

        if 'getserial' not in getSelfserviceActions(authUser):

            log.warning("user %s@%s is not allowed to call this function!",
                        authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you to'
                                  ' request a serial by OTP!'))

    elif method == 'userdisable':

        if 'disable' not in getSelfserviceActions(authUser):

            log.warning("user %r@%r is not allowed to call this function!",
                        authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you '
                                    'to issue this request!'))

    elif method == 'userenable':

        if 'enable' not in getSelfserviceActions(authUser):
            log.warning("user %s@%s is not allowed to call this function!",
                        authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you to'
                                  ' issue this request!'))

    elif method == 'userunassign':

        if 'unassign' not in getSelfserviceActions(authUser):
            log.warning("user %r@%r is not allowed to call this function!",
                        authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif method == 'userdelete':

        if 'delete' not in getSelfserviceActions(authUser):

            log.warning("user %r@%r is not allowed to call this function!",
                        authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

    elif method == 'userwebprovision':
        user_selfservice_actions = getSelfserviceActions(authUser)
        typ = param.get('type').lower()

        if ((typ == 'oathtoken' and
             'webprovisionOATH' not in user_selfservice_actions) or
            (typ == 'googleauthenticator_time' and
                'webprovisionGOOGLEtime' not in user_selfservice_actions) or
            (typ == 'googleauthenticator' and
                'webprovisionGOOGLE' not in user_selfservice_actions)):

            log.warning("[userwebprovision] user %r@%r is not allowed to "
                        "call this function!",
                        authUser.login, authUser.realm)
            raise PolicyException(_('The policy settings do not allow you '
                                  'to issue this request!'))

        # Here we check, if the tokennum exceeds the allowed tokens
        if not _checkTokenNum():

            log.error("The maximum token number is reached!")

            raise PolicyException(_("You may not enroll any more tokens. "
                                  "Your maximum token number "
                                  "is reached!"))

        if not _checkTokenAssigned(authUser):

            log.warning("the maximum number of allowed tokens is exceeded. "
                        "Check the policies")

            raise PolicyException(_("The maximum number of allowed tokens "
                                  "is exceeded. Check the policies"))

    elif method == 'userhistory':
        if 'history' not in getSelfserviceActions(authUser):

            log.warning("user %r@%r is not allowed to call this function!",
                        authUser.login, authUser.realm)

            raise PolicyException(_('The policy settings do not allow you '
                                    'to issue this request!'))

    elif method == 'userinit':

        allowed_actions = getSelfserviceActions(authUser)
        typ = param['type'].lower()
        meth = 'enroll' + typ.upper()

        if meth not in allowed_actions:

            log.warning("user %r@%r is not allowed to enroll %s!",
                        authUser.login, authUser.realm, typ)

            raise PolicyException(_('The policy settings do not allow '
                                  'you to issue this request!'))

        # Here we check, if the tokennum exceeds the allowed tokens
        if not _checkTokenNum():

            log.error("The maximum token number is reached!")

            raise PolicyException(_("You may not enroll any more tokens. "
                                    "Your maximum token number "
                                    "is reached!"))

        if not _checkTokenAssigned(authUser):

            log.warning("the maximum number of allowed tokens is exceeded. "
                        "Check the policies")

            raise PolicyException(_("The maximum number of allowed tokens "
                                    "is exceeded. Check the policies"))

    else:
        log.error("Unknown method in selfservice: %s", method)

        raise PolicyException(_("Unknown method in selfservice: %s") % method)

    return ret


def _checkSystemPolicyPre(method, param=None, authUser=None, user=None):
    ret = {}
    _ = context['translate']

    if not param:
        param = {}

    if method not in SYSTEM_ACTIONS:

        log.error("an unknown method was passed in system: %s", method)

        raise PolicyException(_("Failed to run checkPolicyPre. "
                              "Unknown method: %s") % method)

    auth = _getAuthorization(scope='system', action=SYSTEM_ACTIONS[method])

    if auth['active'] and not auth['auth']:

        log.warning("admin >%s< is not authorited to %s. Missing policy "
                    "scope=system, action=%s",
                    auth['admin'], method, SYSTEM_ACTIONS[method])

        raise PolicyException(_("Policy check failed. You are not allowed "
                              "to %s system config.") % SYSTEM_ACTIONS[method])

    return ret


def getAdminPolicies(action, scope='admin'):
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
    log.info("Evaluating policies for the user: %s", admin_user['login'])

    # check if we got admin policies at all
    p_at_all = getPolicy({'scope': scope})

    if not p_at_all:
        log.info("No policies in scope admin found."
                 " Admin authorization will be disabled.")
        active = False
        realms = []
        resolvers = []

    else:
        pol_request = {'user': admin_user['login'], 'scope': scope}
        if action:
            pol_request['action'] = action

        policies = getPolicy(pol_request)
        log.debug("Found the following policies: %r", policies)

        realms = get_realm_from_policies(policies)
        resolvers = get_resolvers_for_realms(realms)

    log.debug("Found the following resolvers in the policy: %r", resolvers)

    return {'active': active,
            'realms': realms,
            'resolvers': resolvers,
            'admin': admin_user['login']}


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
    if not policies['active']:
        return True

    # If the policy is valid for all realms
    if '*' in policies['realms']:
        return True

    # convert realms and resolvers to lowercase
    policies['realms'] = [x.lower() for x in policies['realms']]
    policies['resolvers'] = [x.lower() for x in policies['resolvers']]

    # in case we got a serial
    if serial != "" and serial is not None:
        realms = linotp.lib.token.getTokenRealms(serial)

        log.debug("the token %r is contained in the realms: %r",
                  serial, realms)

        log.debug("the policy contains the realms: %r", policies['realms'])

        for r in realms:
            if fitAllRealms:
                if r not in policies['realms']:
                    return False
            else:
                if r in policies['realms']:
                    return True

        return fitAllRealms

    # in case of the admin policies - no user name is verified:
    # the username could be empty (not dummy) which prevents an
    # unnecessar resolver lookup
    if user.realm:
        # default realm user
        if user.realm == "" and user.resolver_config_identifier == "":
            return _getDefaultRealm() in policies['realms']
        if not user.realm and not user.resolver_config_identifier:
            return _getDefaultRealm() in policies['realms']
        # we got a realm:
        if user.realm != "":
            return user.realm.lower() in policies['realms']
        if user.resolver_config_identifier != "":
            lower_config_id = user.resolver_config_identifier.lower()
            return lower_config_id in policies['resolvers']

    # catch all
    return False


def getSelfserviceActions(user):
    '''
    This function returns the allowed actions in the self service portal
    for the given user
    '''
    login = user.login
    realm = user.realm
    client = _get_client()

    log.debug("checking actions for scope=selfservice, realm=%r", realm)

    policies = get_client_policy(client, scope="selfservice", realm=realm,
                                 user=login, userObj=user)

    # Now we got a dictionary of all policies within the scope selfservice for
    # this realm. as there can be more than one policy, we concatenate all
    # their actions to a list later we might want to change this

    all_actions = []
    for pol in policies:
        # remove whitespaces and split at the comma
        actions = policies[pol].get('action', '')
        action_list = actions.split(',')
        all_actions.extend(action_list)

    acts = set()
    for act in all_actions:
        acts.add(act.strip())

    # return the list with all actions
    return list(acts)


def _checkTokenNum(user=None, realm=None, post_check=False):
    '''
    This internal function checks if the number of the tokens is valid...
    for a certain realm...

    Therefor it checks the policy
        "scope = enrollment", action = "tokencount = <number>"

    if there are more tokens assigned than in tokencount mentioned,
    return will be false

    :param user: the user in the realm
    :param realm: the relevant realm
    :return: boolean - True if token number is allowed
    '''

    # If there is an empty user, we need to set it to None
    if user:
        if user.login == "":
            user = None

    if user is None and realm is None:
        # No user and realm given, so we check all the tokens
        ret = True
        tNum = linotp.lib.token.getTokenNumResolver()

        log.debug("Number of tokens in DB: %i", int(tNum))
        log.debug("result of checking the token number: %i", ret)

        return ret

    else:
        # allRealms = getRealms()
        Realms = []

        if user:
            log.debug("checking token num in realm: %s, resolver: %s",
                      user.realm, user.resolver_config_identifier)

            # 1. alle resolver aus dem Realm holen.
            # 2. fuer jeden Resolver die tNum holen.
            # 3. die Policy holen und gegen die tNum checken.
            Realms = _getUserRealms(user)
        elif realm:
            Realms = [realm]

        log.debug("checking token num in realm: %r", Realms)

        tokenInRealms = {}
        for R in Realms:
            tIR = linotp.lib.token.getTokenInRealm(R)
            tokenInRealms[R] = tIR
            log.debug("There are %i tokens in realm %r", tIR, R)

        # Now we are checking the policy for every Realm! (if there are more)
        policyFound = False
        maxToken = 0
        for R in Realms:
            pol = getPolicy({'scope': 'enrollment', 'realm': R,
                             'action': 'tokencount'})

            polTNum = getPolicyActionValue(pol, 'tokencount')

            if polTNum > -1:
                policyFound = True

                if int(polTNum) > int(maxToken):
                    maxToken = int(polTNum)

            log.info("Realm: %r, max: %i, tokens in realm: %i",
                     R, int(maxToken), int(tokenInRealms[R]))

            if post_check:
                if int(maxToken) >= int(tokenInRealms[R]):
                    return True
            else:
                if int(maxToken) > int(tokenInRealms[R]):
                    return True

        if policyFound is False:
            log.debug("there is no scope=enrollment, action=tokencount policy "
                      "for the realms %r", Realms)
            return True

        log.info("No policy available for realm %r, where enough managable "
                 "tokens were defined.", Realms)

    return False


def _checkTokenAssigned(user):
    '''
    This internal function checks the number of assigned tokens to a user
    Therefore it checks the policy::

        "scope = enrollment", action = "maxtoken = <number>"

    :return: False, if the user has to many tokens assigned True, if more
        tokens may be assigned to the user
    :rtype: bool
    '''
    if user is None:
        return True
    if user.login == "":
        return True

    client = _get_client()
    Realms = _getUserRealms(user)

    log.debug("checking the already assigned tokens for user %s, realms %s",
              user.login, Realms)

    for R in Realms:
        pol = has_client_policy(client, scope='enrollment', realm=R,
                                user=user.login, userObj=user)

        log.debug("found policies %s", pol)

        if len(pol) == 0:
            log.debug("there is no scope=enrollment policy for Realm %s", R)
            return True

        maxTokenAssigned = getPolicyActionValue(pol, "maxtoken")

        # get the tokens of the user
        tokens = linotp.lib.token.getTokens4UserOrSerial(user, "")

        # If there is a policy, where the tokennumber exceeds the tokens in
        # the corresponding realm..

        log.debug("the user %r has %r tokens assigned. The policy says a "
                  "maximum of %r tokens.",
                  user.login, len(tokens), maxTokenAssigned)

        if (int(maxTokenAssigned) > int(len(tokens)) or
                maxTokenAssigned == -1):
            return True

    return False


def get_tokenissuer(user="", realm="", serial=""):
    '''
    This internal function returns the issuer of the token as defined in policy
    scope = enrollment, action = tokenissuer = <string>
    The string can have the following variables:
        <u>: user
        <r>: realm
        <s>: token serial

    This function is used to create 'otpauth' tokens
    '''
    tokenissuer = "LinOTP"
    client = _get_client()

    pol = has_client_policy(client, scope="enrollment",
                            realm=realm, user=user)

    if len(pol) != 0:
        string_issuer = getPolicyActionValue(pol, "tokenissuer",
                                             is_string=True)
        if string_issuer:
            string_issuer = re.sub('<u>', user, string_issuer)
            string_issuer = re.sub('<r>', realm, string_issuer)
            string_issuer = re.sub('<s>', serial, string_issuer)
            tokenissuer = string_issuer

    log.debug("[get_tokenissuer] providing tokenissuer = %r", tokenissuer)
    return tokenissuer


def get_tokenlabel(user="", realm="", serial=""):
    '''
    This internal function returns the naming of the token as defined in policy
    scope = enrollment, action = tokenname = <string>
    The string can have the following variables:

    - <u>: user
    - <r>: realm
    - <s>: token serial

    This function is used by the creation of googleauthenticator url
    '''
    tokenlabel = ""
    client = _get_client()

    # TODO: What happens when we got no realms?
    # pol = getPolicy( {'scope': 'enrollment', 'realm': realm} )
    pol = has_client_policy(client, scope="enrollment", action="tokenlabel",
                            realm=realm, user=user)
    if len(pol) == 0:
        # No policy, so we use the serial number as label
        log.debug("there is no scope=enrollment policy for realm %r", realm)
        tokenlabel = serial

    else:
        string_label = getPolicyActionValue(pol, "tokenlabel", is_string=True)
        if string_label == "":
            # empty label, so we use the serial
            tokenlabel = serial
        else:
            string_label = re.sub('<u>', user, string_label)
            string_label = re.sub('<r>', realm, string_label)
            string_label = re.sub('<s>', serial, string_label)
            tokenlabel = string_label

    return tokenlabel


def get_autoassignment(user):
    '''
    this function checks the policy scope=enrollment, action=autoassignment
    This is a boolean policy.
    The function returns true, if autoassignment is defined.
    '''
    ret = False
    client = _get_client()

    pol = has_client_policy(client, scope='enrollment',
                            realm=user.realm, user=user.login, userObj=user)

    if len(pol) > 0:
        val = getPolicyActionValue(pol, "autoassignment")
        # with  LinOTP 2.7 the autassign policy is treated as boolean
        if val is True:
            ret = True
        # for backwar compatibility, we accept any values
        # other than -1, which indicates an error
        elif val != -1:
            ret = True

    log.debug("got the autoassignement %r", ret)
    return ret


def get_auto_enrollment(user):
    '''
    this function checks the policy scope=enrollment, action=autoenrollment
    This policy policy returns the tokentyp: sms or email
    The function returns true, if autoenrollment is defined.
    '''
    ret = False
    token_typ = ''

    client = _get_client()

    pol = has_client_policy(client, scope='enrollment',
                            realm=user.realm, user=user.login, userObj=user)

    if len(pol) > 0:
        t_typ = getPolicyActionValue(pol, "autoenrollment", is_string=True)

        log.debug("got the token type = %s", t_typ)

        if type(t_typ) in [str, unicode] and t_typ.lower() in ['sms', 'email']:
            ret = True
            token_typ = t_typ.lower()

    return ret, token_typ


def autoassignment_forward(user):
    '''
    this function checks the policy scope=enrollment, action=autoassignment
    This is a boolean policy.
    The function returns true, if autoassignment is defined.
    '''
    ret = False
    client = _get_client()

    pol = has_client_policy(client, scope='enrollment',
                            action="autoassignment_forward",
                            realm=user.realm, user=user.login, userObj=user)

    if len(pol) > 0:
        ret = True

    return ret


def ignore_autoassignment_pin(user):
    '''
    This function checks the policy
        scope=enrollment, action=ignore_autoassignment_pin
    This is a boolean policy.
    The function returns true, if the password used in the autoassignment
    should not be set as token pin.
    '''
    ret = False
    client = _get_client()

    pol = has_client_policy(client, scope='enrollment',
                            action="ignore_autoassignment_pin",
                            realm=user.realm, user=user.login, userObj=user)

    if len(pol) > 0:
        ret = True

    return ret


def _getRandomOTPPINLength(user):
    '''
    This internal function returns the length of the random otp pin that is
    define in policy scope = enrollment, action = otp_pin_random = 111
    '''
    Realms = _getUserRealms(user)
    maxOTPPINLength = -1
    client = _get_client()

    for R in Realms:
        pol = has_client_policy(client,
                                scope='enrollment', action='otp_pin_random',
                                realm=R, user=user.login, userObj=user)
        if len(pol) == 0:
            log.debug("there is no scope=enrollment policy for Realm %r", R)
            return -1

        OTPPINLength = getPolicyActionValue(pol, "otp_pin_random")

        # If there is a policy, with a higher random pin length
        log.debug("found policy with otp_pin_random = %r", OTPPINLength)

        if int(OTPPINLength) > int(maxOTPPINLength):
            maxOTPPINLength = OTPPINLength

    return maxOTPPINLength


def getOTPPINEncrypt(serial=None, user=None):
    '''
    This function returns, if the otppin should be stored as
    an encrpyted value
    '''
    # do store as hashed value
    encrypt_pin = 0
    Realms = []
    if serial:
        Realms = linotp.lib.token.getTokenRealms(serial)
    elif user:
        Realms = _getUserRealms(user)

    log.debug("checking realms: %r", Realms)

    for R in Realms:
        pol = getPolicy({'scope': 'enrollment', 'realm': R,
                         'action': 'otp_pin_encrypt'})

        log.debug("realm: %r, pol: %r", R, pol)

        if 1 == getPolicyActionValue(pol, 'otp_pin_encrypt'):
            encrypt_pin = 1

    return encrypt_pin


def _getOTPPINPolicies(user, scope="selfservice"):
    '''
    This internal function returns the PIN policies for a realm.
    These policies can either be in the scope "selfservice" or "admin"
    The policy define when resettng an OTP PIN:

    - what should be the length of the otp pin
    - what should be the contents of the otp pin by the actions:

      - otp_pin_minlength =
      - otp_pin_maxlength =
      - otp_pin_contents = [cns] (character, number, special character)

    :return: dictionary like {contents: "cns", min: 7, max: 10}
    '''
    log.debug("[getOTPPINPolicies]")
    client = _get_client()

    Realms = _getUserRealms(user)
    ret = {'min':-1, 'max':-1, 'contents': ""}

    log.debug("searching for OTP PIN policies in scope=%r policies.", scope)
    for R in Realms:

        pol = has_client_policy(client, scope=scope, realm=R,
                                user=user.login, userObj=user)
        if len(pol) == 0:
            log.debug("there is no scope=%r policy for Realm %r",
                      scope, R)
            return ret

        pol = get_client_policy(client, scope=scope, realm=R,
                                action="otp_pin_maxlength",
                                user=user.login, userObj=user)
        n_max = getPolicyActionValue(pol, "otp_pin_maxlength")

        pol = get_client_policy(client, scope=scope, realm=R,
                                action="otp_pin_minlength",
                                user=user.login, userObj=user)
        n_min = getPolicyActionValue(pol, "otp_pin_minlength", max=False)

        pol = get_client_policy(client, scope=scope, realm=R,
                                action="otp_pin_contents",
                                user=user.login, userObj=user)
        n_contents = getPolicyActionValue(pol, "otp_pin_contents",
                                          is_string=True)

        # find the maximum length
        log.debug("find the maximum length for OTP PINs.")
        if int(n_max) > ret['max']:
            ret['max'] = n_max

        # find the minimum length
        log.debug("find the minimum length for OTP_PINs")
        if not n_min == -1:
            if ret['min'] == -1:
                ret['min'] = n_min
            elif n_min < ret['min']:
                ret['min'] = n_min

        # find all contents
        log.debug("find the allowed contents for OTP PINs")
        for k in n_contents:
            if k not in ret['contents']:
                ret['contents'] += k

    return ret


def checkOTPPINPolicy(pin, user):
    '''
    This function checks the given PIN (OTP PIN) against the policy
    returned by the function

    getOTPPINPolicy

    It returns a dictionary:
        {'success': True/False,
          'error': errortext}

    At the moment this works for the selfservice portal
    '''
    _ = context['translate']

    log.debug("[checkOTPPINPolicy]")

    pol = _getOTPPINPolicies(user)
    log.debug("checking for otp_pin_minlength")
    if pol['min'] != -1:
        if pol['min'] > len(pin):
            return {'success': False,
                    'error': _('The provided PIN is too short. It should be '
                               'at least %i characters.') % pol['min']}

    log.debug("checking for otp_pin_maxlength")
    if pol['max'] != -1:
        if pol['max'] < len(pin):
            return {'success': False,
                    'error': (_('The provided PIN is too long. It should not '
                              'be longer than %i characters.') % pol['max'])}

    log.debug("checking for otp_pin_contents")
    if pol['contents']:
        policy_c = "c" in pol['contents']
        policy_n = "n" in pol['contents']
        policy_s = "s" in pol['contents']
        policy_o = "o" in pol['contents']

        contains_c = False
        contains_n = False
        contains_s = False
        contains_other = False

        REG_POLICY_C, REG_POLICY_N, REG_POLICY_S = (
                                    _get_pin_values(context['Config']))

        for c in pin:
            if re.search(REG_POLICY_C, c):
                contains_c = True
            elif re.search(REG_POLICY_N, c):
                contains_n = True
            elif re.search(REG_POLICY_S, c):
                contains_s = True
            else:
                contains_other = True

        if pol['contents'][0] == "+":
            log.debug("checking for an additive character "
                      "group: %s", pol['contents'])
            if ((not (
                    (policy_c and contains_c) or
                    (policy_s and contains_s) or
                    (policy_o and contains_other) or
                    (policy_n and contains_n)
                    )
                 ) or (
                    (not policy_c and contains_c) or
                    (not policy_s and contains_s) or
                    (not policy_n and contains_n) or
                    (not policy_o and contains_other))):
                return {'success': False,
                        'error': _("The provided PIN does not contain "
                                   "characters of the group or it does "
                                   "contains characters that are not in the "
                                   "group %s")
                                 % pol['contents']}
        else:
            log.debug("[checkOTPPINPolicy] normal check: %s", pol['contents'])
            if policy_c and not contains_c:
                return {'success': False,
                        'error': _('The provided PIN does not contain any '
                                   'letters. Check policy otp_pin_contents.')}
            if policy_n and not contains_n:
                return {'success': False,
                        'error': _('The provided PIN does not contain any '
                                   'numbers. Check policy otp_pin_contents.')}
            if policy_s and not contains_s:
                return {'success': False,
                        'error': _('The provided PIN does not contain any '
                                   'special characters. It should contain '
                                   'some of these characters like '
                                   '.: ,;-_<>+*~!/()=?$. Check policy '
                                   'otp_pin_contents.')}
            if policy_o and not contains_other:
                return {'success': False,
                        'error': _('The provided PIN does not contain any '
                                   'other characters. It should contain some'
                                   ' of these characters that are not '
                                   'contained in letters, digits and the '
                                   'defined special characters. Check policy '
                                   'otp_pin_contents.')}

            # Additionally: in case of -cn the PIN must not contain "s" or "o"
            if pol['contents'][0] == "-":
                if (not policy_c and contains_c):
                    return {'success': False,
                            'error': _("The PIN contains letters, although it "
                                       "should not! (%s)") % pol['contents']}
                if (not policy_n and contains_n):
                    return {'success':  False,
                            'error': _("The PIN contains digits, although it "
                                       "should not! (%s)") % pol['contents']}
                if (not policy_s and contains_s):
                    return {'success': False,
                            'error': _("The PIN contains special characters, "
                                       "although it should not! "
                                       "(%s)") % pol['contents']}
                if (not policy_o and contains_other):
                    return {'success': False,
                            'error': _("The PIN contains other characters, "
                                       "although it should not! "
                                       "(%s)") % pol['contents']}

    return {'success': True,
            'error': ''}


def _getRandomPin(randomPINLength):
    newpin = ""

    log.debug("creating a random otp pin of length %r", randomPINLength)

    chars = letters + digits
    for _i in range(randomPINLength):
        newpin = newpin + urandom.choice(chars)

    return newpin


def checkToolsAuthorisation(method, param=None):
    # TODO: fix the semantic of the realm in the policy!

    auth_user = context['AuthUser']

    if not param:
        param = {}

    _checkToolsPolicyPre(method, param=param, authUser=auth_user, user=None)


def checkPolicyPre(controller, method, param=None, authUser=None, user=None):
    '''
    This function will check for all policy definition for a certain
    controller/method It is run directly before doing the action in the
    controller. I will raise an exception, if it fails.

    :param param: This is a dictionary with the necessary parameters.

    :return: dictionary with the necessary results. These depend on
             the controller.
    '''
    ret = {}
    _ = context["translate"]

    if not param:
        param = {}

    log.debug("entering controller %s", controller)
    log.debug("entering method %s", method)

    if controller == "admin":
        ret = _checkAdminPolicyPre(method=method, param=param,
                                   authUser=authUser, user=user)

    elif  controller == 'gettoken':
        ret = _checkGetTokenPolicyPre(method=method, param=param,
                                      authUser=authUser, user=user)
    elif controller == 'audit':
        ret = _checkAuditPolicyPre(method=method, param=param,
                                   authUser=authUser, user=user)

    elif controller == 'manage':
        ret = _checkManagePolicyPre(method=method, param=param,
                                    authUser=authUser, user=user)

    elif controller == 'tools':
        ret = _checkToolsPolicyPre(method=method, param=param,
                                   authUser=authUser, user=user)

    elif controller == 'selfservice':
        ret = _checkSelfservicePolicyPre(method=method, param=param,
                                         authUser=authUser, user=user)

    elif controller == 'system':
        ret = _checkSystemPolicyPre(method=method, param=param,
                                    authUser=authUser, user=user)

    elif controller == 'ocra':
        ret = _checkOcraPolicyPre(method=method, param=param,
                                  authUser=authUser, user=user)

    else:
        # unknown controller
        log.error("an unknown controller <<%r>> was passed.", controller)

        raise PolicyException(_("Failed to run getPolicyPre. Unknown "
                              "controller: %s") % controller)

    return ret


##############################################################################


def checkPolicyPost(controller, method, param=None, user=None):
    '''
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
    '''
    ret = {}
    _ = context['translate']

    if param is None:
        param = {}

    if controller == 'admin':
        ret = _checkAdminPolicyPost(method, param=param, user=user)

    elif controller == 'system':
        ret = _checkSystemPolicyPost(method, param=param, user=user)

    elif controller == 'selfservice':
        ret = _checkSelfservicePolicyPost(method, param=param, user=user)

    else:
        # unknown controller
        log.error("an unknown constroller <<%s>> was passed.", controller)

        raise PolicyException(_("Failed to run getPolicyPost. "
                              "Unknown controller: %s") % controller)

    return ret


###############################################################################
#
# Client Policies
#

def set_realm(login, realm, exception=False):
    '''
    this function reads the policy scope: authorization, client: x.y.z,
    action: setrealm=new_realm and overwrites the existing realm of the user
    with the new_realm.
    This can be used, if the client is not able to pass a realm and the users
    are not be located in the default realm.

    returns:
        realm    - name of the new realm taken from the policy
    '''

    client = _get_client()

    log.debug("got the client %s", client)
    log.debug("users %s original realm is %s", login, realm)

    policies = get_client_policy(client, scope="authorization",
                                 action="setrealm", realm=realm,
                                 user=login, find_resolver=False)

    if len(policies):
        realm = getPolicyActionValue(policies, "setrealm", is_string=True)

    log.debug("users %s new realm is %s", login, realm)
    return realm


def check_user_authorization(login, realm, exception=False):
    '''
    check if the given user/realm is in the given policy.
    The realm may contain the wildcard '*', then the policy holds for
    all realms. If no username or '*' is given, the policy holds for all users.

    attributes:
        login    - loginname of the user
        realm    - realm of the user
        exception    - wether it should return True/False or raise an Exception
    '''
    res = False
    client = _get_client()

    # if there is absolutely NO policy in scope authorization,
    # we return immediately
    if len(getPolicy({"scope": "authorization", "action": "authorize"})) == 0:
        log.debug("absolutely no authorization policy.")
        return True

    log.debug("got the client %s", client)

    policies = get_client_policy(client, scope="authorization",
                                 action="authorize", realm=realm, user=login)

    log.debug("got policies %s for user %s", policies, login)

    if len(policies):
        res = True

    if res is False and exception:
        raise AuthorizeException("Authorization on client %s failed "
                                 "for %s@%s." % (client, login, realm))

    return res


###############################################################################
#
#  Authentication stuff
#
def get_auth_passthru(user):
    '''
    returns True, if the user in this realm should be authenticated against
    the UserIdResolver in case the user has no tokens assigned.
    '''
    ret = False
    client = _get_client()

    pol = has_client_policy(client, scope="authentication",
                            action="passthru", realm=user.realm,
                            user=user.login, userObj=user)
    if len(pol) > 0:
        ret = True
    return ret


def get_auth_forward(user):
    '''
    returns the list of all forwarding servers
    '''
    client = _get_client()

    pol = has_client_policy(client, scope="authentication",
                            action="forward_server", realm=user.realm,
                            user=user.login, userObj=user)
    if not pol:
        return None

    servers = getPolicyActionValue(pol, "forward_server", is_string=True)

    return servers


def get_auth_passOnNoToken(user):
    '''
    returns True, if the user in this realm should be always authenticated
    in case the user has no tokens assigned.
    '''
    ret = False
    client = _get_client()

    pol = has_client_policy(client, scope="authentication",
                            action="passOnNoToken", realm=user.realm,
                            user=user.login, userObj=user)
    if len(pol) > 0:
        ret = True
    return ret


def disable_on_authentication_exceed(user, realms=None):
    '''
    returns True if the token should be disable, if max auth count is reached
    '''
    ret = False
    client = _get_client()

    if user.login:
        pol = get_client_policy(client, scope="authentication",
                                action="disable_on_authentication_exceed",
                                realm=user.realm,
                                user=user.login, userObj=user)
        if len(pol) > 0:
            return True
    else:
        for realm in realms:
            pol = get_client_policy(client, scope="authentication",
                                    action="disable_on_authentication_exceed",
                                    realm=realm)
            if len(pol) > 0:
                return True

    return False


def delete_on_authentication_exceed(user, realms=None):
    '''
    returns True if the token should be disable, if max auth count is reached
    '''

    client = _get_client()

    if user.login:
        pol = get_client_policy(client, scope="authentication",
                                action="delete_on_authentication_exceed",
                                realm=user.realm,
                                user=user.login, userObj=user)
        if len(pol) > 0:
            return True

    else:
        for realm in realms:
            pol = get_client_policy(client, scope="authentication",
                                    action="delete_on_authentication_exceed",
                                    realm=realm)
            if len(pol) > 0:
                return True

    return False



def trigger_sms(realms=None):
    """
    returns true, if a check_s should be allowed to trigger an sms
    """
    client = _get_client()
    user = _getUserFromParam()

    login = user.login
    if realms is None:
        realm = user.realm or _getDefaultRealm()
        realms = [realm]

    ret = False
    for realm in realms:
        pol = has_client_policy(client, scope="authentication",
                                action="trigger_sms", realm=realm,
                                user=login, userObj=user)

        if len(pol) > 0:
            log.debug("found policy in realm %s", realm)
            ret = True

    return ret


def get_auth_AutoSMSPolicy(realms=None):
    '''
    Returns true, if the autosms policy is set in one of the realms

    return:
        True or False

    input:
        list of realms
    '''
    log.debug("checking realms %r ", realms)
    client = _get_client()

    user = _getUserFromParam()
    login = user.login
    if realms is None:
        realm = user.realm or _getDefaultRealm()
        realms = [realm]

    ret = False
    for realm in realms:
        pol = has_client_policy(client, scope="authentication",
                                action="autosms", realm=realm,
                                user=login, userObj=user)

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

    if user is not None:
        p_user = user.login
        p_realm = user.realm

    client = _get_client()

    pol = get_client_policy(client, scope="authentication",
                            action="challenge_response",
                            realm=p_realm,
                            user=p_user, userObj=user)
    log.debug("got policy %r for user %r@%r from client %r",
              pol, p_user, p_realm, client)

    Token_Types = getPolicyActionValue(pol, "challenge_response",
                                       is_string=True)

    token_types = [t.lower() for t in Token_Types.split()]

    if ttype.lower() in token_types or '*' in token_types:

        log.debug("found matching token type %s", ttype)

        ret = True

    return ret


def _get_auth_PinPolicy(realm=None, user=None):
    '''
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
    '''

    #
    #    policy value mapping - from policy defintion:
    #        'value': [0, 1, 2, "token_pin", "password", "only_otp"],

    pin_policy_lookup = {
        "token_pin": 0,
        'password': 1,
        "only_otp": 2,
    }

    log.debug("[get_auth_PinPolicy]")
    client = _get_client()

    if user is None:
        user = _getUserFromParam()
    login = user.login
    if realm is None:
        realm = user.realm or _getDefaultRealm()

    pol = get_client_policy(client, scope="authentication", action="otppin",
                            realm=realm, user=login, userObj=user)

    log.debug("got policy %s for user %s@%s  client %s",
              pol, login, realm, client)

    pin_check = getPolicyActionValue(pol, "otppin", max=False)

    # we map the named values back, to provide interface compatibility
    if pin_check in pin_policy_lookup:
        pin_check = pin_policy_lookup[pin_check]

    return pin_check


def get_qrtan_url(realms):
    '''
    Returns the URL for the half automatic mode for the QR TAN token
    for the given realm

    :remark: there might be more than one url, if the token
             belongs to more than one realm

    :param realms: list of realms or None

    :return: url string

    '''
    log.debug("getting qrtan callback url ")
    url = ''
    urls = []

    if realms is None:
        realms = []

    for realm in realms:
        pol = getPolicy({"scope": "authentication", 'realm': realm,
                         'action': "qrtanurl"})
        url = getPolicyActionValue(pol, "qrtanurl", is_string=True)
        if url:
            urls.append(url)

    if len(urls) > 1:
        raise Exception('multiple enrollement urls %r found for realm set: %r'
                        % (urls, realms))

    log.debug("got callback url %s for realms %r", url, realms)

    return url


###############################################################################
#
#  Authorization
#
def check_auth_tokentype(serial, exception=False, user=None):
    '''
    Checks if the token type of the given serial matches the tokentype policy

    :return: True/False - returns true or false or raises an exception
                          if exception=True
    '''

    _ = context['translate']

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

    pol = get_client_policy(client, scope="authorization", action="tokentype",
                            realm=realm, user=login, userObj=user)

    log.debug("got policy %s for user %s@%s  client %s",
              pol, login, realm, client)

    t_type = getPolicyActionValue(pol, "tokentype", max=False, is_string=True)
    if len(t_type) > 0:
        tokentypes = [t.strip() for t in t_type.lower().split(" ")]

    log.debug("found these tokentypes: <%s>", tokentypes)

    toks = linotp.lib.token.getTokens4UserOrSerial(None, serial)
    if len(toks) > 1:

        log.error("multiple tokens with serial %s found"
                  " - cannot get OTP!", serial)

        raise PolicyException(_("multiple tokens found - "
                              "cannot determine tokentype!"))

    elif len(toks) == 1:

        log.debug("found one token with serial %s", serial)
        tokentype = toks[0].getType().lower()

        log.debug("got the type %s for token %s", tokentype, serial)

        if (tokentype in tokentypes or '*' in tokentypes or
           len(tokentypes) == 0):
            res = True
    elif len(toks) == 0:
        # TODO if the user does not exist or does have no token
        # ---- WHAT DO WE DO? ---
        #  At the moment we pass through: This is the old behaviour...
        res = True

    if res is False and exception:

        context['audit']["action_detail"] = ("failed due to "
                                             "authorization/tokentype policy")

        raise AuthorizeException("Authorization for token %s with type %s "
                                 "failed on client %s" % (serial, tokentype,
                                                          client))

    return res


def check_auth_serial(serial, exception=False, user=None):
    '''
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
    '''

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

    pol = has_client_policy(client, scope="authorization", action="serial",
                            realm=realm, user=login, userObj=user)
    if len(pol) == 0:
        # No policy found, so we skip the rest
        log.debug("No policy scope=authorize, action=serial for user %r, "
                  "realm %r, client %r", login, realm, client)
        return True

    log.debug("got policy %s for user %s@%s  client %s",
              pol, login, realm, client)

    # extract the value from the policy
    serial_regexp = getPolicyActionValue(pol, "serial",
                                         max=False, is_string=True)

    log.debug("found this regexp /%r/ for the serial %r",
              serial_regexp, serial)

    if re.search(serial_regexp, serial):
        log.debug("regexp matches.")
        res = True

    if res is False and exception:
        context['audit']["action_detail"] = ("failed due to authorization/"
                                            "serial policy")
        raise AuthorizeException("Authorization for token %s failed on "
                                 "client %s" % (serial, client))

    return res


def is_auth_return(success=True, user=None):
    '''
    returns True if the policy
        scope = authorization
        action = detail_on_success/detail_on_fail
        is set.

    :param success: Defines if we should check of the policy
                    detaul_on_success (True) or detail_on_fail (False)
    :type success: bool
    '''
    ret = False

    client = _get_client()

    if user is None:
        user = _getUserFromParam()

    login = user.login
    realm = user.realm or _getDefaultRealm()
    if success:
        pol = has_client_policy(client, scope="authorization",
                                action="detail_on_success", realm=realm,
                                user=login, userObj=user)
    else:
        pol = has_client_policy(client, scope="authorization",
                                action="detail_on_fail", realm=realm,
                                user=login, userObj=user)

    if len(pol):
        ret = True

    return ret


# helper ################################
def get_pin_policies(user):
    '''
    lookup for the pin policies - the list of policies
    is preserved for repeated lookups

    : raises: exception, if more then one pin policies are matching

    :param user: the policies which are applicable to the user
    :return: list of otppin id's
    '''
    pin_policies = []

    pin_policies.append(_get_auth_PinPolicy(user=user))
    pin_policies = list(set(pin_policies))

    if len(pin_policies) > 1:
        msg = ("conflicting authentication polices. "
               "Check scope=authentication. policies: %r" % pin_policies)

        log.error("[__checkToken] %r", msg)
        raise Exception('multiple pin policies found')

    return pin_policies


def check_token_reporting(realm):
    """
    parse reporting policies for given realm and user
    :param realm: the realm to be reported
    :return: list of status like [assigned, active&unassigned, total]
    """

    if not realm:
        realm = None

    report_policies = getPolicy({'scope': 'reporting', 'realm': realm})
    actions = []

    for polname, policy in report_policies.items():
        action = policy.get('action', '')
        action = str(action)
        action = action.split(',')
        for act in action:
            if 'token_total' in act:
                actions.append('total')
            if 'token_status' in act:
                status = act.split('=')
                actions.append(status[1])
            if act is '*':
                status = ['active', 'inactive', 'assigned', 'unassigned',
                          'active&assigned', 'active&unassigned',
                          'inactive&assigned', 'inactive&unassigned', 'total']
                for stat in status:
                    actions.append(unicode(stat))
    return actions


def supports_offline(realms, token):

    """
    Check if offline is allowed for the given token.

    :param realms: the realms to be checked
    :param token: the token to be checked

    :returns bool
    """

    if realms is None or len(realms) == 0:
        realms = ['/:no realm:/']

    for realm in realms:
        policy = getPolicy({"scope": "authentication", 'realm': realm,
                            'action': 'support_offline'})
        action_value = getPolicyActionValue(policy, 'support_offline',
                                            is_string=True)
        if action_value:
            token_types = action_value.split()
            if token.getType() in token_types:
                return True

    return False


def get_partition(realms, user):
    """
    returns the partition (key pair identifier) that should be used
    """
    action_values = []
    login = None
    ret = 0

    if realms is None or len(realms) == 0:
        realms = ['/:no realm:/']

    action = 'partition'

    params = {'scope': 'enrollment',
              'action': action}

    for realm in realms:
        params['realm'] = realm
        if login:
            params['user'] = login

        policy = getPolicy(params)
        action_value = getPolicyActionValue(policy, action,
                                            is_string=True)
        if action_value:
            action_values.append(action_value)

    if len(action_values) > 1:
        for value in action_values:
            if value != action_values[0]:
                raise Exception('conflicting policy values %r found for '
                                'realm set: %r' % (action_values, realms))
    if action_values:
        ret = int(action_values[0])

    return ret


def get_single_auth_policy(policy_name, user=None, realms=None):
    """
    Retrieves a policy value and checks if the value is consistent
    across realms.

    :param policy_name: the name of the policy, e.g:
        * qrtoken_pairing_callback_url
        * qrtoken_pairing_callback_sms
        * qrtoken_challenge_response_url
        * qrtoken_challenge_response_sms

    :param realms: the realms that his policy should be effective in
    """

    action_values = []
    login = None
    ret = None

    if user and user.login and user.realm:
        realms = [user.realm]
        login = user.login

    if realms is None or len(realms) == 0:
        realms = ['/:no realm:/']

    params = {"scope": "authentication",
              'action': policy_name}

    for realm in realms:
        params['realm'] = realm
        if login:
            params['user'] = login

        policy = getPolicy(params)
        action_value = getPolicyActionValue(policy, policy_name,
                                            is_string=True)
        if action_value:
            action_values.append(action_value)

    if len(action_values) > 1:
        for value in action_values:
            if value != action_values[0]:
                raise Exception('conflicting policy values %r found for '
                                'realm set: %r' % (action_values, realms))
    if action_values:
        ret = action_values[0]

    return ret
# eof ##########################################################################

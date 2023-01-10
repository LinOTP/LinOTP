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
""" maxtoken policy processing """

import logging

from flask_babel import gettext as _

import linotp
from linotp.lib.context import request_context as context
from linotp.lib.policy.action import get_action_value
from linotp.lib.policy.processing import get_client_policy
from linotp.lib.policy.util import _get_client, _getUserRealms

# Define the map for the maxtoken policy lookup
#   in selfservice/webprovision the provided token type parameter
#   will be mapped to either hmac or totp

WebprovisionTokenTypesMap = {
    "oathtoken": "hmac",
    "googleauthenticator": "hmac",
    "googleauthenticator_time": "totp",
}

log = logging.getLogger(__name__)


def check_maxtoken(method, user, param):
    """
    maxtoken policy restricts the tokennumber for the user in a realm

    :param method: scope of the controller actions
    :param user: the user to whom the new token should belong
    :param param: the calling parameters, which contains either
                   'serial' for assignment or 'type' for enrollment

    :raises PolicyException: if maxtoken policy would be violated
    """

    enroll_methods = ["init", "enroll", "userwebprovision", "userinit"]
    assign_methods = ["userassign", "assign"]

    if method in enroll_methods + assign_methods:

        log.debug("checking maxtokens for user")

        check_maxtoken_for_user(user)

    if method in enroll_methods:

        log.debug("checking maxtokens of user by token type")

        type_of_token = param.get("type", "hmac")
        type_of_token = WebprovisionTokenTypesMap.get(
            type_of_token, type_of_token
        )
        check_maxtoken_for_user_by_type(user, type_of_token=type_of_token)

    elif method in assign_methods:

        log.debug("checking maxtokens of user by serial number")

        tokens = linotp.lib.token.get_tokens(serial=param["serial"])
        for token in tokens:
            type_of_token = token.type.lower()
            check_maxtoken_for_user_by_type(user, type_of_token=type_of_token)


def check_maxtoken_for_user(user):
    """
    This internal function checks the number of assigned tokens to a user
    restricted by the policies:

        "scope = enrollment", action = "maxtoken = <number>"

    :param user: to whom the token should belong
    :raises PolicyException: if maxtoken policy would be violated
    """

    if not user or not user.login:
        return

    client = _get_client()

    user_realms = _getUserRealms(user)

    log.debug(
        "checking the already assigned tokens for user %r, realms %s",
        user,
        user_realms,
    )

    # ----------------------------------------------------------------------- --

    # check the maxtoken policy

    action = "maxtoken"
    tokens = linotp.lib.token.get_tokens(user, "")

    for user_realm in user_realms:

        policies = get_client_policy(
            client,
            scope="enrollment",
            action=action,
            realm=user_realm,
            user=user.login,
            userObj=user,
        )

        if not policies:
            continue

        total_maxtoken = get_action_value(
            policies, scope="enrollment", action=action, default=-1
        )

        if total_maxtoken == -1 or isinstance(total_maxtoken, bool):
            continue

        if len(tokens) + 1 > total_maxtoken:

            error_msg = _(
                "The maximum number of allowed tokens "
                "per user is exceeded. Check the "
                "policies scope=enrollment, "
                "action=maxtoken"
            )

            raise linotp.lib.policy.MaxTokenUserPolicyException(error_msg)


def check_maxtoken_for_user_by_type(user, type_of_token):
    """
    This internal function checks the number of assigned tokens to a user
    restricted by the policies:

        "scope = enrollment", action = "maxtokenTOKENTYPE = <number>"

    :param user: to whom the token should belong
    :param type_of_token: which type of token should be enrolled or assigned
    :raises PolicyException: if maxtoken policy would be violated
    """

    if not user or not user.login:
        return

    client = _get_client()

    user_realms = _getUserRealms(user)

    log.debug(
        "checking the already assigned tokens for user %r, realms %s",
        user,
        user_realms,
    )

    # ------------------------------------------------------------------ --

    # check the maxtokenTOKENTYPE policy

    typed_tokens = linotp.lib.token.get_tokens(user, token_type=type_of_token)

    action = "maxtoken%s" % type_of_token.upper()

    for user_realm in user_realms:

        policies = get_client_policy(
            client,
            scope="enrollment",
            action=action,
            realm=user_realm,
            user=user.login,
            userObj=user,
        )

        if not policies:
            continue

        # compare the tokens of the user with the max numbers of the policy

        total_maxtoken = get_action_value(
            policies, scope="enrollment", action=action, default=-1
        )

        if total_maxtoken == -1 or isinstance(total_maxtoken, bool):
            continue

        if len(typed_tokens) + 1 > total_maxtoken:

            error_msg = _(
                "The maximum number of allowed tokens of type %s "
                "per user is exceeded. Check the policies "
                "scope=enrollment, action=maxtoken%s"
                % (type_of_token, type_of_token.upper())
            )

            raise linotp.lib.policy.MaxTokenTypeUserPolicyException(error_msg)

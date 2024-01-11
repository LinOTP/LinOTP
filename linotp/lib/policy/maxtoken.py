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
from typing import Any, Dict, List, Union

from flask_babel import gettext as _

import linotp
from linotp.lib.context import request_context as context
from linotp.lib.policy.action import get_action_value
from linotp.lib.policy.processing import get_client_policy
from linotp.lib.policy.util import _get_client, _getUserRealms
from linotp.lib.user import User

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


def check_maxtoken_for_user(user: User):
    """
    This internal function checks the number of assigned tokens to a user
    restricted by the policies:

        "scope = enrollment", action = "maxtoken = <number>"

    :param user: to whom the token should belong
    :raises PolicyException: if maxtoken policy would be violated
    """

    if not user or not user.login:
        return

    log.debug(
        "checking the already assigned tokens for user %r",
        user,
    )

    token_limit = get_maxtoken_for_user(user)
    if token_limit is None:
        return
    tokens: List[Any] = linotp.lib.token.get_tokens(user, "")  # type: ignore
    token_count = len(tokens)

    # check the maxtoken policy
    if token_count + 1 > token_limit:
        error_msg = _(
            "The maximum number of allowed tokens "
            "per user is exceeded. Check the "
            "policies scope=enrollment, "
            "action=maxtoken"
        )

        raise linotp.lib.policy.MaxTokenUserPolicyException(error_msg)


def get_maxtoken_for_user(user: User) -> Union[int, None]:
    """
    This function returns maximum number of tokens
    allowed for a user if maxtoken policy is set or None
    """

    if not user or not user.login:
        return

    client: str = _get_client()
    user_realms: List[str] = _getUserRealms(user)

    log.debug(
        "getting the already assigned tokens for user %r, realms %s",
        user,
        user_realms,
    )

    action = "maxtoken"
    maxtoken_limits: List[Union[int, bool]] = _get_maxtoken_pro_realm(
        user_realms, user, action, client
    )

    result = calculate_token_limit(maxtoken_limits)
    return result


def check_maxtoken_for_user_by_type(user: User, type_of_token: str):
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

    log.debug("checking the already assigned tokens for user %r", user)

    token_limit = get_maxtoken_for_user_by_type(user, type_of_token)
    if token_limit is None:
        return

    tokens: List[Any] = linotp.lib.token.get_tokens(user, token_type=type_of_token)  # type: ignore
    token_count = len(tokens)

    if token_count + 1 > token_limit:
        error_msg = _(
            "The maximum number of allowed tokens of type %s "
            "per user is exceeded. Check the policies "
            "scope=enrollment, action=maxtoken%s"
            % (type_of_token, type_of_token.upper())
        )

        raise linotp.lib.policy.MaxTokenTypeUserPolicyException(error_msg)


def get_maxtoken_for_user_by_type(
    user: User, type_of_token: str
) -> Union[int, None]:
    """
    This function returns maximum number of tokens of a specific type
    allowed for a user if maxtoken policy is set or None
    """
    if not user or not user.login:
        return

    client: str = _get_client()  # type: ignore
    user_realms: List[str] = _getUserRealms(user)

    log.debug(
        "getting the already assigned tokens for user %r, realms %s",
        user,
        user_realms,
    )

    action = "maxtoken%s" % type_of_token.upper()
    maxtoken_limits: List[Union[int, bool]] = _get_maxtoken_pro_realm(
        user_realms, user, action, client
    )

    result = calculate_token_limit(maxtoken_limits)  # type: ignore
    return result


def calculate_token_limit(
    limit_info: List[Union[int, bool]]
) -> Union[int, None]:
    """
    This function encapsulates the logic to calculate the token limit
    """
    maxtoken_limits: List[int] = []

    for limit in limit_info:
        if limit == -1 or isinstance(limit, bool):
            continue
        maxtoken_limits.append(limit)

    result = min(maxtoken_limits, default=None)

    return result


def _get_maxtoken_pro_realm(
    user_realms: List[str], user: User, action: str, client: str
) -> List[int]:
    """
    This private function abstracts reusable part of the logic
    from "get_maxtoken" functions
    """
    maxtoken_limits: List[int] = []

    for user_realm in user_realms:
        policies: Dict[str, Any] = get_client_policy(
            client,
            scope="enrollment",
            action=action,
            realm=user_realm,
            user=user.login,
            userObj=user,
        )

        maxtoken_realm = get_action_value(
            policies, scope="enrollment", action=action, default=-1
        )

        maxtoken_limits.append(maxtoken_realm)

    return maxtoken_limits

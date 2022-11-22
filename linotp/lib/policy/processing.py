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
""" policy processing functions

    currently the external interfaces
    - has_client_policy
    - get_client_policy
    - search_policy

    are migration wrappers, which trigger both, the legacy policy and the
    new policy processing to support the direct comparison of the results.

    When the evaluation of the new policy engine is completed the methods
    starting with new_ could be moved in place
"""

import logging
from typing import Any, Tuple

from linotp.lib.policy.evaluate import PolicyEvaluator
from linotp.lib.policy.util import get_policies
from linotp.lib.user import User

LOG = logging.getLogger(__name__)


def search_policy(param, only_active=True):
    """
    Function to retrieve the list of policies.

    attributes:

    - name:   (optional) will only return the policy with the name
    - user:   (optional) will only return the policies for this user
    - realm:  (optional) will only return the policies of this realm
    - scope:  (optional) will only return the policies within this scope
    - action: (optional) will only return the policies with this action
         The action can also be something like "otppin" and will
         return policies containing "otppin = 2"

    :return: a dictionary with the policies. The name of the policy being
             the key
    """

    #
    # filter the policies with the new engine

    policy_elve = PolicyEvaluator(get_policies())

    #
    # install the filters

    policy_elve.set_filters(params=param)

    #
    # add the special filter for activ or inactive policies

    if only_active:
        policy_elve.filter_for_active(state=True)

    #
    # finally we apply the filter

    new_pols = policy_elve.evaluate()

    return new_pols


def getPolicy(param, only_active=True):
    """
    Function to retrieve the list of policies.

    attributes:

    - name:   (optional) will only return the policy with the name
    - user:   (optional) will only return the policies for this user
    - realm:  (optional) will only return the policies of this realm
    - scope:  (optional) will only return the policies within this scope
    - action: (optional) will only return the policies with this action
         The action can also be something like "otppin" and will
         return policies containing "otppin = 2"

    :return: a dictionary with the policies. The name of the policy being
             the key
    """

    #
    # filter the policies with the new engine

    policy_elve = PolicyEvaluator(get_policies())

    #
    # install the filters

    policy_elve.set_filters(params=param)

    #
    # add the special filter for activ or inactive policies

    if only_active:
        policy_elve.filter_for_active(state=True)

    if ("user" in param and param["user"] is not None) or (
        "action" in param and param["action"] is not None
    ):
        policy_elve.filter_for_time()

    #
    # finally we apply the filter

    new_pols = policy_elve.evaluate()

    return new_pols


def is_authorized(admin_user: User, scope: str, action: str) -> bool:
    """
    This internally used function checks whether the currently authenticated
    administrative user is authorized to perform an action in the given scope.

    This method can only be used for administrative users and therefore does
    not take REALMS into account!

    :param admin_user: the admin user to check
    :param scope: policy scope to use (system, audit, monitoring, reporting, tools)
    :param action: action to check in the scope (e.g. read or write)

    returns:
        authenticated : `boolean`
            boolean value whether user is authorized
    """

    policy_eval = PolicyEvaluator(get_policies())

    LOG.debug("Evaluating policies for the user: %r", admin_user)

    scope_policies = policy_eval.has_policy(
        {
            "scope": scope,
            "active": True,
        }
    )

    # if no policy was defined at all -> the access is not restricted
    if len(scope_policies) == 0:

        LOG.info(
            "No active policies in scope %s found - access to this scope is"
            " not restricted!",
            scope,
        )
        return True

    # if any policy is defined, check if the admin_user is allowed to execute
    # the given action by an active policy

    filters = {
        "user": admin_user,
        "scope": scope,
        "action": action,
    }
    policies = policy_eval.set_filters(filters).evaluate(scope_policies)

    LOG.debug("Found the following policies: %r", policies)

    return len(policies) > 0


def get_client_policy(
    client,
    scope=None,
    action=None,
    realm=None,
    user=None,
    find_resolver=True,
    userObj=None,
    active_only=True,
):
    """
    This function returns the dictionary of policies for the given client.

    1. First it searches for all policies matching (scope, action, realm) and
    checks, whether the given client is contained in the policy field client.
    If no policy for the given client is found it takes the policy without
    a client

    2. Then it strips down the returnable policies to those, that only contain
    the username - UNLESS - none of the above policies contains a username

    3. then we try to find resolvers in the username (OPTIONAL)

    4. if nothing matched so far, we try the extended policy check

    """

    policy_eval = PolicyEvaluator(get_policies())

    if realm:
        policy_eval.filter_for_realm(realm)

    if scope:
        policy_eval.filter_for_scope(scope)

    if action:
        policy_eval.filter_for_action(action)

    if client:
        policy_eval.filter_for_client(client)

    policy_eval.filter_for_time()

    if active_only:
        policy_eval.filter_for_active(state=True)

    if userObj:
        policy_eval.filter_for_user(userObj)
    elif user:
        policy_eval.filter_for_user(user)

    policies = policy_eval.evaluate()

    return policies


def has_client_policy(
    client,
    scope=None,
    action=None,
    realm=None,
    user=None,
    find_resolver=True,
    userObj=None,
    active_only=True,
):
    """
    This function returns the dictionary of policies for the given client.

    1. First it searches for all policies matching (scope, action, realm) and
    checks, whether the given client is contained in the policy field client.
    If no policy for the given client is found it takes the policy without
    a client

    2. Then it strips down the returnable policies to those, that only contain
    the username - UNLESS - none of the above policies contains a username

    3. then we try to find resolvers in the username (OPTIONAL)

    4. if nothing matched so far, we try the extended policy check

    The difference to the get_policy is, that it restores the already installed
    filters for an existance check

    """

    policy_eval = PolicyEvaluator(get_policies())

    param = {}

    if realm:
        param["realm"] = realm

    if scope:
        param["scope"] = scope

    if action:
        param["action"] = action

    if active_only:
        policy_eval.filter_for_active(state=True)

    if client:
        param["client"] = client

    if userObj:
        param["user"] = userObj
    elif user:
        param["user"] = user

    policies = policy_eval.has_policy(param)

    return policies


# eof

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

from linotp.lib.policy.evaluate import PolicyEvaluator
from linotp.lib.policy.util import _getAuthenticatedUser, get_policies

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


def _getAuthorization(scope, action):
    """
    This internal function returns the Authrorizaition within some
    the scope=system(or audit, monitoring, tools). for the currently
    authenticated administrativ user.

    This does not take into account the REALMS!

    arguments:
        action  - this is the action
                    scope = system/audit/monitoring/tools
                        read
                        write

    returns:
        a dictionary with the following keys:
        active     (if policies are used)
        admin      (the name of the authenticated admin user)
        auth       (True if admin is authorized for this action)
    """
    active = True
    auth = False

    policy_elve = PolicyEvaluator(get_policies())

    p_at_all = policy_elve.has_policy({"scope": scope})

    if len(p_at_all) == 0:
        LOG.info(
            "No policies in scope %s found. Checking "
            "of scope %s be disabled.",
            scope,
            scope,
        )
        active = False
        auth = True

    # TODO: We may change this later to other authentication schemes
    LOG.debug("[getAuthorization] now getting the admin user name")

    admin_user = _getAuthenticatedUser()

    LOG.debug("Evaluating policies for the user: %s", admin_user["login"])

    param = {"user": admin_user["login"], "scope": scope, "action": action}

    policies = policy_elve.set_filters(param).evaluate(policy_set=p_at_all)
    LOG.debug("Found the following policies: %r", policies)

    if len(list(policies.keys())) > 0:
        auth = True

    return {"active": active, "auth": auth, "admin": admin_user["login"]}


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

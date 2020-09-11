# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2020 arxes-tolina GmbH
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
"""policy action processing"""

import logging

from .processing import get_client_policy

from .util import _get_client
from .util import parse_action_value

log = logging.getLogger(__name__)

def get_selfservice_actions(user, action=None):
    '''
    This function returns the allowed actions in the self service portal
    for the given user

    if there was an action as parameter, we copy only this one
    into the result set

    '''
    login = user.login
    realm = user.realm
    client = _get_client()

    log.debug("checking actions for scope=selfservice, realm=%r", realm)

    policies = get_client_policy(
        client, scope="selfservice", action=action,
        realm=realm, user=login, userObj=user)

    if not policies:
        return {}

    all_actions = {}
    for policy in policies.values():
        actions = parse_action_value(policy.get('action', {}))

        if not action:
            all_actions.update(actions)
        elif action in actions:
            all_actions[action] = actions[action]

    return all_actions

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

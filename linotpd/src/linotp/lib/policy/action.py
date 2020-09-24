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

from warnings import warn
from typing import Dict, Any

from .processing import get_client_policy

from .util import _get_client
from .util import parse_action_value

from .definitions import get_policy_definitions

log = logging.getLogger(__name__)

def get_selfservice_actions(user, action=None):
    '''
    This function returns the allowed actions in the self service portal
    for the given user

    if there was an action as parameter, we copy only this one
    into the result set

    action value will be type converted according to the policy definition

    :return: dictionary with all actions
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

    scope="selfservice"
    pat = PolicyActionTyping()

    all_actions = {}
    for policy in policies.values():
        actions = parse_action_value(policy.get('action', {}))
        if not action:
            all_actions.update(pat.convert_actions(scope, actions))
        elif action in actions:
            all_actions[action] = pat.convert(scope, action, actions[action])

    return all_actions

def get_action_value(policies:Dict, scope:str, action:str,
                     subkey:str=None, default:Any=None) -> Any:
    """Get the value of an action from a set of policies

    :param policies: a dict of policies
    :param scope: the scope of the policy - required for the typing support
    :param action: the name of the searched action
    :param subkey: special feature to support action names with sub keys
    :param default: the default return if nothing is found
    :return: the (typed) action value or default
    """

    if not policies:
        return default

    pat = PolicyActionTyping()

    if subkey:
        action = "%s.%s" % (action, subkey)

    all_actions = {}
    for policy in policies.values():
        actions = parse_action_value(policy.get('action', {}))

        if action in actions:
            current = all_actions.setdefault(action, [])
            current.append(pat.convert(scope, action, actions[action]))
            all_actions[action] = current

    if action not in all_actions:
        return default

    if len(set(all_actions[action])) > 1:
        log.warning('contradicting action values found for action %s:%s: %r',
                    scope, action, all_actions[action])

    return all_actions[action][0]


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

class PolicyActionTyping():
    """Convert the action value according to the policy definition.
    """

    def __init__(self):
        """Helper class for the policy typing.
        """
        self.definitions = get_policy_definitions()

    def convert(self, scope:str, action_name:str, action_value:str) -> Any:
        """Convert the action values acording to the policy definitions.

        :paran scope: of the action
        :param action_name: the name of the action
        :param action_value: the un parsed action value
        :return: the typed value
        """

        if action_name not in self.definitions[scope]:
            return action_value

        typing = self.definitions[scope][action_name].get('type')

        if typing is None:
            return action_value

        elif typing == 'bool':

            if action_value in [True, False]:
                return action_value

            msg = ("%s:%s : action value %r is not compliant with "
                   "action type 'bool'" % (scope, action_name, action_value))
            warn(msg,DeprecationWarning)

            if action_value in [-1, '-1']:
                return False

            if isinstance(action_value, int):
                return action_value > 0

            if isinstance(action_value, str):

                if action_value.lower() == 'true':
                    return True

                if action_value.lower() == 'false':
                    return False

                if action_value.isdigit():
                    return int(action_value) > 0

                return False

            return bool(action_value)

        elif typing == 'int':
            return int(action_value)

        elif typing in ['str', 'string']:
            return str(action_value)

        elif typing == 'set':
            # in case of a set, we try our best:
            # if int() else return as is
            if isinstance(action_value, str) and action_value.isdigit():
                return int(action_value)

        return action_value

    def convert_actions(self, scope:str, actions:Dict) -> Dict:
        """type conversion of an action dict.

        utility to be used in the by functions like get_selfservice_actions
        to make the code better readable

        :param scope: the scope of the action in the policy definition
        :param actions: dict with actions
        :return: dict with all action and their converted values
        """
        all_actions = {}
        for action_name, action_value in actions.items():
            action_value = self.convert(scope, action_name, action_value)
            all_actions[action_name] = action_value
        return all_actions

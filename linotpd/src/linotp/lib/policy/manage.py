# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
""" static policy definitions """

import re
import logging

from copy import deepcopy
from configobj import ConfigObj

from linotp.lib.config import getLinotpConfig
from linotp.lib.config import removeFromConfig
from linotp.lib.config import storeConfig

from linotp.lib.policy import getPolicies

from linotp.lib.error import ServerError
from linotp.lib.context import request_context as context
from linotp.lib.policy.forward import ForwardServerPolicy

class PolicyWarning(Exception):
    pass

log = logging.getLogger(__name__)


def setPolicy(param):
    '''
    Function to set a policy. It expects a dict of with the following keys:

      * name
      * action
      * scope
      * realm
      * user
      * time
      * client
    '''
    ret = {}

    name = param.get('name')
    action = param.get('action')
    scope = param.get('scope')
    realm = param.get('realm')
    user = param.get('user')
    time = param.get('time')
    client = param.get('client')
    active = param.get('active', "True")

    # before storing the policy, we have to check the impact:
    # if there is a problem, we will raise an exception with a warning
    if context and 'Policies' in context:
        policies = context['Policies']
    else:
        policies = getPolicies()

    _check_policy_impact(policies=policies, **param)

    action = ForwardServerPolicy.prepare_forward(action)

    ret["action"] = storeConfig("Policy.%s.action" % name,
                                action, "", "a policy definition")
    ret["scope"] = storeConfig("Policy.%s.scope" % name,
                               scope, "", "a policy definition")
    ret["realm"] = storeConfig("Policy.%s.realm" % name,
                               realm, "", "a policy definition")
    ret["user"] = storeConfig("Policy.%s.user" % name,
                              user, "", "a policy definition")
    ret["time"] = storeConfig("Policy.%s.time" % name,
                              time, "", "a policy definition")
    ret["client"] = storeConfig("Policy.%s.client" % name,
                                client, "", "a policy definition")
    ret["active"] = storeConfig("Policy.%s.active" % name,
                                active, "", "a policy definition")

    return ret


def deletePolicy(name, enforce=False):
    '''
    Function to delete one named policy

    attributes:
        name:   (required) will only return the policy with the name
    '''
    res = {}
    if not re.match('^[a-zA-Z0-9_]*$', name):
        raise ServerError("policy name may only contain the "
                          "characters a-zA-Z0-9_", id=8888)

    if context and 'Config' in context:
        Config = context['Config']
    else:
        Config = getLinotpConfig()

    if context and 'Policies' in context:
        policies = context['Policies']
    else:
        policies = getPolicies()

    # check if due to delete of the policy a lockout could happen
    param = policies.get(name)
    # delete is same as inactive ;-)
    if param:
        param['active'] = "False"
        param['name'] = name
        param['enforce'] = enforce
        _check_policy_impact(policies=policies, **param)

    delEntries = []
    for entry in Config:
        if entry.startswith("linotp.Policy.%s." % name):
            delEntries.append(entry)

    for entry in delEntries:
        # delete this entry.
        log.debug("[deletePolicy] removing key: %s" % entry)
        ret = removeFromConfig(entry)
        res[entry] = ret

    return res


def _check_policy_impact(policies=None, scope='', action='', active='True',
                         client='', realm='', time=None, user=None, name='',
                         enforce=False):
    """
    check if applying the policy will lock the user out
    """

    # Currently only system policies are checked
    if scope.lower() not in ['system']:
        return

    reason = ''
    no_system_write_policy = True
    active_system_policy = False

    pol = {'scope': scope,
           'action': action,
           'active': active,
           'client': client,
           'realm': realm,
           'user': user,
           'time': time
           }

    if not policies:
        policies = getPolicies()

    # in case of a policy change exclude this one from comparison
    if name in policies:
        del policies[name]

    # add the new policy and check the constrains
    policies[name] = pol

    for policy in policies.values():

        # do we have a system policy that is active?
        p_scope = policy['scope'].lower()
        p_active = policy['active'].lower()

        if p_scope == 'system' and p_active == 'true':
            active_system_policy = True

            # get the policy actions
            p_actions = []
            for act in policy.get('action', '').split(','):
                p_actions.append(act.strip())

            # check if there is a write in the actions
            if '*' in p_actions or 'write' in p_actions:
                no_system_write_policy = False
                break

    # for any system policy:
    # if no user is defined defined this can as well result in a lockout
    if not user.strip():
        reason = "no user defined for system policy %s!" % name
    # same for empty realm
    if not realm.strip():
        reason = "no realm defined for system policy %s!" % name

    # if there has been no system policy with write option
    # and there are active system policy left
    if no_system_write_policy and active_system_policy:
        reason = "no active system policy with 'write' permission defined!"

    if reason and enforce is False:
        raise PolicyWarning("Warning: potential lockout due to policy "
                "defintion: %s" % reason)

    # admin policy could as well result in lockout
    return


def create_policy_export_file(policy, filename):
    '''
    This function takes a policy dictionary and creates an export file from it
    '''
    TMP_DIRECTORY = "/tmp"
    filename = "%s/%s" % (TMP_DIRECTORY, filename)
    if len(policy) == 0:
        f = open(filename, "w")
        f.write('')
        f.close()
    else:
        for value in policy.values():
            for k in value.keys():
                value[k] = value[k] or ""

        policy_file = ConfigObj(encoding="UTF-8")
        policy_file.filename = filename

        for name in policy.keys():
            policy_file[name] = policy[name]
            policy_file.write()

    return filename

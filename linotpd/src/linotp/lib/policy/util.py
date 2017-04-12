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
""" policy processing utilities """

import logging
from copy import deepcopy

from linotp.lib.context import request_context as context
from linotp.lib.user import getUserRealms

LOG = logging.getLogger(__name__)

lowercase = 'abcdefghijklmnopqrstuvwxyz'
uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
letters = lowercase + uppercase
ascii_lowercase = lowercase
ascii_uppercase = uppercase
ascii_letters = ascii_lowercase + ascii_uppercase
digits = '0123456789'


def _getUserRealms(user):
    return getUserRealms(user,
                         allRealms=context['Realms'],
                         defaultRealm=context['defaultRealm'])


def _get_pin_values(config):
    REG_POLICY_C = config.get("linotpPolicy.pin_c", "[a-zA-Z]")
    REG_POLICY_N = config.get("linotpPolicy.pin_n", "[0-9]")
    REG_POLICY_S = config.get("linotpPolicy.pin_s",
                              "[.:,;-_<>+*!/()=?$§%&#~\^]")

    return REG_POLICY_C, REG_POLICY_N, REG_POLICY_S


def _getAuthenticatedUser():
    """
    replace the 'getUserFromRequest
    """
    auth_user = context['AuthUser']
    return auth_user


def _getLinotpConfig(config=None):

    lConfig = config
    return lConfig


def get_policies():
    return context['Policies']


def get_copy_of_policies():
    lPolicies = deepcopy(context['Policies'])
    return lPolicies


def _get_client():
    client = context['Client']
    return client


def _getUserFromParam():
    user = context['RequestUser']
    return user


def _getDefaultRealm():
    return context['defaultRealm']


def _getRealms():
    return context['Realms']


def are_the_same(dict1, dict2):
    if not dict1 and not dict2:
        return True

    if dict1 and not dict2:
        return False

    if not dict1 and dict2:
        return False

    if len(dict1.keys()) != len(dict2.keys()):
        return False

    unmatch = set(dict1.keys()) ^ set(dict2.keys())
    if len(unmatch) != 0:
        return False

    return True


def getPolicyActionValue(policies, action, max=True,
                         is_string=False, subkey=None):
    """
    This function retrieves the int value of an action from a list of policies
    input

    :param policies: list of policies as returned from config.getPolicy
        This is a list of dictionaries
    :param action: an action, to be searched
    :param max: if True, it will return the highest value, if there are
        multiple policies if False, it will return the lowest value, if there
        are multiple policies
    :param is_string: if True, the value is a string and not an integer

    Example policy::

        pol10: {
            action: "maxtoken = 10",
            scope: "enrollment",
            realm: "realm1",
            user: "",
            time: ""
           }
    """
    results = {}

    for _polname, pol in policies.items():
        action_key = action
        action_value = pol['action'].strip()
        # the regex requires a trailing ','
        if action_value[-1:] != ',':
            action_value = action_value + ','
        values = parse_action_value(action_value)

        if subkey:
            action_key = "%s.%s" % (action, subkey)

        ret = values.get(action_key, None)

        # the parameter String=False enforces a conversion into an int
        if type(ret) in [str, unicode] and is_string is False:
            try:
                ret = int(ret)
            except ValueError:
                pass

        if ret:
            results[_polname] = ret

    if len(results) > 1:
        for val in results.values():
            if val != results.values()[0]:
                LOG. error("multiple different action value matches exists %r"
                           % results)

    ret = -1
    if is_string:
        ret = ""

    if results:
        ret = results.values()[0]

    return ret


def parse_action_value(action_value):
    """
    parsing the policy action value by an regular expression
    """
    params = {}
    key_vals = action_value.split(',')
    for ke_val in key_vals:
        res = ke_val.split('=', 1)

        # if we have a boolean value, there is only one arg
        if len(res) == 1:
            key = res[0].strip()
            if key:
                params[key] = True
        else:
            key = res[0].strip()
            val = res[1].strip()
            params[key] = val

    return params




def split_value(policy, attribute="client", marks=False):
    """
    This function returns the parameter "client" or "user" in
    a policy as an array

    """
    attrs = policy.get(attribute, "")
    if attrs == "None" or attrs is None:
        attrs = ""

    attrs_array = []
    if marks:
        attrs_array = [co.strip()[:-1] for co in attrs.split(',')
                       if len(co.strip()) and co.strip()[-1] == ":"]
    else:
        attrs_array = [co.strip()
                       for co in attrs.split(',')
                       if len(co.strip()) and co.strip()[-1] != ":"]
    # if for some reason the first element is empty, delete it.
    if len(attrs_array) and attrs_array[0] == "":
        del attrs_array[0]
    return attrs_array


def get_realm_from_policies(policies):
    """
    get all the realms from the policies:

    :param policies: the dict of all policies
    :param lowerRealms: bool - realm comparison should be/ be not case sensitiv

    :return: tuple of resolves and realms
    """
    realms = set()

    for _pol, val in policies.items():
        pol_realm = val.get('realm', '') or ''
        pol_realms = [x.strip() for x in pol_realm.split(',')]
        realms.update(pol_realms)

    return list(realms)


def get_resolvers_for_realms(realms):
    """
    get resolvers from realms

    :param realms: the list of all realms
    :return: list of resolvers
    """

    resolvers = set()

    all_realms = context['Realms']

    for realm in realms:
        if realm in all_realms:
            realm_conf = all_realms[realm]
            for resolver in realm_conf['useridresolver']:
                resolvers.add(resolver.strip(" "))

    return list(resolvers)


def parse_policies(lConfig):
    """
    parse all policie defintions in the config into one policy dict

    :param lconfig: the linotp config dict
    :return: dict with all policies of the config
    """
    Policies = {}
    for entry in lConfig:
        if entry.startswith("linotp.Policy."):
            # log.debug("[getPolicy] entry: %s" % entry )
            policy = entry.split(".", 4)
            if len(policy) == 4:
                name = policy[2]
                key = policy[3]
                value = lConfig.get(entry)

                # prepare the value to be at least an empty string
                if (key in ('user', 'client', 'realm', 'time') and
                   value is None or value.strip() == 'None'):
                    value = ''

                if key == "realm":
                    value = value.lower()

                if name in Policies:
                    Policies[name][key] = value
                else:
                    Policies[name] = {key: value}

    #
    # we make here some assumptions explicit:
    #  "empty values are treated as wildcards"
    # by replacing these empty values by '*'

    for name, policy in Policies.items():
        if 'scope' in policy and policy['scope'] in ['selfservice',
                                                     'admin',
                                                     'enrollment',
                                                     'authorization',
                                                     'authentication']:
            if 'user' in policy and policy['user'] == '':
                policy['user'] = '*'
            if 'client' in policy and policy['client'] == '':
                policy['client'] = '*'
            if 'time' in policy and policy['time'] == '':
                policy['time'] = '*'

    return Policies

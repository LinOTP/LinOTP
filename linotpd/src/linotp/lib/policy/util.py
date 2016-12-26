# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 KeyIdentity GmbH
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

""" policy processing utilities """
from copy import deepcopy

from linotp.lib.context import request_context as context


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
                if value is None and key in ('user', 'client', 'realm'):
                    value = ''
                if key == "realm":
                    value = value.lower()

                if name in Policies:
                    Policies[name][key] = value
                else:
                    Policies[name] = {key: value}

    return Policies

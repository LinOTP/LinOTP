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
""" legacy policy functions """

import logging

from linotp.lib.user import User

from linotp.lib.policy.util import _getAuthenticatedUser
from linotp.lib.policy.util import get_copy_of_policies

from linotp.lib.policy.filter import UserDomainCompare

log = logging.getLogger(__name__)


def legacy_getAuthorization(scope, action):
    """
    This internal function returns the Authrorizaition within some
    the scope=system(or audit, monitoring, tools ). for the currently
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

    scope_filter = {'scope': scope}
    p_at_all = legacy_getPolicy(scope_filter)

    if len(p_at_all) == 0:
        log.info("No policies in scope %s found. Checking "
                 "of scope %s be disabled." % (scope, scope))
        active = False
        auth = True

    # TODO: We may change this later to other authentication schemes
    log.debug("[getAuthorization] now getting the admin user name")

    admin_user = _getAuthenticatedUser()

    log.debug("Evaluating policies for the user: %s" % admin_user['login'])

    param = {'user': admin_user['login'],
             'scope': scope,
             'action': action}

    policies = legacy_getPolicy(param=param)
    log.debug("Found the following policies: %r" % policies)

    if len(policies.keys()) > 0:
        auth = True

    return {'active': active, 'auth': auth, 'admin': admin_user['login']}


def legacy_getPolicy(param, display_inactive=False):
    '''
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
    '''
    # log.debug("[getPolicy] params %s" % str(param))
    Policies = {}

    # First we load ALL policies from the Config
    lPolicies = get_copy_of_policies()

    if param.get('name', None):
        # If a named policy was requested, we add
        # the policy if the name does match case insensitiv
        p_name = param['name'].lower()
        for pol_name in lPolicies:
            if pol_name.lower() == p_name:
                Policies[pol_name] = lPolicies[pol_name]
    else:
        Policies = lPolicies

    # Now we need to clean up policies, that are inactive
    if not display_inactive:
        pol2delete = []
        for polname, policy in Policies.items():
            pol_active = policy.get("active", "True")
            if pol_active == "False":
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    # Now we need to clean up realms, that were not requested
    pol2delete = []
    if param.get('realm', None) is not None:
        # log.debug("[getPolicy] cleanup acccording to realm %s"
        #          % param["realm"])
        for polname, policy in Policies.items():
            delete_it = True
            # log.debug("[getPolicy] evaluating policy %s: %s"
            #          % (polname, str(policy)))
            if policy.get("realm") is not None:
                pol_realms = [p.strip()
                              for p in policy['realm'].lower().split(',')]
                # log.debug("[getPolicy] realms in policy %s: %s"
                #          % (polname, str(pol_realms) ))
                for r in pol_realms:
                    # log.debug("[getPolicy] Realm: %s" % r)
                    if r == param['realm'].lower() or r == '*':
                        # log.debug( "[getPolicy] Setting delete_it to false.
                        # Se we are using policy: %s" % str(polname))
                        delete_it = False
            if delete_it:
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    pol2delete = []
    if param.get('scope', None) is not None:
        # log.debug("[getPolicy] cleanup acccording to scope %s"
        #          % param["scope"])
        for polname, policy in Policies.items():
            if policy['scope'].lower() != param['scope'].lower():
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    pol2delete = []
    if param.get('action', None) is not None:
        # log.debug("[getPolicy] cleanup acccording to action %s"
        #          % param["action"])
        param_action = param['action'].strip().lower()
        for polname, policy in Policies.items():
            delete_it = True
            # log.debug("[getPolicy] evaluating policy %s: %s"
            #          % (polname, str(policy)))
            if policy.get("action") is not None:
                pol_actions = [p.strip()
                               for p in policy.get('action', "").
                               lower().split(',')]
                # log.debug("[getPolicy] actions in policy %s: %s "
                #          % (polname, str(pol_actions) ))
                for policy_action in pol_actions:
                    if policy_action == '*' or policy_action == param_action:
                        # If any action (*) or the exact action we are looking
                        # for matches, then keep the policy
                        # e.g. otppin=1 matches when we search for 'otppin=1'
                        delete_it = False
                    elif policy_action.split('=')[0].strip() == param_action:
                        # If the first part of the action matches then keep the
                        # policy
                        # e.g. otppin=1 matches when we search for 'otppin'
                        delete_it = False
                    else:
                        # No match, delete_it = True
                        pass
            if delete_it:
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    pol2delete = []
    wildcard_match = {}
    exact_user_match = {}
    wildcard_user_match = {}
    if param.get('user', None) is not None:
        # log.debug("cleanup acccording to user %s" % param["user"])
        for polname, policy in Policies.items():
            if policy.get('user'):
                pol_users = [p.strip()
                             for p in policy.get('user').lower().split(',')]
                # log.debug("[getPolicy] users in policy %s: %s"
                #          % (polname, str(pol_users) ))
            else:
                log.error("Empty userlist in policy '%s' not supported!"
                          % polname)
                raise Exception("Empty userlist in policy '%s' not supported!"
                                % polname)

            delete_it = True

            # first check of wildcard in users
            if '*' in pol_users:
                wildcard_match[polname] = policy
                delete_it = False

            # then check for direct name match
            if delete_it:
                if (param['user'].lower() in pol_users or
                     param['user'] in pol_users):
                    exact_user_match[polname] = policy
                    delete_it = False

            if delete_it:
                # we support the verification of the user,
                # to be in a resolver for the admin and system scope
                local_scope = param.get('scope', '').lower()
                if local_scope in ['admin', 'system', 'monitoring',
                                   'authentication',
                                   'reporting.access']:

                    policy_users = policy.get('user', '').split(',')
                    userObj = User(login=param['user'])

                    if 'realm' in param:
                        userObj.realm = param['realm']
                    else:
                        import linotp.lib.realm
                        userObj.realm = linotp.lib.realm.getDefaultRealm()

                    # we do the extended user defintion comparison
                    res = _filter_admin_user(policy_users, userObj)
                    if res is True:
                        wildcard_user_match[polname] = policy
                        delete_it = False

            if delete_it:
                pol2delete.append(polname)
        for polname in pol2delete:
            del Policies[polname]

    # if we got policies and a user is defined on request
    if len(Policies) > 0:
        if exact_user_match:
            Policies = exact_user_match
            log.debug("getting exact user match %r for params %s",
                      exact_user_match, param)

        elif wildcard_user_match:
            Policies = wildcard_user_match
            log.debug("getting wildcard user match %r for params %s",
                      wildcard_user_match, param)

        elif wildcard_match:
            Policies = wildcard_match
            log.debug("getting wildcard user match %r for params %s",
                      wildcard_match, param)

    # only do the realm filtering if action was filtered before
    if 'action' in param:
        Policies = _post_realm_filter(Policies, param)

    log.debug("getting policies %s for params %s" % (Policies, param))
    return Policies


def _post_realm_filter(policies, param):
    """
    best realm match - more precise policies should be prefered

    algorithm:
        if the param realm contains no wildcard
        check if there are policies with exact match of
        that realm

    """
    if 'realm' not in param or not param['realm'] or '*' == param['realm']:
        return policies

    exact_matching = {}

    param_realm = param['realm'].lower()
    for pol_name, pol in policies.items():
        if pol['realm'].lower() == param_realm:
            exact_matching[pol_name] = pol

    if exact_matching:
        return exact_matching

    return policies


def _filter_admin_user(policy_users, userObj):
    """
    filter the policies, where the logged in user matches one of the
    extended policy user filters.

    Remark: currently without user attribute comparison, as the definition
            and the testing here is not completed

    :param policy_users: list of policy user definitions
    :param userObj: the logged in user as object

    :return: boolean, true if user matched policy user definition
    """
    res = False

    for policy_user in policy_users:
        user_def = policy_user.strip()
        res = None

        # check if there is an attribute filter in defintion
        # !! currently unspecified and untested - so commented out!!
        # if '#' in  user_def:
        #    attr_comp = AttributeCompare()
        #    domUserObj = userObj
        #    u_d, _sep, av = user_def.rpartition('#')

        #    # if we have a domain match, we try the compare
        #    # literal, but the attrbute requires the existance!
        #    if '@' in u_d:
        #        if '@' in param['user']:
        #            login, _sep, realm = param['user'].rpartition('@')
        #            domUserObj = User(login=login, realm=realm)

        #    res = attr_comp.compare(userObj, user_def)

        # if no attribute filter -try domain match
        if "@" in user_def:
            domUserObj = userObj

            # in case of domain match, we do string compare
            # to use the same comparator, we have to establish the realm
            # as last part of the login (if there)
            if '@' in userObj.login:
                login, _sep, realm = userObj.login.rpartition('@')
                domUserObj = User(login=login, realm=realm)
            domain_comp = UserDomainCompare()
            res = domain_comp.compare(domUserObj, user_def)

        # or try resolver filter, BUT with existance check
        elif ':' in user_def:
            domain_comp = UserDomainCompare()
            res = domain_comp.exists(userObj, user_def)

        # any other filter is returned as ignored
        else:
            continue

        if res is True:
            break

    return res

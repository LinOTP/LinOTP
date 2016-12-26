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

from linotp.lib.policy.util import _getAuthenticatedUser
from linotp.lib.policy.util import get_policies


from linotp.lib.policy.evaluate import PolicyEvaluater


LOG = logging.getLogger(__name__)


def new_getPolicy(param, display_inactive=False):
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

    #
    # filter the policies with the new engine

    policy_elve = PolicyEvaluater(get_policies())

    #
    # install the filters

    policy_elve.set_filters(params=param)

    #
    # add the special filter for activ or inactive policies

    policy_elve.filter_for_inactive(state=display_inactive)

    #
    # finally we apply the filter

    new_pols = policy_elve.evaluate()

    return new_pols


def new_getAuthorization(scope, action):
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

    policy_elve = PolicyEvaluater(get_policies())

    policy_elve.set_filters({'scope': scope})
    p_at_all = policy_elve.evaluate()

    if len(p_at_all) == 0:
        LOG.info("No policies in scope %s found. Checking "
                 "of scope %s be disabled.", scope, scope)
        active = False
        auth = True

    # TODO: We may change this later to other authentication schemes
    LOG.debug("[getAuthorization] now getting the admin user name")

    admin_user = _getAuthenticatedUser()

    LOG.debug("Evaluating policies for the user: %s", admin_user['login'])

    param = {'user': admin_user['login'],
             'scope': scope,
             'action': action}

    policies = policy_elve.set_filters(param).evaluate(policy_set=p_at_all)
    LOG.debug("Found the following policies: %r", policies)

    if len(policies.keys()) > 0:
        auth = True

    return {'active': active,
            'auth': auth,
            'admin': admin_user['login']}

# eof

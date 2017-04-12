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

""" policy evaluation """

from datetime import datetime

from netaddr import IPAddress
from netaddr import IPNetwork

from linotp.lib.policy.filter import UserDomainCompare
from linotp.lib.policy.filter import AttributeCompare
from linotp.lib.user import User
from linotp.lib.realm import getRealms


class PolicyEvaluator(object):
    """
    policy evaluation engine

    the policy evaluation is defined by an access request like:
        {'scope': 'admin', 'user': 'Hugo@realm'}
    which is checked against all policies. As result the list of all
    matching policies is returned.

    for refactoring the current policy evaluation

      getPolicy()

    could be replaced by three simple steps: by starting the policy class
    and adding the filters

        pe = PolicyEvaluator(Context.policies)
        pe.set_filters(param)

    followed by the evaluation:

        matching_policies = pe.evaluate()

    For post post processing more filters could be added - be aware filters are
    named and could be overwritten - and the evaluation could be made on an
    policy set:

        pe.set_filters({'client': '192.168.178.1'})
        pe.evaluate(previous_policies)

    [
     Currently the filter only return a boolean value, but this could be
     extendend to be a tuple of (match, exact or wildcard) which will help
     to determin the most precise policy
    ]

    [
     In addition to the categorization exact match/ wildcard match the initial
     set of policies for a request should be made. The request specific policy
     set will be determined at request start match for the primary access
     vector, which should be the:

       user, client, time and in some cases the realm
    ]

    """

    def __init__(self, all_policies):
        """
        policy evaluation constructor

        :param all_policies: the base for the policy evaluation set
        """

        self.all_policies = all_policies
        self.filters = []

    def has_policy(self, param):
        """
        check if a policy for example 'scope:admin' exists

        :param: dict with filter conditions
        :return: list of matching policies
        """

        try:

            # preserve the old filters
            sec_filters = self.filters

            self.set_filters(param)
            policies = self.evaluate(multiple=True)

        finally:
            # and restore the preserved ones
            self.filters = sec_filters

        return policies

    def evaluate(self, policy_set=None, multiple=True):
        """
        evaluate - compare all policies against the access request

        implementation detail:
        - The evaluate iterates over all given policies.
        - During the iteration all filter comparisons are made against
          the one policy. This allows an early exit, thus if one filter does
          not match, all further comparison of the given policy could be
          skipped.
        - during the filter definition the comparison function is defined, thus
          all filter evaluation steps could be treated equal by just calling
          the comparison function with the actual value.

        :param policy_set: optional, base policies against which all filter
                           are evaluated
        :param multiple: define if the policies should be post processed to
                         return the best matching ones. Default is to do no
                         post proessing
        :return: the set of matching policies
        """

        matching_policies = {}

        #
        # provide information about the policy evaluation - for debugging :)

        matching_details = {}

        all_policies = self.all_policies

        if policy_set:
            all_policies = policy_set

        if not self.filters:
            return all_policies

        for p_name, p_dict in all_policies.items():

            #
            # special case: for filtering of policies by name:
            # we add the name of the policy to the policy description
            # so we can use the same machine for the name compare

            if 'name' not in p_dict:
                p_dict['name'] = p_name

            #
            # evaluate each filter against the policy. if one filter fails
            # we can skip the evaluation the given policy

            for (f_key, f_value, f_compare) in self.filters:

                policy_condition = p_dict.get(f_key)
                matching = f_compare(policy_condition, f_value)

                if not matching:
                    break

            if matching:
                matching_policies[p_name] = p_dict

        # if we have multiple policies and post processing should be made:
        if not multiple and len(matching_policies):

            #
            # so we do some post selection but dont care for the result, as
            # this is done in the upper level

            matching_policies = self._most_precise_policy(matching_policies)
            return matching_policies

        return matching_policies

    def _most_precise_policy(self, matching_policies):

        no_wild_card_match = {}

        for key in ['user', 'client', 'realm']:
            entry = []
            for name, policy in matching_policies.items():
                conditions = [x.strip() for x in policy[key].split(',')]
                if '*' not in conditions:
                    entry.append(name)

            if len(entry) > 0:
                no_wild_card_match[key] = entry

        res = None

        if ('realm' in no_wild_card_match and
           len(no_wild_card_match['realm']) == 1):

            res = no_wild_card_match['realm']

        elif ('client' in no_wild_card_match and
              len(no_wild_card_match['client']) == 1):

            res = no_wild_card_match['client']

        elif ('user' in no_wild_card_match and
              len(no_wild_card_match['user']) == 1):

            res = no_wild_card_match['user']

        if res:
            policy_name = res[0]
            return {policy_name: matching_policies[policy_name]}

        return matching_policies

    def set_filters(self, params):
        """
        set up a set of filters from a dictionary

        interface to ease the migration
        """

        for key, value in params.items():
            if key == 'active':
                self.filter_for_active(state=value)
            elif key == 'scope':
                self.filter_for_scope(scope=value)
            elif key == 'user':
                self.filter_for_user(user=value)
            elif key == 'realm':
                self.filter_for_realm(realm=value)
            elif key == 'action':
                self.filter_for_action(action=value)
            elif key == 'name':
                self.filter_for_name(name=value)
            elif key == 'time':
                self.filter_for_time(time=value)
            elif key == 'client':
                self.filter_for_client(client=value)

        return self

    def reset_filters(self):
        """
        remove all filters
        """
        del self.filters[:]

    def add_filter(self, key, value, value_compare):
        """
        low level filter interface which adds a tuple of
            key, value and comparering_method
        like
           ('user , 'hugo', user_list_compare)
        """
        self.filters.append((key, value, value_compare))

    def filter_for_inactive(self, state=False):
        """
        usability wrapper for adding state filter for filtering
        inactive policies

        :param state: policy state - boolean
        :return: - nothing -
        """
        if state is not None:
            self.add_filter('active', not state, bool_compare)

    def filter_for_active(self, state=True):
        """
        usability wrapper for adding state filter for filtering active policies

        :param state: policy state - boolean
        :return: - nothing -
        """
        if state is not None:
            self.add_filter('active', state, bool_compare)

    def filter_for_scope(self, scope):
        """
        usability wrapper for the policy scope

        :param state: policy state - boolean
        :return: - nothing -
        """
        if scope is not None:
            self.add_filter('scope', scope, string_compare)

    def filter_for_user(self, user):
        """
        usability wrapper for adding a user filter

        :param user: the user, either of type User or string
        :return: - nothing -
        """
        if user is not None:
            self.add_filter('user', user, user_list_compare)

    def filter_for_action(self, action):
        """
        usability wrapper for adding a filter for actions

        :param user: the action
        :return: - nothing -
        """

        if action is not None:
            self.add_filter('action', action, value_list_compare)

    def filter_for_name(self, name):
        """
        usability wrapper for adding a filter for the policy name

        :param name: policy name - string
        :return: - nothing -
        """
        if name is not None:
            self.add_filter('name', name, string_compare)

    def filter_for_realm(self, realm):
        """
        usability wrapper for adding realm value for realm filtering

        :param realm: realm string
        :return: - nothing -
        """
        if realm is not None:
            self.add_filter('realm', realm, wildcard_icase_list_compare)

    def filter_for_client(self, client):
        """
        usability wrapper for adding client value for client filtering

        :param client: client ip as string
        :return: - nothing -
        """

        if client is not None:
            self.add_filter('client', client, ip_list_compare)

    def filter_for_time(self, time=None):
        """
        usability wrapper for adding time value for time filtering

        :param time: datetime object or None, which referes to now()
        :return: - nothing -
        """
        if time is None:
            time = datetime.now()
        self.add_filter('time', time, time_list_compare)

#
# below: the comparing functions
#
# unit tests in tests/unit/policy/test_condition_comparison.py
#


def value_list_compare(policy_conditions, action_name):
    """
    check if given action_name matches the conditions

    :param policy_condition: the condition described in the policy
    :param action_name: the name of the action, which could be a key=val
    :return: booleans
    """

    conditions = [x.strip() for x in policy_conditions.split(',')]

    if '*' in conditions:
        return True

    # exact action match
    if action_name in conditions:
        return True

    # extract action name from action_name=value
    for condition in conditions:

        cond_name, _sep, _cond_value = condition.partition('=')
        if cond_name.strip() == action_name:
            return True

    return False


def wildcard_list_compare(policy_conditions, value):
    """
    check if given string value matches the conditions

    :param policy_condition: the condition described in the policy
    :param value: the string value
    :return: booleans
    """

    matched = wildcard_icase_list_compare(policy_conditions,
                                          value, ignore_case=False)

    return matched


def wildcard_icase_list_compare(policy_conditions, value, ignore_case=True):
    """
    check if given string value matches the conditions

    :param policy_condition: the condition described in the policy
    :param value: the string value
    :return: booleans
    """

    conditions = [x.strip() for x in policy_conditions.split(',')]

    if '*' in conditions:
        return True

    matched = False

    for condition in conditions:

        its_a_not_condition = False

        if condition[0] in ['-', '!']:
            its_a_not_condition = True
            condition = condition[1:]

        #
        # support for case sensitive comparison

        if ignore_case:
            cmp_value = value.lower()
            cmp_condition = condition.lower()
        else:
            cmp_value = value
            cmp_condition = condition

        if cmp_value == cmp_condition:
            if its_a_not_condition:
                return False
            else:
                matched = True

    return matched


def string_compare(policy_condition, value):
    """
    check if given string value matches the conditions

    :param policy_condition: the condition described in the policy
    :param value: the string value
    :return: booleans
    """
    if policy_condition == value:
        return True

    return False


def bool_compare(policy_condition, value):
    """
    check if given value is boolean and matches of policy conditions

    :param policy_condition: the condition described in the policy
    :param value: the string representation of a boolean value
    :return: booleans
    """

    boolean_condition = str(policy_condition).lower() == 'true'

    if boolean_condition == value:
        return True

    return False


def ip_list_compare(policy_conditions, client):
    """
    check if client ip matches list of policy conditions

    :param policy_condition: the condition described in the policy
    :param client: the to be compared client ip
    :return: booleans
    """

    conditions = [x.strip() for x in policy_conditions.split(',')]

    if '*' in conditions:
        return True

    allowed = False

    for condition in conditions:
        identified = False
        its_a_not_condition = False

        if not condition:
            continue

        if condition[0] in ['-', '!']:
            condition = condition[1:]
            its_a_not_condition = True

        if condition == '*':
            identified = True

        elif IPAddress(client) in IPNetwork(condition):
            identified = True

        if identified:
            if its_a_not_condition:
                return False
            allowed = True

    return allowed


def user_list_compare(policy_conditions, login):
    """
    check if login name matches list of user policy conditions

    :param policy_condition: the condition described in the policy
    :param login: the to be compared user - either User obj or string
    :return: booleans
    """
    conditions = [x.strip() for x in policy_conditions.split(',')]

    if isinstance(login, User):
        user = login
    elif isinstance(login, str) or isinstance(login, unicode):
        if '@' in login:
            usr, _sep, realm = login.rpartition('@')
            user = User(usr, realm)
        else:
            user = User(login)
    else:
        raise Exception("unsupported type of login")

    matched = False

    domain_comp = UserDomainCompare()
    attr_comp = AttributeCompare()

    for condition in conditions:

        if not condition:
            continue

        its_a_not_condition = False

        # we preserve the kind of match:
        # in case of a 'non condition' match, we must return immeaditly
        # and return a False to break out of the loop of conditions

        if condition[0] in ['-', '!']:
            condition = condition[1:]
            its_a_not_condition = True

        if '#' in condition:

            if ((isinstance(login, str) or isinstance(login, unicode)) and
               '@' in login):

                usr, _sep, realm = login.rpartition('@')

                if realm in getRealms():
                    c_user = User(usr, realm)
                else:
                    c_user = User(login)

            else:
                c_user = user

            identified = attr_comp.compare(c_user, condition)

        elif '@' in condition:  # domain condition requires a domain compare

            #
            # we support fake users, where login is of type string
            # and who have an '@' in it - we rely on that real users
            # are identified up front and then login will of type User

            if ((isinstance(login, str) or isinstance(login, unicode)) and
               '@' in login):
                u_login, _, r_login = login.rpartition('@')
                c_user = User(u_login, r_login)
            else:
                c_user = user
            identified = domain_comp.compare(c_user, condition)

        elif ':' in condition:  # resolver condition - by user exists check

            #
            # special treatment of literal user definition with an @ in login:
            # we can split last part and check if it is an existing realm. If
            # not we treat the user login as literal only

            if ((isinstance(login, str) or isinstance(login, unicode)) and
               '@' in login):

                usr, _sep, realm = login.rpartition('@')

                if realm in getRealms():
                    c_user = User(usr, realm)
                else:
                    c_user = User(login)

            else:
                c_user = user

            identified = domain_comp.exists(c_user, condition)

        else:  # simple user condition with string compare and wild cards

            identified = domain_comp.compare(user, condition)

        if identified:
            matched = True

            if its_a_not_condition:  # early exit on a not condition
                return False

    return matched


def _compare_cron_value(value, target):
    """
     cron value comparison - compare the target, if it matches the cron value

    a cron values could be like

        */15 */6 1,15,31 * 1-5 *
    or
        0 12 * * 1-5 * (0 12 * * Mon-Fri *)

     (c) code copied from pycron

        https://github.com/kipe/pycron

    with MIT Licence

        https://github.com/kipe/pycron/blob/master/LICENSE

    :param value: one cron entry
    :param target: the matching value
    :return: boolean - if target matches the cron entry
    """

    value = value.strip()

    if value == '*':
        return True

    values = [x.strip() for x in value.split(',')]

    for value in values:
        try:
            # First, try a direct comparison
            if int(value) == target:
                return True
        except ValueError:
            pass

        if '/' in value:
            val, interval = [x.strip() for x in value.split('/')]

            #
            # Not sure if applicable for every situation, but
            # just to make sure...

            if val != '*':
                continue

            # If the remainder is zero, this matches

            if target % int(interval) == 0:
                return True

        if '-' in value:
            try:
                start, end = [int(x.strip()) for x in value.split('-')]
            except ValueError:
                continue
            # If target value is in the range, it matches
            if target in range(start, end + 1):
                return True

    return False


def cron_compare(condition, now):
    """
    compare a cron condition with a given datetime

    :param condition: a cron condition
    :param now: the datetime to compare with

    :return: boolean - is allowed or not
    """

    condition_parts = []
    parts = condition.split(' ')
    for part in parts:
        if part.strip():
            condition_parts.append(part)

    if len(condition_parts) != 6:
        raise Exception("Error in Time Condition format")

    #
    # extract the members of the cron condition

    minute = condition_parts[0]
    hour = condition_parts[1]
    dom = condition_parts[2]
    month = condition_parts[3]
    dow = condition_parts[4]
    year = condition_parts[5]

    weekday = now.isoweekday()

    return (_compare_cron_value(minute, now.minute) and
            _compare_cron_value(hour, now.hour) and
            _compare_cron_value(dom, now.day) and
            _compare_cron_value(month, now.month) and
            _compare_cron_value(dow, 0 if weekday == 7 else weekday) and
            _compare_cron_value(year, now.year))


def time_list_compare(policy_conditions, now):
    """
    compare a given time with a time description in the policy

    for the time description we use the cron format, which allows to
    define time frames like access from Mo-Fr and from 6:00 to 18:00:

    * 6-18 * * 1-5 *

    * * * * * *
    | | | | | |
    | | | | | +-- Year              (range: 1900-3000)
    | | | | +---- Day of the Week   (range: 1-7, 1 standing for Monday)
    | | | +------ Month of the Year (range: 1-12)
    | | +-------- Day of the Month  (range: 1-31)
    | +---------- Hour              (range: 0-23)
    +------------ Minute            (range: 0-59)

    Remark: time conditions are separated by ';' as the ',' is part of
            the cron expression

    """
    conditions = [x.strip() for x in policy_conditions.split(';')]

    matched = False

    if now is None:
        now = datetime.now()

    for condition in conditions:

        #
        # skip for empty conditions

        if not condition:
            continue

        #
        # support excluding conditions which start with [-,!]

        its_a_not_condition = False

        if condition[0] in ['-', '!']:
            its_a_not_condition = True
            condition = condition[1:]

        #
        # compare the cron condition

        if cron_compare(condition, now):
            if its_a_not_condition:
                return False
            else:
                matched = True

    return matched

# eof

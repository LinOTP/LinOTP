# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""policy evaluation"""

from datetime import datetime
from typing import Dict

from netaddr import IPAddress, IPNetwork

from linotp.lib.realm import getRealms
from linotp.lib.user import User

from .filter import AttributeCompare, UserDomainCompare
from .util import parse_action_value

WILDCARD_MATCH = "wildcard:match"
EXACT_MATCH = "exact:match"
REGEX_MATCH = "regex:match"
NOT_MATCH = "not:match"


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

    def has_policy(self, param, strict_matches=True):
        """
        check if a policy for example 'scope:admin' exists

        :param: dict with filter conditions
        :return: list of matching policies
        """

        try:
            # preserve the old filters
            sec_filters = [old_filter for old_filter in self.filters]

            self.set_filters(param)
            policies = self.evaluate(strict_matches=strict_matches)

        finally:
            # and restore the preserved ones
            self.filters = sec_filters

        return policies

    def evaluate(self, policy_set=None, strict_matches=True):
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
        - If strict_matches=True, there is a special treatment of the user matching in policies, which
          classifies the policies in those with a pure wildcard match, a regex
          match and an exact matching. If there are exact matching, this set of
          policies is prefered over those with a regex match, which is prefered
          over the set of pure wildcard '*' match. Thus in case of a wildcard
          match, all policies are returned.
          If strict_matches=False, the policies get intersected over all matching policies.

        :param policy_set: optional, base policies against which all filter
                           are evaluated
        :return: the set of matching policies
        """

        if not policy_set:
            policy_set = self.all_policies

        matching_policies, matches = self._get_matching_policies_and_matches(policy_set)
        if not matching_policies:
            return {}

        if strict_matches:
            selection = self._intersect_matches_strict(matching_policies, matches)
        else:
            selection = self._intersect_matches_lazy(matching_policies, matches)

        result = {}
        for entry in selection:
            result[entry] = policy_set[entry]

        return result

    def _get_matching_policies_and_matches(self, policy_set):
        matching_policies = {}
        # preserve a dict with which policy matched best wrt the user
        matches = {}

        if not self.filters:
            return policy_set, matches

        for p_name, p_dict in policy_set.items():
            matching = False

            #
            # special case: for filtering of policies by name:
            # we add the name of the policy to the policy description
            # so we can use the same machine for the name compare

            if "name" not in p_dict:
                p_dict["name"] = p_name

            #
            # evaluate each filter against the policy. if one filter fails
            # we can skip the evaluation the given policy

            match_type = {}

            for f_key, f_value, f_compare in self.filters:
                policy_condition = p_dict.get(f_key)

                # here we honor the user matching, which in difference to the
                # other matching functions returns more than a boolean -
                # it returns the matching precission, which is either:
                # exact:match, regex:match or wildcard:match
                # - the evaluation of the set of policy conditions can
                # only be evaluated within the user_list_compare
                # function

                match_type[f_key], matching = f_compare(policy_condition, f_value)

                if not matching:
                    break

            # --------------------------------------------------------------- --

            # all conditions are evaluated: preserve results in case of a match

            if not matching:
                continue

            matching_policies[p_name] = p_dict
            self.add_match_type(matches, match_type, p_name)

        return matching_policies, matches

    def _intersect_matches_strict(self, matching_policies, matches):
        # to get the best machtes, we intersect the matching policies
        # for example:
        #
        # matchin all: p1, p2, p3, p4, p5
        # user exact: p1, p2, p3
        # user wild: p4, p5
        # => 1 selection: (p1, p2, p3, p4,) & (p1, p2, p3) = (p1, p2, p3)
        #
        # intersect result with realm:
        # realm match exact: p1, p2, p4
        # => 2. selection: (p1, p2, p3) & (p1, p2, p4) = (p1, p2)
        #
        # intersect result with client:
        # client match exact: p3
        # client match wildcard: p1
        # => 3. selecttion: (p1, p2) & (p1) = p1

        return self._intersect_matches_(matching_policies, matches, strict_matches=True)

    def _intersect_matches_lazy(self, matching_policies, matches):
        # to get the most, we intersect the union of matching policies
        # for example:
        #
        # matchin all: p1, p2, p3, p4, p5
        # user exact: p1, p2, p3
        # user wild: p5
        # => 1 selection: (p1, p2, p3, p4, p5) & ((p1, p2, p3) | (p5)) = (p1, p2, p3, p5)
        #
        # intersect result with realm:
        # realm match exact: p1, p2, p5
        # => 2. selection: (p1, p2, p3, p5) & (p1, p2, p5) = (p1, p2, p5)
        #
        # intersect result with client:
        # client match exact: p5
        # client match wildcard: p1
        # => 3. selecttion: (p1, p2, p5) & ((p5) | (p1)) = (p1, p5)

        return self._intersect_matches_(
            matching_policies, matches, strict_matches=False
        )

    def _intersect_matches_(self, matching_policies, matches, strict_matches=True):
        selection = set(matching_policies.keys())

        user_matches = matches.get("user", {})
        if user_matches:
            selection = self.select(
                selection,
                user_matches.get(EXACT_MATCH, set()),
                user_matches.get(REGEX_MATCH, set()),
                user_matches.get(WILDCARD_MATCH, set()),
                strict_matches=strict_matches,
            )

        realm_matches = matches.get("realm", {})
        if realm_matches:
            selection = self.select(
                selection,
                realm_matches.get(EXACT_MATCH, set()),
                realm_matches.get(WILDCARD_MATCH, set()),
                strict_matches=strict_matches,
            )

        client_matches = matches.get("client", {})
        if client_matches:
            selection = self.select(
                selection,
                client_matches.get(EXACT_MATCH, set()),
                client_matches.get(WILDCARD_MATCH, set()),
                strict_matches=strict_matches,
            )

        return selection

    def add_match_type(self, matches: Dict, matches_dict: Dict, policy: str):
        """helper to add the matches into a common dict.

        the dict will contain
            {match_key: {match_type: set(of policy_names)}}

        for example:
            {
            'user': {
                'exact:match':set(p1,p2,p3),
                'regex:match':set(p4),
                'wildcard:match':set(p6)
                },
            'realm': {. . .}
            }

        :param matches: target dict for gathering all matches
        :param matches_dict: the per policy match evaluation
        :param policy: the name of the policy
        """
        for key, match_type in matches_dict.items():
            if key not in matches:
                matches[key] = {}

            if match_type not in matches[key]:
                matches[key][match_type] = set()

            matches[key][match_type].add(policy)

    def select(self, all_matches, *args, **kwargs):
        """helper to intersect the identified sets of matches.

        if no match could be made with one set, try the next one.
        if no intersection with any set, we return the initial one

        :param all_matches: set of initial entries
        :param *args: list of sets, whereby the ordering defines the
                      matching precission e.g.:
                          set(exact), set(regex), set(wildcard)
        :return: set of matches
        """

        if kwargs.get("strict_matches", True):
            for match_set in args:
                if all_matches & match_set:
                    return all_matches & match_set
        else:
            match_set = set().union(*args)
            if all_matches & match_set:
                return all_matches & match_set

        return all_matches

    def set_filters(self, params):
        """
        set up a set of filters from a dictionary

        interface to ease the migration
        """

        for key, value in list(params.items()):
            if key == "active":
                self.filter_for_active(state=value)
            elif key == "scope":
                self.filter_for_scope(scope=value)
            elif key == "user":
                self.filter_for_user(user=value)
            elif key == "realm":
                self.filter_for_realm(realm=value)
            elif key == "action":
                self.filter_for_action(action=value)
            elif key == "name":
                self.filter_for_name(name=value)
            elif key == "time":
                self.filter_for_time(time=value)
            elif key == "client":
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

    def filter_for_active(self, state=True):
        """
        usability wrapper for adding state filter for filtering active policies

        :param state: policy state - boolean
        :return: - nothing -
        """
        if state is not None:
            self.add_filter("active", state, bool_compare)

    def filter_for_scope(self, scope):
        """
        usability wrapper for the policy scope

        :param state: policy state - boolean
        :return: - nothing -
        """
        if scope is not None:
            self.add_filter("scope", scope, string_compare)

    def filter_for_user(self, user):
        """
        usability wrapper for adding a user filter

        :param user: the user, either of type User or string
        :return: - nothing -
        """
        if user is not None:
            self.add_filter("user", user, user_list_compare)

    def filter_for_action(self, action):
        """
        usability wrapper for adding a filter for actions

        :param user: the action
        :return: - nothing -
        """

        if action is not None:
            self.add_filter("action", action, action_compare)

    def filter_for_name(self, name):
        """
        usability wrapper for adding a filter for the policy name

        :param name: policy name - string
        :return: - nothing -
        """
        if name is not None:
            self.add_filter("name", name, string_compare)

    def filter_for_realm(self, realm):
        """
        usability wrapper for adding realm value for realm filtering

        :param realm: realm string
        :return: - nothing -
        """
        if realm is not None:
            self.add_filter("realm", realm, wildcard_icase_list_compare)

    def filter_for_client(self, client):
        """
        usability wrapper for adding client value for client filtering

        :param client: client ip as string
        :return: - nothing -
        """

        if client is not None:
            self.add_filter("client", client, ip_list_compare)

    def filter_for_time(self, time=None):
        """
        usability wrapper for adding time value for time filtering

        :param time: datetime object or None, which referes to now()
        :return: - nothing -
        """
        if time is None:
            time = datetime.now()
        self.add_filter("time", time, time_list_compare)


#
# below: the comparing functions
#
# unit tests in tests/unit/policy/test_condition_comparison.py
#


def action_compare(policy_actions, action):
    """
    check if given action is in the policy_actions

    remarks: we only do the policy detection, the action evaluation is done
             by using the get_action_value

    :param policy_actions: the condition described in the policy
    :param action: the name of the action, which could be a key=val
    :return: booleans
    """

    p_actions = parse_action_value(policy_actions)

    if "*" in p_actions:
        return WILDCARD_MATCH, True

    if "=" not in action:
        if action in p_actions:
            return EXACT_MATCH, True
        return NOT_MATCH, False

    # we only check if the action name is in the policy actions, the value
    # evaluation is done by using the get_action_value() function

    for a_name in parse_action_value(action).keys():
        if a_name in p_actions:
            return EXACT_MATCH, True

    return NOT_MATCH, False


def value_list_compare(policy_conditions, action_name):
    """
    check if given action_name matches the conditions

    :param policy_condition: the condition described in the policy
    :param action_name: the name of the action, which could be a key=val
    :return: booleans
    """

    conditions = [x.strip() for x in policy_conditions.split(",")]

    if "*" in conditions:
        return WILDCARD_MATCH, True

    # exact action match
    if action_name in conditions:
        return EXACT_MATCH, True

    # extract action name from action_name=value
    for condition in conditions:
        cond_name, _sep, _cond_value = condition.partition("=")
        if cond_name.strip() == action_name:
            return EXACT_MATCH, True

    return NOT_MATCH, False


def wildcard_list_compare(policy_conditions, value):
    """
    check if given string value matches the conditions

    :param policy_condition: the condition described in the policy
    :param value: the string value
    :return: booleans
    """

    matched = wildcard_icase_list_compare(policy_conditions, value, ignore_case=False)

    return matched


def wildcard_icase_list_compare(policy_conditions, value, ignore_case=True):
    """
    check if given string value matches the conditions

    :param policy_condition: the condition described in the policy
    :param value: the string value
    :return: booleans
    """

    conditions = [x.strip() for x in policy_conditions.split(",")]

    if "*" in conditions:
        return WILDCARD_MATCH, True

    matched = False
    match_type = NOT_MATCH

    for condition in conditions:
        if not condition:
            continue

        its_a_not_condition = False

        if condition[0] in ["-", "!"]:
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
                return NOT_MATCH, False
            else:
                matched = True
                match_type = EXACT_MATCH

    return match_type, matched


def string_compare(policy_condition, value):
    """
    check if given string value matches the conditions

    :param policy_condition: the condition described in the policy
    :param value: the string value
    :return: booleans
    """
    if policy_condition == value:
        return EXACT_MATCH, True

    return EXACT_MATCH, False


def bool_compare(policy_condition, value):
    """
    check if given value is boolean and matches of policy conditions

    :param policy_condition: the condition described in the policy
    :param value: the string representation of a boolean value
    :return: booleans
    """

    boolean_condition = str(policy_condition).lower() == "true"

    if boolean_condition == value:
        return EXACT_MATCH, True

    return EXACT_MATCH, False


def ip_list_compare(policy_conditions, client):
    """
    check if client ip matches list of policy conditions

    :param policy_condition: the condition described in the policy
    :param client: the to be compared client ip
    :return: booleans
    """

    conditions = [x.strip() for x in policy_conditions.split(",")]

    if "*" in conditions:
        return WILDCARD_MATCH, True

    allowed = False
    match_type = NOT_MATCH

    for condition in conditions:
        identified = False
        its_a_not_condition = False

        if not condition:
            continue

        if condition[0] in ["-", "!"]:
            condition = condition[1:]
            its_a_not_condition = True

        if condition == "*":
            identified = True
            if match_type == "":
                match_type = WILDCARD_MATCH

        elif IPAddress(client) in IPNetwork(condition):
            identified = True
            match_type = EXACT_MATCH

        if identified:
            if its_a_not_condition:
                return NOT_MATCH, False
            allowed = True

    return match_type, allowed


def user_list_compare(policy_conditions, login):
    """
    check if login name matches list of user policy conditions

    :param policy_condition: the condition described in the policy
    :param login: the to be compared user - either User obj or string
    :return: booleans
    """
    conditions = [x.strip() for x in policy_conditions.split(",")]

    if isinstance(login, User):
        user = login
    elif isinstance(login, str):
        if "@" in login:
            usr, _sep, realm = login.rpartition("@")
            user = User(usr, realm)
        else:
            user = User(login)
    else:
        raise Exception("unsupported type of login")

    full_qualified_names = user.get_full_qualified_names()

    matched = False
    match_type = NOT_MATCH

    domain_comp = UserDomainCompare()
    attr_comp = AttributeCompare()

    for condition in conditions:
        if not condition:
            continue

        its_a_not_condition = False

        # we preserve the kind of match:
        # in case of a 'non condition' match, we must return immeaditly
        # and return a False to break out of the loop of conditions

        if condition[0] in ["-", "!"]:
            condition = condition[1:]
            its_a_not_condition = True

        if "#" in condition:
            if isinstance(login, str) and "@" in login:
                usr, _sep, realm = login.rpartition("@")

                if realm in getRealms():
                    c_user = User(usr, realm)
                else:
                    c_user = User(login)

            else:
                c_user = user

            identified = attr_comp.compare(c_user, condition)

        elif "@" in condition:  # domain condition requires a domain compare
            #
            # we support fake users, where login is of type string
            # and who have an '@' in it - we rely on that real users
            # are identified up front and then login will of type User

            if isinstance(login, str) and "@" in login:
                u_login, _, r_login = login.rpartition("@")
                c_user = User(u_login, r_login)
            else:
                c_user = user
            identified = domain_comp.compare(c_user, condition)

        elif ":" in condition:  # resolver condition - by user exists check
            #
            # special treatment of literal user definition with an @ in login:
            # we can split last part and check if it is an existing realm. If
            # not we treat the user login as literal only

            if isinstance(login, str) and "@" in login:
                usr, _sep, realm = login.rpartition("@")

                if realm in getRealms():
                    c_user = User(usr, realm)
                else:
                    c_user = User(login)

            else:
                c_user = user

            # check resolver of the user
            identified = domain_comp.exists(c_user, condition)

        else:  # simple user condition with string compare and wild cards
            identified = domain_comp.compare(user, condition)

        if not identified:
            continue

        # early exit on a not condition: !user1

        if its_a_not_condition:
            return NOT_MATCH, False

        # if we came here, we got a least one match
        matched = True

        # evaluate the precission of the user match

        if condition in full_qualified_names:
            match_type = EXACT_MATCH

        if condition == "*":
            if not match_type or match_type == NOT_MATCH:
                match_type = WILDCARD_MATCH
        else:
            if match_type != EXACT_MATCH:
                match_type = REGEX_MATCH

    return match_type, matched


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

    if value == "*":
        return True

    values = [x.strip() for x in value.split(",")]

    for value in values:
        try:
            # First, try a direct comparison
            if int(value) == target:
                return True
        except ValueError:
            pass

        if "/" in value:
            val, interval = [x.strip() for x in value.split("/")]

            #
            # Not sure if applicable for every situation, but
            # just to make sure...

            if val != "*":
                continue

            # If the remainder is zero, this matches

            if target % int(interval) == 0:
                return True

        if "-" in value:
            try:
                start, end = [int(x.strip()) for x in value.split("-")]
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

    parts = condition.split(" ")
    condition_parts = [part for part in parts if part.strip()]

    if len(condition_parts) != 6:
        raise Exception(
            "Error in Time Condition format: Expected 6 but "
            f"got {len(condition_parts)} parts in cron notation"
        )

    #
    # extract the members of the cron condition
    minute, hour, dom, month, dow, year = condition_parts

    weekday = now.isoweekday()

    return (
        _compare_cron_value(minute, now.minute)
        and _compare_cron_value(hour, now.hour)
        and _compare_cron_value(dom, now.day)
        and _compare_cron_value(month, now.month)
        and _compare_cron_value(dow, 0 if weekday == 7 else weekday)
        and _compare_cron_value(year, now.year)
    )


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
    conditions = [x.strip() for x in policy_conditions.split(";")]

    matched = False
    match_type = NOT_MATCH

    if now is None:
        now = datetime.now()

    for condition in conditions:
        #
        # skip for empty conditions

        if not condition:
            continue

        # if in the conditions one is with wildcard we grant access

        if condition == "*":
            return WILDCARD_MATCH, True

        #
        # support excluding conditions which start with [-,!]

        its_a_not_condition = False

        if condition[0] in ["-", "!"]:
            its_a_not_condition = True
            condition = condition[1:]

        #
        # compare the cron condition

        if cron_compare(condition, now):
            if its_a_not_condition:
                return NOT_MATCH, False
            else:
                matched = True
                match_type = EXACT_MATCH

    return match_type, matched


# eof

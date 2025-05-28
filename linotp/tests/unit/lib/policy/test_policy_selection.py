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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

"""Unit test for complex policy selection.

The test focus is to select policy with best user match in focus.
Best match criteria are 'exact:match', 'regex:match' and 'wildcard:match'
"""

import unittest

from mock import patch

from linotp.lib.policy.evaluate import PolicyEvaluator
from linotp.lib.user import User

# -------------------------------------------------------------------------- --

# helper mack functions


def fn_mock_domain_comp(user_obj, condition):
    """Helper function to simulate simple domain comparison.

    without the need to contact a resolver
    """

    fqn = user_obj.get_full_qualified_names()
    if condition in fqn:
        return True

    if condition == "*.%s:" % user_obj.resolver_config_identifier:
        return True

    if condition == "*@%s" % user_obj.realm:
        return True

    if condition == "*":
        return True

    return False


# -------------------------------------------------------------------------- --

# helper function


def create_policy(name, **params):
    """helper - to shorten the policy defintion writing.

    allows to make the relevant parts of the policy obvious by heavily
    using defaults
    """
    entry = {
        "user": "",
        "scope": "selfservice",
        "action": name,
        "realm": "*",
        "active": "True",
        "client": "*",
        "time": "* * * * * *;",
    }
    entry.update(params)
    policy = {name: entry}
    return policy


class TestPoliciesSelection(unittest.TestCase):
    """
    unit test the policy evaluation especially wrt best user matching
    """

    @patch("linotp.lib.policy.evaluate.UserDomainCompare.exists")
    @patch("linotp.lib.policy.evaluate.UserDomainCompare.compare")
    def test_user_exact_match(self, mock_domain_comp, mock_domain_exists):
        """evaluate for user1@realm with resolver 'resolver'

        dedicated only user1 policies whith fqn should match excluding not match
        """

        mock_domain_comp.side_effect = fn_mock_domain_comp
        mock_domain_exists.side_effect = fn_mock_domain_comp

        # define user

        user = User(login="user1", realm="realm", resolver_config_identifier="resolver")

        # define policies

        policies = {}
        policies.update(create_policy("self1", user="*"))
        policies.update(create_policy("self2", user="user1"))
        policies.update(create_policy("self3", user="user1"))
        policies.update(create_policy("self4", user="*, user1"))
        policies.update(create_policy("self5", user="*, user1.resolver:"))
        policies.update(
            create_policy("self6", user="*@realm, *.resolver:, user2, !user1")
        )
        policies.update(
            create_policy("self7", user="!*@realm, *.resolver:, user2.resolver, user1")
        )
        policies.update(create_policy("self8", user="*, !user1@realm, user2@realm"))

        # evaluate the policies wrt. the given user

        p_eval = PolicyEvaluator(policies)
        p_eval.filter_for_user(user)
        matching_policies = p_eval.evaluate()

        # compare the results

        expected_matches = set(["self2", "self3", "self4", "self5"])

        matching_policies_names = set(matching_policies.keys())
        assert matching_policies_names == expected_matches

    @patch("linotp.lib.policy.evaluate.UserDomainCompare.exists")
    @patch("linotp.lib.policy.evaluate.UserDomainCompare.compare")
    def test_user_exact_match2(self, mock_domain_comp, mock_domain_exists):
        """evaluate for user2@realm with resolver 'resolver'

        dedicated only user2 policies whith fqn should match and not for realm!
        """

        mock_domain_comp.side_effect = fn_mock_domain_comp
        mock_domain_exists.side_effect = fn_mock_domain_comp

        # define user

        user = User(login="user2", realm="realm", resolver_config_identifier="resolver")

        # define policies

        policies = {}
        policies.update(create_policy("self1", user="*"))
        policies.update(create_policy("self2", user="user1"))
        policies.update(create_policy("self3", user="user1"))
        policies.update(create_policy("self4", user="*, user1"))
        policies.update(create_policy("self5", user="*, user1.resolver:"))
        policies.update(
            create_policy("self6", user="*@realm, *.resolver:, user2, !user1")
        )
        policies.update(
            create_policy("self7", user="!*@realm, *.resolver:, user2.resolver:, user1")
        )
        policies.update(create_policy("self8", user="*, !user1@realm, user2@realm"))

        # evaluate the policies wrt. the given user

        p_eval = PolicyEvaluator(policies)
        p_eval.filter_for_user(user)
        matching_policies = p_eval.evaluate()

        # compare the results

        expected_matches = set(["self6", "self8"])

        matching_policies_names = set(matching_policies.keys())
        assert matching_policies_names == expected_matches, matching_policies_names

    @patch("linotp.lib.policy.evaluate.UserDomainCompare.exists")
    @patch("linotp.lib.policy.evaluate.UserDomainCompare.compare")
    def test_user_regex_match1(self, mock_domain_comp, mock_domain_exists):
        """evaluate for user3@realm with resolver 'resolver'

        as there is no dedicated user policy, the policies with resolver or
        realm will match.
        """

        mock_domain_comp.side_effect = fn_mock_domain_comp
        mock_domain_exists.side_effect = fn_mock_domain_comp

        # define user

        user = User(login="user3", realm="realm", resolver_config_identifier="resolver")

        # define policies

        policies = {}
        policies.update(create_policy("self1", user="*"))
        policies.update(create_policy("self2", user="user1"))
        policies.update(create_policy("self3", user="user1"))
        policies.update(create_policy("self4", user="*, user1"))
        policies.update(create_policy("self5", user="*, user1.resolver:"))
        policies.update(
            create_policy("self6", user="*@realm, *.resolver:, user2, !user1")
        )
        policies.update(
            create_policy("self7", user="!*@realm, *.resolver:, user2.resolver, user1")
        )
        policies.update(create_policy("self8", user="*, !user1@realm, user2@realm"))

        # evaluate the policies wrt. the given user

        p_eval = PolicyEvaluator(policies)
        p_eval.filter_for_user(user)
        matching_policies = p_eval.evaluate()

        # compare the results

        expected_matches = set(["self6"])

        matching_policies_names = set(matching_policies.keys())
        assert matching_policies_names == expected_matches

    @patch("linotp.lib.policy.evaluate.UserDomainCompare.exists")
    @patch("linotp.lib.policy.evaluate.UserDomainCompare.compare")
    def test_user_regex_match2(self, mock_domain_comp, mock_domain_exists):
        """evaluate for user3@realmx with resolver 'resolver'

        as there is no dedicated user policy, the policies with resolver or
        realm will match.
        """

        mock_domain_comp.side_effect = fn_mock_domain_comp
        mock_domain_exists.side_effect = fn_mock_domain_comp

        # define user

        user = User(
            login="user3",
            realm="realmx",
            resolver_config_identifier="resolver",
        )

        # define policies

        policies = {}
        policies.update(create_policy("self1", user="*"))
        policies.update(create_policy("self2", user="user1"))
        policies.update(create_policy("self3", user="user1"))
        policies.update(create_policy("self4", user="*, user1"))
        policies.update(create_policy("self5", user="*, user1.resolver:"))
        policies.update(
            create_policy("self6", user="*@realm, *.resolver:, user2, !user1")
        )
        policies.update(
            create_policy("self7", user="!*@realm, *.resolver:, user2.resolver, user1")
        )
        policies.update(create_policy("self8", user="*, !user1@realm, user2@realm"))

        # evaluate the policies wrt. the given user

        p_eval = PolicyEvaluator(policies)
        p_eval.filter_for_user(user)
        matching_policies = p_eval.evaluate()

        # compare the results

        expected_matches = set(["self6", "self7"])

        matching_policies_names = set(matching_policies.keys())
        assert matching_policies_names == expected_matches

    @patch("linotp.lib.policy.evaluate.UserDomainCompare.exists")
    @patch("linotp.lib.policy.evaluate.UserDomainCompare.compare")
    def test_user_wild_match(self, mock_domain_comp, mock_domain_exists):
        """evaluate for user4@realmX with resolver 'resolverZ'

        as there is no dedicated policy, the policies with wildcards will match
        """

        mock_domain_comp.side_effect = fn_mock_domain_comp
        mock_domain_exists.side_effect = fn_mock_domain_comp

        # define user

        user = User(
            login="user3",
            realm="realmX",
            resolver_config_identifier="resolverZ",
        )

        # define policies

        policies = {}
        policies.update(create_policy("self1", user="*"))
        policies.update(create_policy("self2", user="user1"))
        policies.update(create_policy("self3", user="user1"))
        policies.update(create_policy("self4", user="*, user1"))
        policies.update(create_policy("self5", user="*, user1.resolver:"))
        policies.update(
            create_policy("self6", user="*@realm, *.resolver:, user2, !user1")
        )
        policies.update(
            create_policy("self7", user="!*@realm, *.resolver:, user2.resolver, user1")
        )
        policies.update(create_policy("self8", user="*, !user1@realm, user2@realm"))

        # evaluate the policies wrt. the given user

        p_eval = PolicyEvaluator(policies)
        p_eval.filter_for_user(user)
        matching_policies = p_eval.evaluate()

        # compare the results

        expected_matches = set(["self1", "self4", "self5", "self8"])

        matching_policies_names = set(matching_policies.keys())
        assert matching_policies_names == expected_matches


# eof #

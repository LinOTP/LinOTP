# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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

"""
Test the passthrough Policy in combination with the passOnNoToken
"""

import unittest

from mock import patch

from linotp.lib.policy.evaluate import PolicyEvaluator

policies = {
    "p1": {
        "name": "qrtoken_local",
        "user": "hugo, *",
        "realm": "myrealm",
        "client": "*",
        "time": "*",
        "action": "select",
        "scope": "authentication",
        "active": "True",
    },
    "p2": {
        "name": "qrtoken_local",
        "user": "hugo, eva",
        "realm": "myrealm",
        "client": "127.0.0.1",
        "time": "*",
        "action": "select",
        "scope": "authentication",
        "active": "True",
    },
    "p3": {
        "name": "qrtoken_local",
        "user": "hugo, eva",
        "realm": "*",
        "client": "*",
        "time": "*",
        "action": "select",
        "scope": "authentication",
        "active": "True",
    },
    "p4": {
        "name": "qrtoken_local",
        "user": "anton, eva, *",
        "realm": "myrealm",
        "client": "127.0.0.1",
        "time": "*",
        "action": "select",
        "scope": "authentication",
        "active": "True",
    },
    "p5": {
        "name": "qrtoken_local",
        "user": "eva, *",
        "realm": "your_realm",
        "client": "127.0.0.1",
        "time": "*",
        "action": "select",
        "scope": "authentication",
        "active": "True",
    },
}


class TestGetClientPolicy(unittest.TestCase):
    """Policy evaluation test."""

    def test_multiple_matches(self):
        """test for most precise result over multiple matches.

        to get the best matches, we intersect the matching policies
        for example:

        matching all: p1, p2, p3, p4, p5
        user exact: p1, p2, p3
        user wild: p4, p5
        => 1 selection: (p1, p2, p3, p4,) & (p1, p2, p3) = (p1, p2, p3)

        intersect result with realm:
        realm match exact: p1, p2, p4
        => 2. selection: (p1, p2, p3) & (p1, p2, p4) = (p1, p2)

        intersect result with client:
        client match exact: p3
        client match wildcard: p1
        => 3a. selection: (p1, p2) & (p3) = () => try the client wildcards
        => 3b. selection: (p1, p2) & (p1) = p1
        """

        policies = {
            "p1": {
                "name": "qrtoken_local",
                "user": "hugo, *",
                "realm": "myrealm",
                "client": "*",
                "time": "*",
                "action": "select",
                "scope": "authentication",
                "active": "True",
            },
            "p2": {
                "name": "qrtoken_local",
                "user": "hugo, eva",
                "realm": "myrealm",
                "client": "127.0.0.1",
                "time": "*",
                "action": "select",
                "scope": "authentication",
                "active": "True",
            },
            "p3": {
                "name": "qrtoken_local",
                "user": "hugo, eva",
                "realm": "*",
                "client": "*",
                "time": "*",
                "action": "select",
                "scope": "authentication",
                "active": "True",
            },
            "p4": {
                "name": "qrtoken_local",
                "user": "anton, eva, *",
                "realm": "myrealm",
                "client": "127.0.0.1",
                "time": "*",
                "action": "select",
                "scope": "authentication",
                "active": "True",
            },
            "p5": {
                "name": "qrtoken_local",
                "user": "eva, *",
                "realm": "your_realm",
                "client": "127.0.0.1",
                "time": "*",
                "action": "select",
                "scope": "authentication",
                "active": "True",
            },
        }

        policy_eval = PolicyEvaluator({})

        policy_eval.filter_for_realm("myrealm")
        policy_eval.filter_for_user("hugo")
        policy_eval.filter_for_client("192.168.178.12")

        res = policy_eval.evaluate(policies)

        assert len(list(res.keys())) == 1
        assert "p1" in res

    def test_simple_client_match(self):
        """test that only the most precise client policy will match."""

        policies = {
            "p1": {
                "name": "qrtoken_local",
                "user": "hugo, *",
                "realm": "myrealm",
                "client": "*",
                "time": "*",
                "action": "select",
                "scope": "authentication",
                "active": "True",
            },
            "p2": {
                "name": "qrtoken_local",
                "user": "eva, *",
                "realm": "myrealm",
                "client": "127.0.0.1",
                "time": "*",
                "action": "select",
                "scope": "authentication",
                "active": "True",
            },
        }

        policy_eval = PolicyEvaluator(policies)

        policy_eval.filter_for_realm("myrealm")
        policy_eval.filter_for_user("anton")
        policy_eval.filter_for_client("127.0.0.1")

        res = policy_eval.evaluate(policies)

        assert len(list(res.keys())) == 1
        assert "p1" not in res
        assert "p2" in res


# eof #

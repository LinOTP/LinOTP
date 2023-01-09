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

import pytest
from mock import patch

from linotp.lib.policy import is_authorized
from linotp.lib.user import User


def set_policy(
    name="name",
    user="admin",
    scope="system",
    active=True,
    action="read",
):
    """Helper to define a policy for the policy set"""
    policy = {
        "name": name,
        "user": user,
        "scope": scope,
        "action": action,
        "realms": [],
        "active": active,
        "client": "*",
        "time": "* * * * * *;",
        "resolvers": "",
    }
    return {policy["name"]: policy}


ADMIN = User(
    login="admin", realm="realm", resolver_config_identifier="resolver"
)
NIMDA = User(
    login="nimda", realm="realm", resolver_config_identifier="resolver"
)


def test_no_policies(app):
    """
    Check that every user is authorized for performing actions within a scope
    without any policies.
    """

    policies = {}

    with patch(
        "linotp.lib.policy.processing.get_policies"
    ) as mock_get_policies:
        mock_get_policies.return_value = policies
        assert is_authorized(
            ADMIN, scope="system", action="read"
        ), "Admin should be authorized to read in bootstrap mode"
        assert is_authorized(
            ADMIN, scope="system", action="write"
        ), "Admin should be authorized to write in bootstrap mode"


def test_inactive_policies(app):
    """
    Check that every user is authorized for performing actions within a scope
    with only inactive policies.
    """
    policies = set_policy(
        name="s1", user="admin", scope="system", action="read", active=False
    )

    with patch(
        "linotp.lib.policy.processing.get_policies"
    ) as mock_get_policies:
        mock_get_policies.return_value = policies
        assert is_authorized(
            ADMIN, scope="system", action="read"
        ), "Admin should be authorized as there is no active policy"
        assert is_authorized(
            NIMDA, scope="system", action="read"
        ), "Nimda should be authorized as there is no active policy"


def test_user_specific_policy_match(app):
    """
    Check that only the user mentioned in a policy is authorized to perfom the
    action specified in it.
    """

    policies = set_policy(
        name="s1", user="admin", scope="system", action="read", active=True
    )

    with patch(
        "linotp.lib.policy.processing.get_policies"
    ) as mock_get_policies:
        mock_get_policies.return_value = policies
        assert is_authorized(
            ADMIN, scope="system", action="read"
        ), "Admin should be authorized by a matching policy"
        assert not is_authorized(
            NIMDA, scope="system", action="read"
        ), "Nimda should not be authorized as there is no matching policy"


def test_specific_beats_wildcard_policies(app):
    """
    Check that a user-specific policy grants additional permissions to that user,
    on top of the permissions already granted to all users via a wildcard policy.

    The users only affected by the wildcard policy do not get the permissions in
    the specific policy.
    """

    policies = {}
    policies.update(
        set_policy(
            name="s1", user="*", scope="system", action="read", active=True
        )
    )
    policies.update(
        set_policy(
            name="s2",
            user="admin",
            scope="system",
            action="read, write",
            active=True,
        )
    )

    with patch(
        "linotp.lib.policy.processing.get_policies"
    ) as mock_get_policies:
        mock_get_policies.return_value = policies
        assert is_authorized(
            NIMDA, scope="system", action="read"
        ), "Nimda should be authorized by the wildcard matching policy"
        assert is_authorized(
            ADMIN, scope="system", action="read"
        ), "Admin should be authorized by the exact matching policy"
        assert not is_authorized(NIMDA, scope="system", action="write"), (
            "Nimda should not be authorized by the specific but unmatching "
            "policy"
        )
        assert is_authorized(
            ADMIN, scope="system", action="write"
        ), "Admin should be authorized by the exact matching policy"


def test_multiple_user_specific_policies(app):
    """
    Check that each user is only granted permissions specifically assigned to
    them in particular.
    """

    policies = {}
    policies.update(
        set_policy(
            name="s1",
            user="admin",
            scope="system",
            action="read, write",
            active=True,
        )
    )
    policies.update(
        set_policy(
            name="s2",
            user="nimda",
            scope="system",
            action="read",
            active=True,
        )
    )
    with patch(
        "linotp.lib.policy.processing.get_policies"
    ) as mock_get_policies:
        mock_get_policies.return_value = policies
        assert is_authorized(
            NIMDA, scope="system", action="read"
        ), "Nimda should be authorized by the exact matching policy"
        assert is_authorized(
            ADMIN, scope="system", action="read"
        ), "Admin should be authorized by the exact matching policy"
        assert not is_authorized(
            NIMDA, scope="system", action="write"
        ), "Nimda should not be authorized due to no matching policies"
        assert is_authorized(
            ADMIN, scope="system", action="write"
        ), "Admin should be authorized by the exact matching policy"


def test_inactive_wildcard_policy(app):
    """
    Check that an inactive wildcard is not evaluated.
    """

    policies = {}
    policies.update(
        set_policy(
            name="s1",
            user="*",
            scope="system",
            action="read, write",
            active=False,
        )
    )
    policies.update(
        set_policy(
            name="s3",
            user="nimda",
            scope="system",
            action="read",
            active=True,
        )
    )
    with patch(
        "linotp.lib.policy.processing.get_policies"
    ) as mock_get_policies:
        mock_get_policies.return_value = policies
        assert is_authorized(
            NIMDA, scope="system", action="read"
        ), "Nimda should be authorized by the exact matching policy"
        assert not is_authorized(
            ADMIN, scope="system", action="read"
        ), "Admin should not be authorized due to no matching policies"
        assert not is_authorized(
            NIMDA, scope="system", action="write"
        ), "Nimda should not be authorized due to no matching policies"
        assert not is_authorized(
            ADMIN, scope="system", action="write"
        ), "Admin should not be authorized due to no matching policies"


def test_inactive_specific_policy(app):
    """
    Check that an inactive specific policy is not evaluated.
    """

    policies = {}
    policies.update(
        set_policy(
            name="s1", user="*", scope="system", action="read", active=True
        )
    )
    policies.update(
        set_policy(
            name="s2",
            user="admin",
            scope="system",
            action="read, write",
            active=True,
        )
    )
    policies.update(
        set_policy(
            name="s3",
            user="nimda",
            scope="system",
            action="write",
            active=False,
        )
    )
    with patch(
        "linotp.lib.policy.processing.get_policies"
    ) as mock_get_policies:
        mock_get_policies.return_value = policies
        assert is_authorized(NIMDA, scope="system", action="read"), (
            "Nimda should be authorized to read as there as there is a "
            "matching active wildcard policy"
        )
        assert is_authorized(
            ADMIN, scope="system", action="read"
        ), "Admin should be authorized to read as there is a matching active policy"
        assert not is_authorized(NIMDA, scope="system", action="write"), (
            "Nimda should not be authorized to write as there are no matching "
            "active policies"
        )
        assert is_authorized(
            ADMIN, scope="system", action="write"
        ), "Admin should be authorized to write as there is a matching active policy"


def test_only_inactive_policies_in_scope(app):
    """
    Check authorization for a scope when all policies for that scope are
    inactive.

    Compared to the previous test, disabling the remaining one active policy
    that is specific to user ADMIN will return this scope to bootstrap mode.
    This means that NIMDA will have all permissions in the scope again.
    """
    policies = {}
    policies.update(
        set_policy(
            name="s1", user="*", scope="system", action="read", active=False
        )
    )
    policies.update(
        set_policy(
            name="s2",
            user="admin",
            scope="system",
            action="read, write",
            active=False,
        )
    )
    policies.update(
        set_policy(
            name="s3",
            user="nimda",
            scope="system",
            action="read",
            active=False,
        )
    )
    with patch(
        "linotp.lib.policy.processing.get_policies"
    ) as mock_get_policies:
        mock_get_policies.return_value = policies
        assert is_authorized(ADMIN, scope="system", action="read"), (
            "Admin should be authorized to read as all policies in scope are "
            "inactive"
        )
        assert is_authorized(NIMDA, scope="system", action="read"), (
            "Nimda should be authorized to read as all policies in scope are "
            "inactive"
        )
        assert is_authorized(ADMIN, scope="system", action="write"), (
            "Admin should be authorized to write as all policies in scope are "
            "inactive"
        )
        assert is_authorized(NIMDA, scope="system", action="write"), (
            "Nimda should be authorized to write as all policies in scope are "
            "inactive"
        )


def test_scope_independence(app):
    """
    Check that a scope without any policies is still in bootstrap mode if
    another scope has active policies.
    """

    policies = {}
    policies.update(
        set_policy(
            name="a1",
            user="admin",
            scope="audit",
            action="view",
            active=True,
        )
    )

    with patch(
        "linotp.lib.policy.processing.get_policies"
    ) as mock_get_policies:
        mock_get_policies.return_value = policies
        assert is_authorized(
            ADMIN, scope="audit", action="view"
        ), "Admin should be authorized to view audit due to matching policy"
        assert not is_authorized(NIMDA, scope="audit", action="view"), (
            "Nimda should not be authorized to view audit due to no matching "
            "policies"
        )
        assert is_authorized(
            ADMIN, scope="system", action="read"
        ), "Admin should be authorized to read system due to bootstrap mode"
        assert is_authorized(
            ADMIN, scope="system", action="write"
        ), "Admin should be authorized to read system due to bootstrap mode"
        assert is_authorized(
            NIMDA, scope="system", action="read"
        ), "Nimda should be authorized to read system due to bootstrap mode"
        assert is_authorized(
            NIMDA, scope="system", action="write"
        ), "Nimda should be authorized to read system due to bootstrap mode"


def test_scope_independence_with_inactive_policies(app):
    """
    Check that a scope with only inactive policies is still in bootstrap mode if
    another scope has active policies.
    """

    policies = {}
    policies.update(
        set_policy(
            name="a1",
            user="admin",
            scope="audit",
            action="view",
            active=True,
        )
    )
    policies.update(
        set_policy(
            name="s1",
            user="admin",
            scope="system",
            action="read",
            active=False,
        )
    )
    with patch(
        "linotp.lib.policy.processing.get_policies"
    ) as mock_get_policies:
        mock_get_policies.return_value = policies
        assert is_authorized(
            ADMIN, scope="audit", action="view"
        ), "Admin should be authorized to view audit due to matching policy"
        assert not is_authorized(NIMDA, scope="audit", action="view"), (
            "Nimda should not be authorized to view audit due to no matching "
            "policies"
        )
        assert is_authorized(
            ADMIN, scope="system", action="read"
        ), "Admin should be authorized to read system due to bootstrap mode"
        assert is_authorized(
            ADMIN, scope="system", action="write"
        ), "Admin should be authorized to read system due to bootstrap mode"
        assert is_authorized(
            NIMDA, scope="system", action="read"
        ), "Nimda should be authorized to read system due to bootstrap mode"
        assert is_authorized(
            NIMDA, scope="system", action="write"
        ), "Nimda should be authorized to read system due to bootstrap mode"


# eof #

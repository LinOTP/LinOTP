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

"""
Tests for CLI help behavior without app initialization
"""

import sys
from unittest.mock import MagicMock, patch

import pytest

from linotp.cli import LinOTPGroup


@pytest.mark.parametrize(
    "argv,should_use_minimal_app",
    [
        (["linotp", "--help"], True),
        (["linotp", "config", "--help"], True),
        (["linotp", "local-admins", "--help"], True),
        (["linotp", "config", "show"], False),
        (["linotp", "local-admins"], False),
        (["linotp", "init", "database"], False),
    ],
)
def test_help_flag_detection(argv, should_use_minimal_app):
    """Test that LinOTPGroup detects --help flag correctly"""
    with patch.object(sys, "argv", argv):
        # Create a mock create_app function
        mock_create_app = MagicMock(return_value=MagicMock())

        # Initialize LinOTPGroup
        group = LinOTPGroup(
            name="linotp",
            create_app=mock_create_app,
        )

        if should_use_minimal_app:
            # When --help is present, create_app should be replaced
            # with minimal_app, not the original mock
            assert group.create_app != mock_create_app
            assert group.create_app.__name__ == "minimal_app"
        else:
            # When --help is not present, create_app should be the original
            assert group.create_app == mock_create_app

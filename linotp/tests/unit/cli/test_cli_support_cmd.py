# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
"""LinOTP test for `linotp support` command group."""

import json
import os
from datetime import datetime

import pytest
from freezegun import freeze_time

from linotp.cli import main as cli_main
from linotp.tests import TestController


@pytest.fixture
def runner(app):
    return app.test_cli_runner(mix_stderr=False)


def test_invalid_support_file(app, runner):
    """Test the set of an expired license file and get of the support info."""

    support_file = os.path.join(TestController.fixture_path, "expired-lic.pem")

    result = runner.invoke(cli_main, ["support", "verify", "-f", support_file])
    assert result.exit_code == 2
    assert "Invalid License: expired" in result.stderr

    result = runner.invoke(cli_main, ["support", "set", support_file])
    assert result.exit_code == 2
    assert (
        "Failed to set license! expired - valid till '2017-12-12'"
    ) in result.stderr

    result = runner.invoke(cli_main, ["support", "get"])
    assert result.exit_code == 2
    assert "No support license installed" in result.stderr

    result = runner.invoke(cli_main, ["support", "verify"])
    assert result.exit_code == 2
    assert "Support not available" in result.stderr


def test_expired_support_file(app, runner):
    """Test the set of a valid license file and get of the support info."""

    support_file = os.path.join(TestController.fixture_path, "expired-lic.pem")

    license_valid_date = datetime(year=2017, month=11, day=16)

    with freeze_time(license_valid_date):
        result = runner.invoke(cli_main, ["support", "set", support_file])
        assert result.exit_code == 0
        assert "Successfully set license." in result.stderr

    result = runner.invoke(cli_main, ["support", "get"])
    assert result.exit_code == 0

    # verify that the output is json parseable
    jres = json.loads(result.stdout)
    assert "licensee" in jres
    assert jres["expire"] == "2017-12-12"

    result = runner.invoke(cli_main, ["support", "verify"])
    assert result.exit_code == 2
    assert "Invalid License: expired" in result.stderr


def test_valid_support_file(app, runner):
    """Test setting a valid license file and getting the support info."""

    support_file = os.path.join(TestController.fixture_path, "expired-lic.pem")

    license_valid_date = datetime(year=2017, month=11, day=16)

    with freeze_time(license_valid_date):
        result = runner.invoke(cli_main, ["support", "set", support_file])
        assert result.exit_code == 0
        assert "Successfully set license." in result.stderr

        result = runner.invoke(cli_main, ["support", "get"])
        assert result.exit_code == 0

        # verify that the output is json parseable
        jres = json.loads(result.stdout)
        assert jres["expire"] == "2017-12-12"

        result = runner.invoke(cli_main, ["support", "verify"])
        assert result.exit_code == 0
        assert "True" in result.stdout


def test_demo_support_file(app, runner):
    """Test setting a valid license file and getting the support info."""

    support_file = os.path.join(TestController.fixture_path, "demo-lic.pem")

    license_valid_date = datetime(year=2017, month=11, day=16)

    result = runner.invoke(cli_main, ["support", "verify", "-f", support_file])
    assert result.exit_code == 0
    assert "True" in result.stdout

    with freeze_time(license_valid_date):
        result = runner.invoke(cli_main, ["support", "set", support_file])
        assert result.exit_code == 0
        assert "Successfully set license." in result.stderr

        result = runner.invoke(cli_main, ["support", "get"])
        assert result.exit_code == 0

        # verify that the expiration date is in 14 days
        jres = json.loads(result.stdout)
        assert jres["expire"] == "2017-11-30"

        result = runner.invoke(cli_main, ["support", "verify"])
        assert result.exit_code == 0
        assert "True" in result.stdout

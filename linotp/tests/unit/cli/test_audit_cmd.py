# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2019 KeyIdentity GmbH
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

import pytest

from linotp.cli import main as cli_main

# -------------------------------------------------------------------------- --

AUDIT_AMOUNT_ENTRIES = 100


@pytest.fixture
def setup_audit_table(app):
    """Add AUDIT_AMOUNT_ENTRIES entries into the fresh audit database"""

    entry = {
        "action": "validate/check",
    }
    for _ in range(AUDIT_AMOUNT_ENTRIES):
        app.audit_obj.log_entry(entry)


@pytest.fixture
def export_dir(tmp_path):
    """Generate temporary export directory"""
    d = tmp_path / "export"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def runner(app, tmp_path):
    """Creates a testing instance of the flask cli runner class"""
    return app.test_cli_runner(mix_stderr=False)


def test_run_janitor(app, runner, setup_audit_table):
    """Run janitor with default values

    By default the max-entries value is 10000 and the min-entries value is
    5000.
    """

    # run linotp audit-janitor
    result = runner.invoke(cli_main, ["audit", "cleanup"])
    assert result.exit_code == 0


def test_run_janitor_with_params(app, runner, setup_audit_table, export_dir):
    """Run janitor with different max, min and export directory

    Max = 10, Min = 5. Prepared Database with AUDIT_AMOUNT_ENTRIES entries.
    5 entries left and AUDIT_AMOUNT_ENTRIES - min exported.
    """
    max = 10
    min = 5

    # run linotp audit-janitor --max 10 --min 5
    result = runner.invoke(
        cli_main,
        [
            "audit",
            "cleanup",
            "--max",
            max,
            "--min",
            min,
            "--exportdir",
            str(export_dir),
        ],
    )
    assert result.exit_code == 0

    list_of_files = export_dir.glob("*")
    export_file = None
    for f in list_of_files:
        if "SQLData" in str(f):
            export_file = export_dir / f
            break

    assert export_file is not None
    num_lines = sum(1 for line in export_file.open())
    assert num_lines == AUDIT_AMOUNT_ENTRIES - min


def test_run_janitor_max_min(app, runner, setup_audit_table):
    """Run janitor with max not greater than min"""
    max = 5
    min = 5
    # run linotp audit-janitor
    result = runner.invoke(
        cli_main,
        [
            "audit",
            "cleanup",
            "--max",
            max,
            "--min",
            min,
        ],
    )
    assert result.exit_code == 1

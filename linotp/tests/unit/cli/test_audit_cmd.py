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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

from datetime import datetime
from pathlib import Path
from typing import List

import pytest
from freezegun.api import FrozenDateTimeFactory

from flask.testing import FlaskCliRunner

from linotp.app import LinOTPApp
from linotp.cli import main as cli_main
from linotp.lib.audit.SQLAudit import AuditTable
from linotp.model import db

# -------------------------------------------------------------------------- --

AUDIT_AMOUNT_ENTRIES = 100


@pytest.fixture
def setup_audit_table(app: LinOTPApp):
    """Add AUDIT_AMOUNT_ENTRIES entries into the fresh audit database"""

    entry = {
        "action": "validate/check",
    }
    for _ in range(AUDIT_AMOUNT_ENTRIES):
        app.audit_obj.log_entry(entry)


@pytest.fixture
def export_dir(tmp_path: Path) -> Path:
    """Generate temporary export directory"""
    d = tmp_path / "export"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def runner(app: LinOTPApp) -> FlaskCliRunner:
    """Creates a testing instance of the flask cli runner class"""
    return app.test_cli_runner(mix_stderr=False)


@pytest.mark.parametrize(
    "options,deleted,remaining,cleaned",
    [
        (
            ["--max", 10, "--min", 5],
            AUDIT_AMOUNT_ENTRIES - 5,
            5,
            True,
        ),
        (
            ["--max", AUDIT_AMOUNT_ENTRIES, "--min", 5],
            0,
            AUDIT_AMOUNT_ENTRIES,
            False,
        ),
        (
            ["--max", AUDIT_AMOUNT_ENTRIES - 1, "--min", 0],
            AUDIT_AMOUNT_ENTRIES,
            0,
            True,
        ),
        (
            [
                "--max",
                AUDIT_AMOUNT_ENTRIES - 1,
                "--min",
                AUDIT_AMOUNT_ENTRIES - 1,
            ],
            1,
            AUDIT_AMOUNT_ENTRIES - 1,
            True,
        ),
        (
            [],
            0,
            AUDIT_AMOUNT_ENTRIES,
            False,
        ),
    ],
)
def test_audit_cleanup_parameters(
    app: LinOTPApp,
    runner: FlaskCliRunner,
    setup_audit_table: None,
    freezer: FrozenDateTimeFactory,
    options: List,
    deleted: int,
    remaining: int,
    cleaned: bool,
):
    """Run audit cleanup with different max and min values"""

    freezer.move_to("2020-01-01 09:50:00")
    formated_time = datetime.now().strftime(
        app.config["BACKUP_FILE_TIME_FORMAT"]
    )

    # Set BACKUP_DIR to `./backup` (instead of creating `/var/linotp/backup`)
    app.config["BACKUP_DIR"] = "backup"

    result = runner.invoke(cli_main, ["-vv", "audit", "cleanup"] + options)

    assert result.exit_code == 0

    filename = f"SQLAuditExport.{formated_time}.{deleted}.csv"
    export_file = Path(app.config["BACKUP_DIR"]) / filename
    if cleaned:
        num_lines = sum(1 for _ in export_file.open())
        # expected: Number of deleted lines + header row
        assert num_lines == deleted + 1
        assert f"{remaining} entries left in database" in result.stderr
        assert f"Exported into {export_file}" in result.stderr
    else:
        assert not export_file.is_file()
        assert f"{remaining} entries in database" in result.stderr
        assert "Exported" not in result.stderr

    assert db.session.query(AuditTable).count() == remaining


def test_audit_cleanup_disabled_export(
    app: LinOTPApp,
    runner: FlaskCliRunner,
    freezer: FrozenDateTimeFactory,
    export_dir: Path,
    setup_audit_table: None,
):
    freezer.move_to("2020-01-01 09:50:00")
    formated_time = datetime.now().strftime(
        app.config["BACKUP_FILE_TIME_FORMAT"]
    )

    runner.invoke(
        cli_main,
        [
            "-vv",
            "audit",
            "cleanup",
            "--max",
            "10",
            "--min",
            "10",
            "--no-export",
            "--exportdir",
            str(export_dir),
        ],
    )

    deleted = AUDIT_AMOUNT_ENTRIES - 10

    filename = f"SQLAuditExport.{formated_time}.{deleted}.csv"
    export_file_backup_dir = Path(app.config["BACKUP_DIR"]) / filename

    assert not export_file_backup_dir.is_file()
    assert len(list(export_dir.iterdir())) == 0


def test_audit_cleanup_custom_export_dir(
    app: LinOTPApp,
    runner: FlaskCliRunner,
    freezer: FrozenDateTimeFactory,
    export_dir: Path,
    setup_audit_table: None,
):
    freezer.move_to("2020-01-01 09:50:00")
    formated_time = datetime.now().strftime(
        app.config["BACKUP_FILE_TIME_FORMAT"]
    )

    runner.invoke(
        cli_main,
        [
            "-vvv",
            "audit",
            "cleanup",
            "--max",
            "10",
            "--min",
            "10",
            "--exportdir",
            str(export_dir),
        ],
    )

    deleted = AUDIT_AMOUNT_ENTRIES - 10

    filename = f"SQLAuditExport.{formated_time}.{deleted}.csv"
    export_file_backup_dir = Path(app.config["BACKUP_DIR"]) / filename
    export_file_export_dir = export_dir / filename

    assert not export_file_backup_dir.is_file()
    assert export_file_export_dir.is_file()

    num_lines = sum(1 for _ in export_file_export_dir.open())
    # expected: Number of deleted lines + header row
    assert num_lines == deleted + 1


def test_run_janitor_max_min(runner: FlaskCliRunner, setup_audit_table: None):
    """Run janitor with min greater than max"""
    max = 5
    min = 6
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
    assert (
        "Error: --max must be greater than or equal to --min" in result.stderr
    )

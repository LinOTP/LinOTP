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

from datetime import datetime, timedelta, timezone
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
FREEZE_DATE = datetime(2020, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def setup_audit_table(app: LinOTPApp, freezer: FrozenDateTimeFactory):
    """
    Add AUDIT_AMOUNT_ENTRIES entries into the fresh audit database.
    One entry per day until (but excluding) `FREEZE_DATE`.
    """

    entry = {
        "action": "validate/check",
    }

    start_date = FREEZE_DATE - timedelta(days=AUDIT_AMOUNT_ENTRIES)
    for i in range(AUDIT_AMOUNT_ENTRIES):
        current_date = start_date + timedelta(days=i)
        freezer.move_to(current_date)
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
    "options,deleted,remaining,cleaned,exit_code,partial_err_msg",
    [
        (
            [
                "--cleanup-threshold",
                10,
                "--max-entries-to-keep",
                5,
                "--export",
            ],
            AUDIT_AMOUNT_ENTRIES - 5,
            5,
            True,
            0,
            "",
        ),
        (
            [
                "--cleanup-threshold",
                AUDIT_AMOUNT_ENTRIES,
                "--max-entries-to-keep",
                5,
                "--export",
            ],
            0,
            AUDIT_AMOUNT_ENTRIES,
            False,
            0,
            f"{AUDIT_AMOUNT_ENTRIES} entries in database",
        ),
        (
            [
                "--cleanup-threshold",
                AUDIT_AMOUNT_ENTRIES - 1,
                "--max-entries-to-keep",
                0,
                "--export",
            ],
            AUDIT_AMOUNT_ENTRIES,
            0,
            True,
            0,
            "",
        ),
        (
            [
                "--cleanup-threshold",
                AUDIT_AMOUNT_ENTRIES - 1,
                "--max-entries-to-keep",
                AUDIT_AMOUNT_ENTRIES - 1,
                "--export",
            ],
            1,
            AUDIT_AMOUNT_ENTRIES - 1,
            True,
            0,
            "",
        ),
        (
            ["--max-entries-to-keep", AUDIT_AMOUNT_ENTRIES - 1, "--export"],
            1,
            AUDIT_AMOUNT_ENTRIES - 1,
            True,
            0,
            "",
        ),
        (
            [],
            0,
            AUDIT_AMOUNT_ENTRIES,
            False,
            0,
            "0 entries in database",
        ),
        (
            [
                "--max-entries-to-keep",
                AUDIT_AMOUNT_ENTRIES,
                "--export",
                "--delete-after-days",
                "1",
            ],
            0,
            AUDIT_AMOUNT_ENTRIES,
            False,
            1,
            "`--delete-after-days` can not be used alongside",
        ),
        (
            [
                "--delete-after-days",
                "0",
            ],
            AUDIT_AMOUNT_ENTRIES,
            0,
            False,
            0,
            "",
        ),
        (
            [
                "--delete-after-days",
                "1",
            ],
            AUDIT_AMOUNT_ENTRIES - 1,
            1,
            False,
            0,
            "",
        ),
        (
            [
                "--delete-after-days",
                "99",
            ],
            1,
            AUDIT_AMOUNT_ENTRIES - 1,
            False,
            0,
            "",
        ),
        (
            [
                "--delete-after-days",
                "100",
            ],
            0,
            AUDIT_AMOUNT_ENTRIES,
            False,
            0,
            "",
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
    exit_code: int,
    partial_err_msg: str,
):
    """Run audit cleanup with different `cleanup-threshold` and `max-entries-to-keep` values"""

    freezer.move_to(FREEZE_DATE)
    formated_time = datetime.now().strftime(
        app.config["BACKUP_FILE_TIME_FORMAT"]
    )

    result = runner.invoke(cli_main, ["-vv", "audit", "cleanup"] + options)

    assert result.exit_code == exit_code

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
        assert partial_err_msg in result.stderr
        assert "Exported" not in result.stderr

    assert db.session.query(AuditTable).count() == remaining


def test_audit_cleanup_disabled_export(
    app: LinOTPApp,
    runner: FlaskCliRunner,
    freezer: FrozenDateTimeFactory,
    export_dir: Path,
    setup_audit_table: None,
):
    freezer.move_to(FREEZE_DATE)
    formated_time = datetime.now().strftime(
        app.config["BACKUP_FILE_TIME_FORMAT"]
    )

    runner.invoke(
        cli_main,
        [
            "-vv",
            "audit",
            "cleanup",
            "--max-entries-to-keep",
            "10",
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
    freezer.move_to(FREEZE_DATE)
    formated_time = datetime.now().strftime(
        app.config["BACKUP_FILE_TIME_FORMAT"]
    )

    runner.invoke(
        cli_main,
        [
            "-vvv",
            "audit",
            "cleanup",
            "--max-entries-to-keep",
            "10",
            "--export",
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


def test_run_janitor_invalid_threshold(
    runner: FlaskCliRunner, setup_audit_table: None
):
    """Run janitor with `cleanup-threshold` smaller than `max-entries-to-keep`"""
    cleanup_threshold = 5
    max_entries_to_keep = cleanup_threshold + 1
    # run `linotp audit cleanup`
    result = runner.invoke(
        cli_main,
        [
            "audit",
            "cleanup",
            "--cleanup-threshold",
            cleanup_threshold,
            "--max-entries-to-keep",
            max_entries_to_keep,
        ],
    )
    assert result.exit_code == 1
    assert (
        "Error: --cleanup-threshold must be greater than or equal to --max-entries-to-keep"
        in result.stderr
    )

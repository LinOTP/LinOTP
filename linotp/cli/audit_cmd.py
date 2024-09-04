#!/usr/bin/env python3
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

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import click
from sqlalchemy import desc
from sqlalchemy.sql.functions import count, max, min

from flask import current_app
from flask.cli import AppGroup, with_appcontext

from linotp.lib.audit.SQLAudit import AuditTable
from linotp.model import db

from . import get_backup_filename

# -------------------------------------------------------------------------- --

# audit commands: cleanup (more commands to come ...)

audit_cmds = AppGroup("audit", help="Manage audit options")


@audit_cmds.command(
    "cleanup",
    help=(
        "Reduce the number of audit log entries in the database.\n\n"
        "If more than --max-entries-to-keep entries are in the audit table, "
        "older entries will be deleted so that only --max-entries-to-keep "
        "entries remain in the table."
    ),
)
@click.option(
    "--max-entries-to-keep",
    "max_entries_to_keep",
    type=int,
    help=(
        "The maximum number of entries to keep if cleanup is triggered. "
        "Defaults to 5,000."
    ),
)
@click.option(
    "--cleanup-threshold",
    "cleanup_threshold",
    type=int,
    help=(
        "Specify the maximum number of entries in the database that triggers the cleanup process. "
        "When the number of entries exceeds this threshold, the cleanup process is initiated. "
        "This value must be greater than or equal to the value specified for --max-entries-to-keep. "
        "If you do not want to directly reach the limit again, set it to a lower number than --max-entries-to-keep. "
        "This is especially usefull for cronjobs triggering an export. In this case, setting --cleanup-threshold "
        "to e.g. twice the amount of --max-entries-to-keep will drastically reduce the number of backup-files. "
        "Defaults to the value of --max-entries-to-keep."
    ),
)
@click.option(
    "--delete-after-days",
    "delete_after_days",
    type=int,
    help=(
        "Delete entries older than the given number of days (starting from the beginning of the day). "
        "Can't be used alongside `--max-entries-to-keep` or `--cleanup-threshold`!"
    ),
)
@click.option(
    "--export",
    is_flag=True,
    help="Write a backup file for the deleted audit lines.",
)
@click.option(
    "--exportdir",
    "-e",
    type=click.Path(exists=True, dir_okay=True),
    help=(
        "Defines the directory where the audit entries which "
        "are cleaned up are exported into. The backup file named "
        "”SQLAuditExport.{now_time}.{highest_exported_id}.csv” "
        "will be saved there.\n\nDefaults to the BACKUP_DIR "
        "configured for LinOTP."
    ),
)
@with_appcontext
def cleanup_command(
    max_entries_to_keep: Optional[int],
    cleanup_threshold: Optional[int],
    delete_after_days: Optional[int],
    export: bool,
    exportdir: Optional[str],
):
    """This function removes old entries from the audit table.

    If more than `max_entries_to_keep` entries are in the audit table, older entries
    will be deleted so that only `max_entries_to_keep` entries remain in the table.
    Cleanup is only triggered if the number of entries is greater than `cleanup_threshold`.
    """

    app = current_app

    if delete_after_days is not None and (
        cleanup_threshold or max_entries_to_keep
    ):
        app.echo(
            "`--delete-after-days` can not be used alongside `--max-entries-to-keep` or `--cleanup-threshold`"
        )
        sys.exit(1)

    if delete_after_days is None:
        if max_entries_to_keep is None:
            max_entries_to_keep = 5000

        if cleanup_threshold is None:
            cleanup_threshold = max_entries_to_keep

        if not (0 <= max_entries_to_keep <= cleanup_threshold):
            app.echo(
                "Error: --cleanup-threshold must be greater than or equal to --max-entries-to-keep."
            )
            sys.exit(1)

    try:
        if export:
            export_path = Path(exportdir or current_app.config["BACKUP_DIR"])
            export_path.mkdir(parents=True, exist_ok=True)
        else:
            export_path = None

        sqljanitor = SQLJanitor(export_dir=export_path)

        cleanup_infos = sqljanitor.cleanup(
            cleanup_threshold, max_entries_to_keep, delete_after_days
        )

        entries_in_audit = cleanup_infos["entries_in_audit"]
        app.echo(f"{entries_in_audit} entries found in database.", v=1)

        entries_deleted = cleanup_infos["entries_deleted"]
        if entries_deleted > 0:
            app.echo(
                f"{entries_deleted} entries cleaned up.\n"
                f"{entries_in_audit - entries_deleted} entries left in database."
            )

            if cleanup_infos["export_filename"]:
                app.echo(f'Exported into {cleanup_infos["export_filename"]}')
            else:
                app.echo("No export was triggered.")

            app.echo(
                f'Cleaning up took {cleanup_infos["time_taken"]} seconds', v=1
            )
        else:
            app.echo(
                f'Nothing cleaned up. {cleanup_infos["entries_in_audit"]} '
                "entries in database.\n"
            )

        app.echo(
            f"Called with --max-entries-to-keep: {max_entries_to_keep}, --cleanup-threshold: {cleanup_threshold}, --delete-after-days: {delete_after_days}.",
            v=1,
        )

    except Exception as exx:
        app.echo(f"Error while cleanup up audit table: {exx!s}")
        sys.exit(1)


class SQLJanitor:
    """
    script to help the house keeping of audit entries
    """

    def __init__(self, export_dir: Optional[Path] = None):
        self.export_dir = export_dir

        self.app = current_app

    def export_data(self, export_up_to) -> Optional[Path]:
        """
        export each audit row into a csv output

        :param export_up_to: all entries up to this id will be dumped
        :return: filepath of exported data or None if no export done
        """

        if not self.export_dir:
            self.app.echo(
                "No export directory defined, skipping backup.",
                v=1,
            )
            return None

        filename_template = f"SQLAuditExport.%s.{export_up_to}.csv"
        export_file = self.export_dir / get_backup_filename(filename_template)
        with export_file.open("w") as f:
            result = (
                db.session.query(AuditTable)
                .filter(AuditTable.id <= export_up_to)
                .order_by(desc(AuditTable.id))
                .all()
            )

            # write the csv header
            audit_columns = AuditTable.__table__.columns
            csv_header = "; ".join([column.name for column in audit_columns])
            f.write(csv_header)
            f.write("\n")

            for audit_row in result:
                row_data = []
                for column in audit_columns:
                    val = getattr(audit_row, column.name)
                    if isinstance(val, int):
                        row_data.append("%d" % val)
                    elif isinstance(val, str):
                        row_data.append('"%s"' % val)
                    elif val is None:
                        row_data.append("")
                    else:
                        row_data.append("?")
                        self.app.echo(
                            "exporting of unknown data / data type %r" % val,
                            v=1,
                        )
                f.write("; ".join(row_data))
                f.write("\n")

        return export_file

    def cleanup(
        self,
        cleanup_threshold,
        max_entries_to_keep,
        delete_after_days: Optional[int] = None,
    ):
        """
        identify the audit data and delete them

        :param cleanup_threshold: the maximum amount of data.
            cleanup is triggered if the number of entries exceed `cleanup_threshold`.
        :param max_entries_to_keep: the minimum amount of data that should not be deleted
        :param delete_after_days: Delete entries older than the given number of days (starting from the beginning of the day).
            Can't be used alongside `cleanup_threshold` or `max_entries_to_keep`.

        :return: cleanup_infos - {
            'cleaned': False,
            'entries_in_audit': 0,
            'entries_deleted': 0,
            'export_filename' : None,
            'first_entry_id': 0,
            'last_entry_id': 0,
            'time_taken': 0,
            } -
        """

        cleanup_infos = {
            "cleaned": False,
            "entries_in_audit": 0,
            "entries_deleted": 0,
            "export_filename": None,
            "first_entry_id": 0,
            "last_entry_id": 0,
            "time_taken": 0,
        }

        start_time = datetime.now(timezone.utc)

        if delete_after_days is not None and (
            cleanup_threshold or max_entries_to_keep
        ):
            raise ValueError(
                "param `delete_after_days` can not be used alongside `cleanup_threshold` and `max_entries_to_keep`"
            )

        total = int(db.session.query(count(AuditTable.id)).scalar())
        cleanup_infos["entries_in_audit"] = total
        first_id = db.session.query(min(AuditTable.id)).scalar()
        cleanup_infos["first_entry_id"] = first_id
        last_id = db.session.query(max(AuditTable.id)).scalar()
        cleanup_infos["last_entry_id"] = last_id

        if delete_after_days is not None:
            start_of_day = datetime(
                start_time.year,
                start_time.month,
                start_time.day,
                tzinfo=timezone.utc,
            )
            cutoff_date = start_of_day - timedelta(days=delete_after_days)
            cutoff_iso = cutoff_date.isoformat(timespec="milliseconds")
            # Query for the highest ID that is older than the cutoff date
            delete_from = (
                db.session.query(max(AuditTable.id))
                .filter(AuditTable.timestamp < cutoff_iso)
                .scalar()
                or 0
            )
        elif total > cleanup_threshold:
            delete_from = last_id - max_entries_to_keep
        else:
            delete_from = 0

        if delete_from > 0:
            # if export is enabled, we start the export now
            export_file = self.export_data(delete_from)
            cleanup_infos["export_filename"] = (
                str(export_file) if export_file else None
            )

            result = (
                db.session.query(AuditTable)
                .filter(AuditTable.id <= delete_from)
                .delete()
            )

            db.session.commit()

            cleanup_infos["entries_deleted"] = result
            cleanup_infos["cleaned"] = True

        end_time = datetime.now(timezone.utc)

        duration = end_time - start_time
        cleanup_infos["time_taken"] = duration.seconds

        return cleanup_infos

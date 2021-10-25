#!/usr/bin/env python3
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

""" This is a janitor program, that cleans up the audit log.

    If the audit entries exceed the linotpAudit.sql.highwatermark
    the tool will delete old entries and only leave the
       linotpAudit.sql.lowwatermark entries

    14-09-02: added ability to dump the 'to be deleted audit data' into a
              directory. This could be defined by 2 new linotp config
              entries:

            - linotpAudit.janitor.dir = /tmp

              the dumpfile is extend with date and the biggest id of the
              to be deleted data eg:     SQLData.2014.9.2-22382.csv

            - linotpAudit.janitor.logdir = /var/log/linotp/
"""

import datetime
import sys
from pathlib import Path
from typing import Optional

import click
from sqlalchemy import asc, desc
from sqlalchemy.sql.functions import count

from flask import current_app
from flask.cli import AppGroup, with_appcontext

from linotp.lib.audit.SQLAudit import AuditTable
from linotp.model import db

from . import get_backup_filename

# -------------------------------------------------------------------------- --

# audit commands: cleanup (more commands to come ...)

audit_cmds = AppGroup("audit")


@audit_cmds.command(
    "cleanup",
    help=(
        "Reduce the number of audit log entries in the database.\n\n"
        "If more than --max entries are in the audit table, older "
        "entries will be deleted so that only --min entries remain "
        "in the table. Set --min and --max to the same value to "
        "delete only those entries that exceed the maximum number "
        "(--max) of entries allowed"
    ),
)
@click.option(
    "--max",
    "maximum",
    default=10000,
    help=(
        "The maximum number of entries that may be in the database"
        "before entries are deleted. Defaults to 10,000."
    ),
)
@click.option(
    "--min",
    "minimum",
    default=5000,
    help=(
        "The number of entries that should remain in the database if "
        "data is cleaned up. You need to set a lower number than --max "
        "if you do not want directly reach the limit again. Set it to "
        "the same value as --max to only delete entries that are "
        "exceeding the maximum allowed number of entries. Defaults to "
        "5,000."
    ),
)
@click.option(
    "--no-export",
    is_flag=True,
    help="Do not write a backup file for the deleted audit lines.",
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
    maximum: int, minimum: int, no_export: bool, exportdir: Optional[str]
):
    """This function removes old entries from the audit table.

    If more than max entries are in the audit table, older entries
    will be deleted so that only min entries remain in the table.
    """

    app = current_app
    try:

        if not (0 <= minimum <= maximum):
            app.echo("Error: --max must be greater than or equal to --min.")
            sys.exit(1)

        if no_export:
            export_path = None
        else:
            export_path = Path(exportdir or current_app.config["BACKUP_DIR"])
            export_path.mkdir(parents=True, exist_ok=True)

        sqljanitor = SQLJanitor(export_dir=export_path)

        cleanup_infos = sqljanitor.cleanup(maximum, minimum)

        app.echo(
            f'{cleanup_infos["entries_in_audit"]} entries found in database.',
            v=2,
        )

        if cleanup_infos["entries_deleted"] > 0:
            app.echo(
                f'{cleanup_infos["entries_in_audit"] - minimum} entries '
                f"cleaned up. {minimum} entries left in database.\n"
                f"Min: {minimum}, Max: {maximum}.",
                v=1,
            )

            if cleanup_infos["export_filename"]:
                app.echo(
                    f'Exported into {cleanup_infos["export_filename"]}',
                    v=2,
                )

            app.echo(
                f'Cleaning up took {cleanup_infos["time_taken"]} seconds',
                v=2,
            )
        else:
            app.echo(
                f'Nothing cleaned up. {cleanup_infos["entries_in_audit"]} '
                "entries in database.\n"
                f"Min: {minimum}, Max: {maximum}.",
                v=1,
            )

    except Exception as exx:
        app.echo(f"Error while cleanup up audit table: {exx!s}")
        sys.exit(1)


class SQLJanitor:
    """
    script to help the house keeping of audit entries
    """

    def __init__(self, export_dir: Path = None):

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

                prin = "; ".join(row_data)
                f.write(prin)
                f.write("\n")

        return export_file

    def cleanup(self, max_entries, min_entries):
        """
        identify the audit data and delete them

        :param max_entries: the maximum amount of data
        :param min_entries: the minimum amount of data that should
                            not be deleted

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

        start_time = datetime.datetime.now()

        total = int(db.session.query(count(AuditTable.id)).scalar())
        cleanup_infos["entries_in_audit"] = total
        if total > max_entries:

            first_id = int(
                db.session.query(AuditTable.id)
                .order_by(asc(AuditTable.id))
                .limit(1)
                .scalar()
            )
            cleanup_infos["first_entry_id"] = first_id

            last_id = int(
                db.session.query(AuditTable.id)
                .order_by(desc(AuditTable.id))
                .limit(1)
                .scalar()
            )
            cleanup_infos["last_entry_id"] = last_id

            delete_from = last_id - min_entries
            if delete_from > 0:
                # if export is enabled, we start the export now
                export_file = self.export_data(delete_from)
                cleanup_infos["export_filename"] = str(export_file)

                db.session.query(AuditTable).filter(
                    AuditTable.id <= delete_from
                ).delete()

                db.session.commit()

                cleanup_infos["entries_deleted"] = total - min_entries
                cleanup_infos["cleaned"] = True

        end_time = datetime.datetime.now()

        duration = end_time - start_time
        cleanup_infos["time_taken"] = duration.seconds

        return cleanup_infos

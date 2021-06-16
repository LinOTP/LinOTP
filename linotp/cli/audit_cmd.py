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
import os
import sys

import click
from sqlalchemy import MetaData, Table, asc, desc, func, select

from flask import current_app
from flask.cli import AppGroup, with_appcontext

# -------------------------------------------------------------------------- --

# audit commands: cleanup (more commands to come ...)

audit_cmds = AppGroup("audit")


@audit_cmds.command(
    "cleanup", help="Reduce the amount of audit log entries in the database"
)
@click.option(
    "--max",
    "maximum",
    default=10000,
    help="The maximum entries. If not given 10.000 as default is "
    + "assumed.",
)
@click.option(
    "--min",
    "minimum",
    default=5000,
    help="The minimum old remaining entries. If not given 5.000 "
    + "as default is assumed.",
)
@click.option(
    "--exportdir",
    "-e",
    type=click.Path(exists=True, dir_okay=True),
    help="Defines the directory where the audit entries which "
    + "are cleaned up are exported. A example filename would be: "
    + "SQLData.yeah.month.day-max_id.csv",
)
@with_appcontext
def cleanup_command(maximum, minimum, exportdir):
    """This function removes old entries from the audit table.

    If more than max entries are in the audit table, older entries
    will be deleted so that only min entries remain in the table.
    This tool can decrypt the OTP Key stored in the LinOTP database. You need
    to pass the encrypted key, the IV and the filename of the encryption key.
    """

    app = current_app
    try:

        if not (0 <= minimum < maximum):
            app.echo("Error: max has to be greater than min.")
            sys.exit(1)

        sqljanitor = SQLJanitor(export=exportdir)

        cleanup_infos = sqljanitor.cleanup(maximum, minimum)

        app.echo(
            f'{cleanup_infos["entries_in_audit"]} entries found in database.',
            v=2,
        )

        if cleanup_infos["entries_deleted"] > 0:
            app.echo(
                f'{cleanup_infos["entries_in_audit"] - minimum} entries '
                "cleaned up. {minimum} entries left in database.\n"
                "Min: {minimum}, Max: {maximum}.",
                v=2,
            )

            if cleanup_infos["export_filename"]:
                app.echo(
                    f'Exported into {cleanup_infos["export_filename"]}', v=2
                )

            app.echo(
                f'Cleaning up took {cleanup_infos["time_taken"]} seconds', v=2
            )
        else:
            app.echo(
                f'Nothing cleaned up. {cleanup_infos["entries_in_audit"]} '
                "entries in database.\n"
                "Min: {minimum}, Max: {maximum}.",
                v=2,
            )

    except Exception as exx:
        app.echo(f"Error while cleanup up audit table: {exx!s}")
        sys.exit(1)


class SQLJanitor:
    """
    script to help the house keeping of audit entries
    """

    def __init__(self, export=None):

        self.export_dir = export

        self.app = current_app
        engine = current_app.audit_obj.engine

        engine.echo = False  # We want to see the SQL we're creating
        metadata = MetaData(engine)
        # The audit table already exists, so no need to redefine it. Just
        # load it from the database using the "autoload" feature.
        self.audit = Table("audit", metadata, autoload=True)

    def export_data(self, max_id):
        """
        export each audit row into a csv output

        :param max_id: all entries with lower id will be dumped
        :return: string (filename) if export succeeds, None if export failed
        """

        if not self.export_dir:
            return None

        # create the filename
        t2 = datetime.datetime.now()
        filename = "SQLData.%d.%d.%d-%d.csv" % (
            t2.year,
            t2.month,
            t2.day,
            max_id,
        )

        with open(os.path.join(self.export_dir, filename), "w") as f:
            s = self.audit.select(self.audit.c.id < max_id).order_by(
                desc(self.audit.c.id)
            )
            result = s.execute()

            # write the csv header
            keys = list(result.keys())
            prin = "; ".join(keys)
            f.write(prin)
            f.write("\n")

            for row in result:
                row_data = []
                vals = list(row.values())
                for val in vals:
                    if isinstance(val, int):
                        row_data.append("%d" % val)
                    elif isinstance(val, str):
                        row_data.append('"%s"' % val)
                    elif val is None:
                        row_data.append(" ")
                    else:
                        row_data.append("?")
                        self.app.echo(
                            "exporting of unknown data / data type %r" % val,
                            v=1,
                        )

                prin = "; ".join(row_data)
                f.write(prin)
                f.write("\n")

        return filename

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

        t1 = datetime.datetime.now()
        id_pos = 0
        overall_number = 0

        # TODO: replace with a select between query

        rows = select([func.count()]).select_from(self.audit).execute()
        row = rows.fetchone()
        overall_number = int(row[id_pos])

        cleanup_infos["entries_in_audit"] = overall_number
        if overall_number >= max_entries:

            s = self.audit.select().order_by(asc(self.audit.c.id)).limit(1)
            rows = s.execute()
            first_id = int(rows.fetchone()[id_pos])
            cleanup_infos["first_entry_id"] = first_id

            s = self.audit.select().order_by(desc(self.audit.c.id)).limit(1)
            rows = s.execute()
            last_id = int(rows.fetchone()[id_pos])
            cleanup_infos["last_entry_id"] = last_id

            delete_from = last_id - min_entries
            if delete_from > 0:
                # if export is enabled, we start the export now
                export_filename = self.export_data(delete_from)
                cleanup_infos["export_filename"] = export_filename
                s = self.audit.delete(self.audit.c.id < delete_from)
                s.execute()
                cleanup_infos["entries_deleted"] = overall_number - min_entries
                cleanup_infos["cleaned"] = True

        t2 = datetime.datetime.now()

        duration = t2 - t1
        cleanup_infos["time_taken"] = duration.seconds
        return cleanup_infos

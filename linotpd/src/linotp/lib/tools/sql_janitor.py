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

""" This is a janitor program, that cleans up the audit log
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

import os
import sys
import datetime
import logging
from sqlalchemy import *
from getopt import getopt, GetoptError
import configparser


log = logging.getLogger(__name__)


class SQLJanitor():
    """
    script to help the house keeping of audit entries
    """

    def __init__(self, engine, export=None):

        self.export_dir = export

        engine.echo = False  # We want to see the SQL we're creating
        metadata = MetaData(engine)
        # The audit table already exists, so no need to redefine it. Just
        # load it from the database using the "autoload" feature.
        self.audit = Table('audit', metadata, autoload=True)


    def export_data(self, max_id):
        """
        export each audit row into a csv output

        :param max_id: all entries with lower id will be dumped
        :return: - nothing -
        """

        if not self.export_dir:
            log.info('no export directory defined')
            return

        if not os.path.isdir(self.export_dir):
            log.error('export directory %r not found' % self.export_dir)
            return

        # create the filename
        t2 = datetime.datetime.now()
        filename = "SQLData.%d.%d.%d-%d.csv" % (t2.year, t2.month, t2.day, max_id)

        f = None
        try:
            f = open(os.path.join(self.export_dir, filename), "w")

            s = self.audit.select(self.audit.c.id < max_id).order_by(desc(self.audit.c.id))
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
                    if type(val) in [int, int]:
                        row_data.append("%d" % val)
                    elif type(val) in [str, str]:
                        row_data.append('"%s"' % val)
                    elif val is None:
                        row_data.append(" ")
                    else:
                        row_data.append("?")
                        log.error('exporting of unknown data / data type %r' % val)
                prin = "; ".join(row_data)
                f.write(prin)
                f.write("\n")
        except Exception as exx:
            log.error('failed to export data %r' % exx)
            raise exx
        finally:
            if f:
                f.close()
        return

    def cleanup(self, max_entries, min_entries):
        """
        identify the audit data and delete them

        :param max_entries: the maximum amount of data
        :param min_entries: the minimum amount of data that should not be deleted

        :return: - nothing -
        """
        t1 = datetime.datetime.now()
        id_pos = 0
        overall_number = 0

        rows = select([func.count()]).select_from(self.audit).execute()
        row = rows.fetchone()
        overall_number = int(row[id_pos])


        log.info("Found %i entries in the audit" % overall_number)
        if overall_number >= max_entries:

            log.info("Deleting older entries")
            s = self.audit.select().order_by(asc(self.audit.c.id)).limit(1)
            rows = s.execute()
            first_id = int(rows.fetchone()[id_pos])

            s = self.audit.select().order_by(desc(self.audit.c.id)).limit(1)
            rows = s.execute()
            last_id = int (rows.fetchone()[id_pos])

            log.info("Found ids between %i and %i" % (first_id, last_id))
            delete_from = last_id - min_entries

            if delete_from > 0:
                # if export is enabled, we start the export now
                self.export_data(delete_from)

                log.info("Deleting all IDs less than %i" % delete_from)
                s = self.audit.delete(self.audit.c.id < delete_from)
                s.execute()

            else:
                log.info("Nothing to do. "
                        "There are less entries than the low watermark")

        else:
            log.info("Nothing to be done: %i below high watermark %i" %
                (overall_number, max_entries))


        t2 = datetime.datetime.now()

        duration = t2 - t1
        log.info("Took me %i seconds" % duration.seconds)
        return

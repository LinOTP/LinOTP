# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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

"""
import user tool -
  import a csv file of users

if called from within LinOTP

import linotp.model.meta
Session = linotp.model.meta.Session
Engine = meta.engine

"""
import csv
import json

import logging
from linotp.lib.tools.import_user.ImportHandler import ImportHandler


log = logging.getLogger(__name__)


class FormatReader(object):
    """
    support for special csv formats
    """
    pass


class DefaultFormatReader(FormatReader):

    delimiter = ','
    quotechar = '"'

    @classmethod
    def prepare_row(cls, row):
        return row


class PasswdFormatReader(FormatReader):

    delimiter = ':'
    quotechar = '"'

    @classmethod
    def prepare_row(cls, row):

        if len(row) < 5:
            return row

        ext_row = row[0:4]

        # support for extend password format, which contains email++

        if ',' in row[4]:
            attr = row[4].split(',')
            if len(attr) < 5:
                attr.append("")
        else:
            attr = ',,,,'.split(',')
            attr[0] = row[4]

        # now split the name into surname and lastname

        if ' ' in attr[0]:
            ext_name = attr[0].split(' ', 1)
        else:
            ext_name = (attr[0] + " ").split(' ', 1)

        # finally we concat all

        ext_row.extend(ext_name)
        ext_row.extend(attr[1:])
        ext_row.extend(row[5:])

        return ext_row


class UserImport(object):

    def __init__(self, ImportHandler):

        self.user_column_mapping = {}
        self.import_handler = ImportHandler
        self.encoding = 'UTF-8'

    def set_mapping(self, mapping):
        self.user_column_mapping = mapping

    def get_users_from_data(self, csv_data, format_reader,
                            passwords_in_plaintext=False):
        """
        for each row
        - iterate over all available database columns and
        - check if there is a column for this in the csv data

        and add the group identifier

        """

        reader = csv.reader(csv_data.split('\n'),
                            delimiter=format_reader.delimiter,
                            quotechar=format_reader.quotechar)

        for row in reader:

            if not row:
                continue

            row = format_reader.prepare_row(row)

            user = self.import_handler.User()

            for entry in self.import_handler.User.user_entries:

                value = ""
                column_id = self.user_column_mapping.get(entry, -1)

                if column_id == -1 or column_id >= len(row):
                    continue

                # as the csv converter does not support unicode
                # we have to decode the data

                value = row[column_id].decode(self.encoding)

                user.set(entry, value)

                if entry == 'password' and passwords_in_plaintext:
                    user.creat_password_hash(row[column_id])

            yield user

    def import_csv_users(self, csv_data, dryrun=False,
                         format_reader=DefaultFormatReader,
                         passwords_in_plaintext=False):
        """
        insert and update users

        update of users is done in 2 steps

        0. get a list of all former stored userid
        1. insert all csv data, either update or create
        2. all former entries, which have not been update, will be removed

        """
        users_deleted = {}
        users_created = {}
        users_not_modified = {}
        users_modified = {}

        processed_users = {}

        former_user_by_id = self.import_handler.prepare()

        try:

            # -------------------------------------------------------------- --

            # finally remove all former, not updated users
            # update or insert all user from the csv data

            for user in self.get_users_from_data(
                             csv_data,
                             format_reader,
                             passwords_in_plaintext=passwords_in_plaintext):

                # only store valid users that have a userid and a username
                if not user.userid or not user.username:
                    continue

                # prevent processing user multiple times
                if (user.userid in processed_users.keys() or
                    user.username in processed_users.values()):
                    raise Exception("Violation of unique constraint - "
                                    "duplicate user in data: %r" % user)
                else:
                    processed_users[user.userid] = user.username

                # search for the user

                former_user = self.import_handler.lookup(user)

                # if it does not exist we create a new one

                if not former_user:
                    users_created[user.userid] = user.username
                    if not dryrun:
                        self.import_handler.add(user)

                else:

                    if former_user.userid in former_user_by_id:
                        del former_user_by_id[former_user.userid]

                    if former_user == user:
                        users_not_modified[user.userid] = user.username
                    else:
                        users_modified[user.userid] = user.username
                        if not dryrun:
                            self.import_handler.update(former_user, user)

            # -------------------------------------------------------------- --

            # finally remove all former, not updated users

            for del_userid, del_user_name in former_user_by_id.items():
                users_deleted[del_userid] = del_user_name
                if not dryrun:
                    self.import_handler.delete_by_id(del_userid)

            result = {
                'created': users_created,
                'updated': users_not_modified,
                'modified': users_modified,
                'deleted': users_deleted,
                }

            if not dryrun:
                self.import_handler.commit()

            return result

        except Exception as exx:

            self.import_handler.rollback()
            log.exception(exx)
            raise exx

        finally:
            self.import_handler.close()

# ------------------------------------------------------------------------- --


def main():

    from linotp.lib.tools.import_user.SQLImportHandler import Shell_DatabaseContext
    from linotp.lib.tools.import_user.SQLImportHandler import SQLImportHandler

    # in the test main() we use a password file, which is prepared
    # for splitting the description fields into csv data

    with open("/linotp/def-passwd", "r") as f:
        csv_data = f.read()

    user_column_map = {
            "userid": 2,
            "username": 0,
            "phone": 8,
            "mobile": 7,
            "email": 9,
            "surname": 5,
            "givenname": 4,
            "password": 1}

    sql_url = 'postgres://otpd:linotp2d@localhost/otpdb'
    shell_db_context = Shell_DatabaseContext(sql_url=sql_url)

    import_handler = SQLImportHandler(
                                 groupid="Hello",
                                 resolver_name="TestResolver",
                                 database_context=shell_db_context)

    user_import = UserImport(import_handler)

    user_import.set_mapping(user_column_map)

    result = user_import.import_csv_users(
                                csv_data,
                                format_reader=PasswdFormatReader())

    print(result)

    return

if __name__ == "__main__":

    main()

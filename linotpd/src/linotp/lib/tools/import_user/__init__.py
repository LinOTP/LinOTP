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
import hashlib
import crypt

from os import urandom
import base64

from linotp.lib.tools.import_user.ImportHandler import ImportHandler


class FormatReader(object):
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

    def set_mapping(self, mapping):
        self.user_column_mapping = mapping

    def _encrypt_password(self, password):
        """
        we use crypt type sha512, which is a secure and standard according to:
        http://security.stackexchange.com/questions/20541/\
                         insecure-versions-of-crypt-hashes

        :param password: the plain text password
        :return: the encrypted password
        """

        ctype = '6'
        salt_len = 20

        b_salt = urandom(3 * ((salt_len + 3) // 4))

        # we use base64 charset for salt chars as it is nearly the same
        # charset, if '+' is changed to '.' and the fillchars '=' are
        # striped off

        salt = base64.b64encode(b_salt).strip("=").replace('+', '.')

        # now define the password format by the salt definition

        insalt = '$%s$%s$' % (ctype, salt[0:salt_len])
        encryptedPW = crypt.crypt(password, insalt)

        return encryptedPW

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

                if column_id != -1 and column_id < len(row):
                    value = row[column_id]

                if entry == 'password' and passwords_in_plaintext:
                    value = self._encrypt_password(value)

                user.set(entry, value)

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
        users_deleted = 0
        users_created = 0
        users_updated = 0

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

                # search for the user
                former_user = self.import_handler.lookup(user)

                # if it does not exist we create a new one
                if not former_user:
                    users_created += 1
                    if not dryrun:
                        self.import_handler.add(user)

                else:
                    users_updated += 1

                    if former_user.userid in former_user_by_id:
                        former_user_by_id.remove(former_user.userid)

                    if not dryrun:
                        self.import_handler.update(former_user, user)

            # -------------------------------------------------------------- --

            # finally remove all former, not updated users

            for del_userid in former_user_by_id:
                users_deleted += 1
                if not dryrun:
                    self.import_handler.delete_by_id(del_userid)

            result = {
                'created': users_created,
                'updated': users_updated,
                'deleted': users_deleted}

            self.import_handler.commit()

            return result

        except Exception as exx:

            self.import_handler.rollback()

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

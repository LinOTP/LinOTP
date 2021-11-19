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


from sqlalchemy import schema, types

from linotp.lib.crypto import utils
from linotp.model import db


class SqlUser(db.Model):

    __tablename__ = "imported_user"
    __table_args__ = {
        "mysql_collate": "utf8_unicode_ci",
        "mysql_charset": "utf8",
    }

    groupid = schema.Column(types.Unicode(100), primary_key=True, index=True)

    userid = schema.Column(types.Unicode(100), primary_key=True, index=True)

    username = schema.Column(types.Unicode(255), default="", index=True)

    phone = schema.Column(types.Unicode(100), default="")

    mobile = schema.Column(types.Unicode(100), default="")

    email = schema.Column(types.Unicode(100), default="")

    surname = schema.Column(types.Unicode(100), default="")

    givenname = schema.Column(types.Unicode(100), default="")

    password = schema.Column(types.Unicode(255), default="", index=True)


class ImportedUser(SqlUser):

    user_entries = [
        "userid",
        "username",
        "phone",
        "mobile",
        "email",
        "surname",
        "givenname",
        "password",
        "groupid",
    ]

    def __init__(self):
        self._pw_gen = False

    def update(self, user):
        """
        update all attributes of the user from the other user

        :param user: the other / previous user
        """
        for attr in self.user_entries:
            setattr(self, attr, getattr(user, attr))

    def set(self, entry, value):
        """
        generic setting of attributes of the user

        :param entry: attribute name
        :param value: attribute value
        """

        if entry in self.user_entries:
            setattr(self, entry, value)

    def create_password_hash(self, plain_password: str) -> None:
        """
        create a password hash entry from a given plaintext password
        """
        self.password = utils.crypt_password(plain_password)
        self._pw_gen = True

    def __eq__(self, user):
        """
        compare two users

        :param user: the other user
        :return: bool
        """

        for attr in self.user_entries:

            # special handling for goupe_id, which might not be set at
            # comparing time
            if attr == "groupid":
                continue

            if attr == "password" and user._pw_gen:
                continue

            if not (hasattr(self, attr) and hasattr(user, attr)):
                return False

            if getattr(self, attr) != getattr(user, attr):
                return False

        return True

    def __ne__(self, user):
        """
        compare two users

        :param user: the other user
        :return: bool
        """
        return not (self == user)

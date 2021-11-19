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


from typing import Any, Dict, List

from sqlalchemy import schema, types
from sqlalchemy.orm import Session

from linotp.lib.crypto import utils
from linotp.model import db


class NoSuchUserError(Exception):
    def __init__(
        self, username: str, message: str = "User {0} does not exist"
    ):
        super().__init__(message.format(username))
        self.username = username


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

    def __init__(self, resolver_name: str = None):
        self._pw_gen = False
        self.user_class = SqlUser
        self.session: Session = db.session()
        self.resolver_name = resolver_name

    def _get_user(self, username: str) -> SqlUser:
        user = self.session.query(self.user_class).get(
            (self.resolver_name, username)
        )
        if not user:
            raise NoSuchUserError(username)
        return user

    def _get_keys_of_table(self) -> List[str]:
        tablename = self.user_class.__tablename__
        return self.user_class.metadata.tables[tablename].c.keys()

    def update(self, user: SqlUser) -> None:
        """
        update all attributes of the user from the other user

        :param user: the other / previous user
        """
        for attr in self.user_entries:
            setattr(self, attr, getattr(user, attr))

    def set(self, entry: str, value: Any) -> None:
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

    def list_users(self) -> List[Dict[str, str]]:
        """list all users of an ImportedUser instance

        Returns:
            List[Dict[str, str]]:
                returns a list of an ImportedUser instance
        """
        user_list = (
            self.session.query(self.user_class)
            .filter(self.user_class.groupid == self.resolver_name)
            .all()
        )

        result = []
        for user in user_list:
            single_user = {}
            for attr in self._get_keys_of_table():
                single_user[attr] = getattr(user, attr)
            result.append(single_user)

        return result

    def remove_all_users(self) -> None:
        """removes all users from an ImportedUser instance"""
        all_users = (
            self.session.query(self.user_class)
            .filter(self.user_class.groupid == self.resolver_name)
            .all()
        )

        for user in all_users:
            self.session.delete(user)

    def remove_user(
        self,
        username: str,
    ) -> None:
        """remove one user from an ImportedUser instance

        Args:
            username (str): the name of the user wich should be deleted
        """

        user = self._get_user(username)
        self.session.delete(user)

    def __eq__(self, user: Any) -> bool:
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

    def __ne__(self, user: Any) -> bool:
        """
        compare two users

        :param user: the other user
        :return: bool
        """
        return not (self == user)

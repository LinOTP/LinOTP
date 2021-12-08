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

from sqlalchemy import orm
from sqlalchemy.orm import Session

from linotp.lib.crypto import utils as cryptutils
from linotp.model import db
from linotp.model.schema import ImportedUserSchema


class NoSuchUserError(Exception):
    def __init__(
        self, username: str, message: str = "User {0} does not exist"
    ):
        super().__init__(message.format(username))
        self.username = username


class ImportedUser(ImportedUserSchema):

    user_entries = [name.name for name in ImportedUserSchema.__table__.c]

    @orm.reconstructor
    def __init__(self, resolver_name: str = None):
        self._pw_gen = False
        self.user_class = ImportedUserSchema
        self.session: Session = db.session()
        self.resolver_name = resolver_name
        self.plain_password = None

    def _get_user(self, username: str) -> ImportedUserSchema:
        user = self.session.query(self.user_class).get(
            (self.resolver_name, username)
        )
        if not user:
            raise NoSuchUserError(username)
        return user

    def _get_keys_of_table(self) -> List[str]:
        tablename = self.user_class.__tablename__
        return self.user_class.metadata.tables[tablename].c.keys()

    def update(self, user: ImportedUserSchema) -> None:
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
        return cryptutils.crypt_password(plain_password)

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

            # special handling for because the passwords are hashed
            if attr == "password":
                if self.plain_password and not user.plain_password:
                    same = cryptutils.compare_password(
                        self.plain_password, user.password
                    )
                elif user.plain_password and not self.plain_password:
                    same = cryptutils.compare_password(
                        user.plain_password, self.password
                    )
                elif self.plain_password and user.plain_password:
                    same = self.plain_password == user.plain_password
                else:
                    same = self.password == user.password
                if not same:
                    return False
                else:
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

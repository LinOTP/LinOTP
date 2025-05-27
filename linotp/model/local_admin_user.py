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

from typing import Dict, List

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from linotp.app import LinOTPApp, create_app
from linotp.lib.config import getFromConfig
from linotp.lib.crypto.utils import crypt_password
from linotp.model import db, setup_db
from linotp.model.config import set_config
from linotp.model.imported_user import ImportedUserSchema


class DuplicateUserError(Exception):
    def __init__(self, username: str, message: str = "User {0} already exists"):
        super().__init__(message.format(username))
        self.username = username


class NoSuchUserError(Exception):
    def __init__(self, username: str, message: str = "User {0} does not exist"):
        super().__init__(message.format(username))
        self.username = username


class LocalAdminResolver:
    def __init__(self, app: LinOTPApp) -> None:
        self.user_class = ImportedUserSchema
        self.session: Session = db.session()
        self.admin_resolver_name = app.config["ADMIN_RESOLVER_NAME"]
        self.admin_realm_name = app.config["ADMIN_REALM_NAME"].lower()

    def _get_user(self, username: str) -> ImportedUserSchema:
        user = self.session.query(self.user_class).get(
            (self.admin_resolver_name, username)
        )
        if not user:
            raise NoSuchUserError(username)
        return user

    def add_user(
        self,
        username: str,
        password: str,
        surname: str = "",
        givenname: str = "",
        phone: str = "",
        mobile: str = "",
        email: str = "",
    ) -> None:
        """Create a new admin user in the local admin resolver

        Args:
            username (str):
                username of the new user
            password (str):
                password of the new user
            surname (str, optional):
                surename of the new user.
                Defaults to "".
            givenname (str, optional):
                givename of the new user.
                Defaults to "".
            phone (str, optional):
                phone number of the new user.
                Defaults to "".
            mobile (str, optional):
                mobile number of the new user.
                Defaults to "".
            email (str, optional):
                email of the new user.
                Defaults to "".

        Raises:
            DuplicateUserError:
                raises if a user should be created which already exists
        """
        user = self.user_class(
            userid=username,
            groupid=self.admin_resolver_name,
            username=username,
            password=self._encrypt_password(password) if password else "*",
            surname=surname,
            givenname=givenname,
            phone=phone,
            mobile=mobile,
            email=email,
        )
        try:
            self.session.add(user)
            self.session.commit()
        except IntegrityError:
            raise DuplicateUserError(username)

    def update_user(
        self,
        username: str,
        surname: str = "",
        givenname: str = "",
        phone: str = "",
        mobile: str = "",
        email: str = "",
    ) -> None:
        """Create a new admin user in the local admin resolver

        Args:
            username (str):
                username of the new user
            surname (str, optional):
                surename of the new user.
                Defaults to "".
            givenname (str, optional):
                givename of the new user.
                Defaults to "".
            phone (str, optional):
                phone number of the new user.
                Defaults to "".
            mobile (str, optional):
                mobile number of the new user.
                Defaults to "".
            email (str, optional):
                email of the new user.
                Defaults to "".

        Raises:
            NoSuchUserError:
                raises if a user which should get updated does not exist
        """

        user = self._get_user(username)

        user.surname = surname
        user.givenname = givenname
        user.email = email
        user.email = email
        user.phone = phone
        user.mobile = mobile
        self.session.commit()

    def set_user_password(
        self,
        username: str,
        password: str,
    ) -> None:
        """set the password for a local admin user

        Args:
            username (str):
                the name of the user which should get a new password
            password (str):
                the new password of the user

        Raises:
            UserNotExistException:
                raises if a user which should get updated does not exist
        """
        user = self._get_user(username)
        user.password = self._encrypt_password(password)
        self.session.commit()

    def remove_user(self, username: str) -> None:
        """removes a local admin user

        Args:
            username (str):
                the name of the user which should get removed
        """

        user = self._get_user(username)
        self.session.delete(user)
        self.session.commit()

    def list_users(self) -> List[Dict[str, str]]:
        """list all local admin users

        Returns:
            List[Dict[str, str]]:
                returns a list of all local admin users
        """
        user_list = (
            self.session.query(self.user_class)
            .filter(self.user_class.groupid == self.admin_resolver_name)
            .all()
        )

        result = []
        for user in user_list:
            single_user = {}
            for attr in self._get_keys_of_table():
                single_user[attr] = getattr(user, attr)
            result.append(single_user)

        return result

    def get_user_info(self, username: str) -> Dict[str, str]:
        user = self._get_user(username)
        return {
            attr: getattr(user, attr)
            for attr in self._get_keys_of_table()
            if attr not in ("groupid", "password", "userid", "username")
        }

    def _remove_all_users(self) -> None:
        """Removes all local admin users. This is here in order to make the
        example below not fail if the object created there already
        exists in the database; in the interest of safety, there is no
        intention of making this functionality available in the
        CLI.

        """

        for user in (
            self.session.query(self.user_class)
            .filter(self.user_class.groupid == self.admin_resolver_name)
            .all()
        ):
            self.session.delete(user)
        self.session.commit()

    def _encrypt_password(self, password: str) -> str:
        return crypt_password(password)

    def _get_keys_of_table(self) -> List[str]:
        tablename = self.user_class.__tablename__
        return self.user_class.metadata.tables[tablename].c.keys()

    def add_to_admin_realm(self) -> None:
        """Checks whether the resolver is part of the admin realm and adds it
        if necessary. This may be needed if the user adds a different resolver
        to the admin realm and then removes this one. (This resolver cannot
        be deleted outright, but it can be removed from the admin realm.)

        We assume that the admin realm itself exists already, or, more
        precisely, LinOTP doesn't care if you add a resolver to a realm that
        doesn't exist.

        """

        admin_resolver_name = (
            f"useridresolver.SQLIdResolver.IdResolver.{self.admin_resolver_name}"
        )

        # Check magic config database entry for the list of resolvers
        # in the admin realm.

        admin_resolvers_key = f"useridresolver.group.{self.admin_realm_name}"
        admin_resolvers = getFromConfig(admin_resolvers_key, "")
        if admin_resolvers:  # Avoid splitting an empty string
            for name in admin_resolvers.split(","):
                if name.strip() == admin_resolver_name:
                    return  # Resolver is in realm, we're done here

        # If we get here, the `admin_resolver_name` doesn't occur in
        # the list of resolvers associated with the admin realm, so we
        # add it and write the list back to the database. (We're
        # deliberately sticking it in front so broken resolvers after
        # it don't cause problems when trying to find users in this
        # one.)

        admin_resolvers_new = admin_resolver_name
        if admin_resolvers:
            admin_resolvers_new += "," + admin_resolvers

        set_config(
            key=admin_resolvers_key,
            value=admin_resolvers_new,
            typ="text",
            description="None",
            update=True,
        )

        self.session.commit()


if __name__ == "__main__":
    app = create_app()

    data = {
        "givenname": "Donald",
        "surname": "Duck",
        "phone": "56789",
        "mobile": "1234567",
        "email": "donald@entenhausen.duck",
    }

    with app.app_context():
        la = LocalAdminResolver(app)

        la._remove_all_users()
        la.add_user(username="donald2", password="topSecret", **data)
        print(la.list_users())
        la.set_user_password("donald2", "new2")
        data["givenname"] = "Donald2"
        la.update_user(username="donald2", **data)
        print(la.list_users())
        la.remove_user("donald2")
        print(la.list_users())

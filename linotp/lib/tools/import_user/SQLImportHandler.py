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

"""
import user into an SQL Resolver

  * define the table
  * import the users
  * define the resolver

"""

import json
import logging

from sqlalchemy.engine import create_engine
from sqlalchemy.orm import sessionmaker

from linotp.lib.resolver import defineResolver
from linotp.lib.tools.import_user.ImportHandler import ImportHandler
from linotp.model.imported_user import ImportedUser
from linotp.useridresolver.SQLIdResolver import IdResolver as sql_resolver

log = logging.getLogger(__name__)


class DuplicateUserError(Exception):
    pass


class DatabaseContext:
    """
    with the database context ist is possible to drive the "user import"
    from the shell and from within LinOTP
    """


class LinOTP_DatabaseContext(DatabaseContext):
    """
    the linotp database context -
    - recieve the current session and engine
    """

    def __init__(self, SqlSession, SqlEngine):
        """
        initialisation with the reference to the current Engine and Session
        """
        self.session = SqlSession
        self.engine = SqlEngine

    def get_session(self):
        """
        encapsulate the access to the session, which is different for the
        different context

        :return: database session
        """
        return self.session

    def define_resolver(self, params):
        """
        native define the resolver
        - in the LinOTP context, we can use the internal function to define
          the resolver
        :param params: dict with the resolver parameter
        """

        defineResolver(params)


class Shell_DatabaseContext(DatabaseContext):
    """
    the shell database context -
    - use the sql url to process the import of the users
    """

    def __init__(self, sql_url):
        """
        initialisation from the sql url
        """
        self.sessionmaker = sessionmaker()
        self.engine = create_engine(sql_url, echo=True)
        self.sessionmaker.configure(bind=self.engine)
        self.session = self.sessionmaker()

    def get_session(self):
        """
        encapsulate the access to the session, which is different for the
        different context
        """
        return self.session

    def define_resolver(self, params):
        """
        native define the resolver
        - in the Shell context, this could be done by an http request to linotp

        - currently not implemented

        :param params: dict with the resolver parameter
        """

        print("create resolver currently only available in the scope of LinOTP")


class SQLImportHandler(ImportHandler):
    """
    the SQLResolverContext will be used to import the users into an
    sql table and creates an SQL Resolver for the access to the imported
    users
    """

    def __init__(self, groupid, resolver_name, database_context):
        """
        initialisation - using the given database context, to support
        usage from a shell and from within LinOTP
        """
        self.table_name = ImportedUser.__tablename__

        self.groupid = groupid
        self.resolver_name = resolver_name
        self.db_context = database_context

    def _get_resolver_parameters(self):
        """
        create the config of an sql resolver, which
        - establish driver, admin user and password
        - table
        - user_mapping
        - where condition with groupid

        - internal, called for the creating of the resolver

        :return: dictionary of the resolver parameters
        """

        mapping = {entry: entry for entry in ImportedUser.user_entries}

        where = f"groupid = '{self.groupid}'"

        resolver_parameters = {
            "Driver": "",
            "Server": "",
            "Port": "",
            "Database": "",
            "User": "",
            "Password": "",
            "Table": self.table_name,
            "Where": where,
            "Map": json.dumps(mapping),
            "readonly": True,
        }

        resolver_parameters["name"] = self.resolver_name

        sql_resolver_type = sql_resolver.getResolverClassType()
        resolver_parameters["type"] = sql_resolver_type

        _config, missing = sql_resolver.filter_config(resolver_parameters)

        if missing:
            msg = "missing some resolver attributes: %r"
            raise Exception(msg, missing)

        return resolver_parameters

    def get_resolver_spec(self):
        """
        :return: return resolver spec for insert in a realm
        """
        return "useridresolver.SQLIdResolver.IdResolver." + self.resolver_name

    def _create_resolver(self):
        """
        create the resolver with it's parameters
        - internal function, called after the linotp import

        :return: list of the parameters
        """
        params = self._get_resolver_parameters()
        self.db_context.define_resolver(params)
        return params

    # ---------------------------------------------------------------------- --

    # external interface for the Resolver Import Handler

    def prepare(self):
        """
        external steps called from the UserImport

        for the sqlresolverc import context the following steps are made:
        - create the table for the users
        - prepare the list of allready available users for this groupid
        - create the database session context
        """

        session = self.db_context.get_session()

        u_users = (
            session.query(ImportedUser.userid, ImportedUser.username)
            .filter(ImportedUser.groupid == self.groupid)
            .all()
        )

        former_user_by_id = dict(u_users)
        return former_user_by_id

    def commit(self):
        """
        external steps called from the UserImport
        - within this step the resolver is created
        """
        self._create_resolver()
        session = self.db_context.get_session()
        session.commit()

    def rollback(self):
        """
        external steps called from the UserImport in case of an error
        """
        session = self.db_context.get_session()
        session.rollback()

    def close(self):
        """
        external steps called from the UserImport during the finalization
        """
        session = self.db_context.get_session()
        session.close()

    # ---------------------------------------------------------------------- --

    # user related functions

    def lookup(self, user):
        """
        the lookup is called during the user import, to look for an
        already existing user

        :param user: the user with the new values
        """

        session = self.db_context.get_session()

        u_user_list = (
            session.query(ImportedUser)
            .filter(ImportedUser.userid == user.userid)
            .filter(ImportedUser.groupid == self.groupid)
            .all()
        )

        if u_user_list:
            return u_user_list[0]

        return None

    def add(self, user):
        """
        add user to the database session

        :param user: the user with the new values
        """

        session = self.db_context.get_session()

        # add the required group identifier
        user.set("groupid", self.groupid)

        session.add(user)

    def update(self, former_user, user):
        """
        update a user and add it to the databases session

        :param former_user: the user identified by the database
        :param user: the user with the new values
        """

        # merge the csv user data in the db user object
        former_user.update(user)
        former_user.set("groupid", self.groupid)

        session = self.db_context.get_session()

        session.add(former_user)

    def delete_by_id(self, user_id):
        """
        delete the user from the database

        :param user_id: the uniqe identifiert of the user
        """
        session = self.db_context.get_session()

        del_user = (
            session.query(ImportedUser)
            .filter(ImportedUser.userid == user_id)
            .filter(ImportedUser.groupid == self.groupid)
            .all()
        )

        if len(del_user) > 1:
            msg = (
                f"There exist more than one user with userid {user_id} and "
                f"groupid {self.groupid}. Database maybe corrupted."
            )
            raise DuplicateUserError(msg)

        if del_user:
            session.delete(del_user[0])

    # ---------------------------------------------------------------------- --

    # inner class to process the orm user object


# eof #

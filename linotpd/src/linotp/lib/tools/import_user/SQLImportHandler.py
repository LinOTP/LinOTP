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
  import user into an SQL Resolver

    * define the table
    * import the users
    * define the resolver

"""
import logging
import json

from sqlalchemy import schema, types
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from useridresolver.SQLIdResolver import IdResolver as sql_resolver

from linotp.lib.resolver import defineResolver

from linotp.lib.tools.import_user.ImportHandler import ImportHandler
from linotp.lib.crypto import libcrypt_password

log = logging.getLogger(__name__)

Base = declarative_base()


class DatabaseContext(object):
    """
    with the database context ist is possible to drive the "user import"
    from the shell and from within LinOTP
    """
    pass


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

        return

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
        return

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

        print("create resolver currently only available in "
              "the scope of LinOTP")
        return


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
        self.table_name = self.User.__tablename__

        self.groupid = groupid
        self.resolver_name = resolver_name
        self.db_context = database_context
        self.table_created = False

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

        url = self.db_context.engine.url

        mapping = {}
        for entry in SQLImportHandler.User.user_entries:
            mapping[entry] = entry

        where = "groupid = '%s'" % self.groupid

        resolver_parameters = {
            "Driver": url.drivername,
            "Server": url.host or "",
            "Port": str(url.port or ""),
            "Database": url.database,
            "User": url.username or "",
            "Password": url.password or "",
            "Table": self.table_name,
            "Where": where,
            "Map": json.dumps(mapping),
            "readonly": True,
            }

        resolver_parameters['name'] = self.resolver_name

        sql_resolver_type = sql_resolver.getResolverClassType()
        resolver_parameters['type'] = sql_resolver_type

        _config, missing = sql_resolver.filter_config(resolver_parameters)

        if missing:
            raise Exception("missing some resolver attributes: %r",
                            missing)

        return resolver_parameters

    def get_resolver_spec(self):
        """
        :return: return resolver spec for insert in a realm
        """
        return "useridresolver.SQLIdResolver.IdResolver." + self.resolver_name

    def _create_table(self):
        """
        create the table to store the users
        - internal function, called at the import start
        """

        if not self.table_created:

            Base.metadata.create_all(self.db_context.engine,
                                     checkfirst=True)

            self.table_created = True

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
        self._create_table()

        former_user_by_id = {}

        session = self.db_context.get_session()

        u_users = session.query(self.User.userid, self.User.username).filter(
            self.User.groupid == self.groupid).all()

        for u_user in u_users:
            userid, username = u_user
            former_user_by_id[userid] = username

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

        u_user_list = session.query(self.User).filter(
                self.User.userid == user.userid).filter(
                self.User.groupid == self.groupid).all()

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

        del_user = session.query(self.User).filter(
                self.User.userid == user_id and
                self.User.groupid == self.groupid).all()

        if del_user:
            session.delete(del_user[0])
    # ---------------------------------------------------------------------- --

    # inner class to process the orm user object

    class User(Base):

        __tablename__ = "imported_user"

        groupid = schema.Column(types.Unicode(100),
                                primary_key=True,
                                index=True)

        userid = schema.Column(types.Unicode(100),
                               primary_key=True,
                               index=True)

        username = schema.Column(types.Unicode(255),
                                 default=u'',
                                 index=True)

        phone = schema.Column(types.Unicode(100),
                              default=u'')

        mobile = schema.Column(types.Unicode(100),
                               default=u'')

        email = schema.Column(types.Unicode(100),
                              default=u'')

        surname = schema.Column(types.Unicode(100),
                                default=u'')

        givenname = schema.Column(types.Unicode(100),
                                  default=u'')

        password = schema.Column(types.Unicode(255),
                                 default=u'',
                                 index=True)

        user_entries = [
            "userid", "username", "phone", "mobile", "email", "surname",
            "givenname", "password", "groupid"]

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

        def creat_password_hash(self, plain_password):
            """
            create a password hash entry from a given plaintext password
            """
            self.password = libcrypt_password(plain_password)
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
            return not(self == user)

# eof #

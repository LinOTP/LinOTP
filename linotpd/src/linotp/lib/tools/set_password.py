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
set password handler -
  enable the user to change his password
"""

import logging

from linotp.lib.tools import ToolsHandler
from linotp.lib.crypto import libcrypt_password

from sqlalchemy import schema, types
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.exc import MultipleResultsFound

Base = declarative_base()

log = logging.getLogger(__name__)


class DataBaseContext(object):
    """
    the database context - used to preseve the engine, which is required for
    the unit test, where the sqlite database resides in memory
    """

    def __init__(self, sql_url):
        """
        constructor of the db context to initalize the
        sql engine and sessionmaker form a sql url

        :param sql_url: the database url
        :return: - nothing -
        """

        self.engine = create_engine(sql_url, echo=True)

        # setup the session maker, which will create a new session on demand

        self.sessionmaker = sessionmaker()
        self.sessionmaker.configure(bind=self.engine)

    def get_session(self):
        """
        build a new db session on demand

        :return: a new session, which is closed with a session.close()
        """
        return self.sessionmaker()

    def get_engine(self):
        """
        provide access to the sql engine

        :return: the initialized db engine
        """
        return self.engine


class SetPasswordHandler(ToolsHandler):
    """
    the handler to change the admin password
    """

    class AdminUser(Base):
        """
        AdminUser - the db user entry
        - we use here the same class defintion as for the user import
          which will allow to place a managed resolver on top of this
        """
        __tablename__ = "admin_users"

        groupid = schema.Column(types.Unicode(100),
                                primary_key=True,
                                index=True)

        userid = schema.Column(types.Unicode(100),
                               primary_key=True,
                               index=True)

        username = schema.Column(types.Unicode(255),
                                 default=u'',
                                 unique=True,
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
                                 default=u'')

    @staticmethod
    def create_table(db_context):
        """
        create the table to store the users
        - internal function, called at the import start

        :param db_context: object to provide the database engine and connection
        :return: - nothing -
        """

        engine = db_context.get_engine()
        Base.metadata.create_all(engine,
                                 checkfirst=True)

    @staticmethod
    def create_admin_user(db_context, username, crypted_password):
        """
        create the initial admin user with his password if it does not exists
        - called during server start

        :param db_context: object to provide the database engine and connection
        :param username: the name of the admin user
        :param crypted_password: the lib crypt encrypted password
        :return: - nothing -
        """

        session = db_context.get_session()

        try:

            admin_users = session.query(
                SetPasswordHandler.AdminUser).filter(
                SetPasswordHandler.AdminUser.username == username
                ).all()

            if len(admin_users) > 0:
                log.info("admin user %r already exist - user not updated!")
                return

            admin_user = SetPasswordHandler.AdminUser()

            admin_user.userid = username
            admin_user.username = username
            admin_user.groupid = "admin"
            admin_user.givenname = "created by setPassword"

            admin_user.password = crypted_password

            session.add(admin_user)
            session.commit()

        except Exception as exx:

            log.exception(exx)
            session.rollback()

        finally:

            session.close()

    # ---------------------------------------------------------------------- --

    def __init__(self, db_context):
        """
        initialisation with the dbContext - this will allow the reusage
        of the engine which is required for the unit testing

        :param dbContext: object to provide the database engine and connection
        :return: - nothing -
        """
        self.db_context = db_context

    def set_password(self, username, old_password, new_password):
        """
        set the password, which requires the old_password for authorisation

        :param username: the admin username
        :param old_password: use the old password for authorisation
        :param new_password: the new password
        :return: - nothing -
        """

        session = self.db_context.get_session()

        try:
            try:
                admin_user = session.query(self.AdminUser).filter(
                                    self.AdminUser.username == username).one()

            except NoResultFound:
                log.error("no user %r found!", username)
                raise Exception("no user %r found!" % username)

            except MultipleResultsFound:
                log.error("multiple users %r found!", username)
                raise Exception("multiple users %r found!" % username)

            crypted_password = admin_user.password

            if libcrypt_password(
                    old_password, crypted_password) != crypted_password:

                raise Exception("old password missmatch!")

            admin_user.password = libcrypt_password(new_password)

            session.add(admin_user)

            session.commit()

        except Exception as exx:
            log.exception(exx)
            session.rollback()

            raise exx

        finally:
            session.close()

# eof #

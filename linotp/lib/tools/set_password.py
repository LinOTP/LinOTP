# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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

from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound

from linotp.lib.crypto import utils
from linotp.lib.tools import ToolsHandler
from linotp.model import db

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
        pass

    def get_session(self):
        """
        build a new db session on demand

        :return: a new session, which is closed with a session.close()
        """
        return db.session

    def get_engine(self):
        """
        provide access to the sql engine

        :return: the initialized db engine
        """
        return db.engine


class SetPasswordHandler(ToolsHandler):
    """
    the handler to change the admin password
    """

    class AdminUser(db.Model):
        """
        AdminUser - the db user entry
        - we use here the same class defintion as for the user import
          which will allow to place a managed resolver on top of this
        """

        __tablename__ = "admin_users"

        groupid = db.Column(db.String(100), primary_key=True, index=True)
        userid = db.Column(db.String(100), primary_key=True, index=True)
        username = db.Column(
            db.String(255), default="", unique=True, index=True
        )
        phone = db.Column(db.String(100), default="")
        mobile = db.Column(db.String(100), default="")
        email = db.Column(db.String(100), default="")
        surname = db.Column(db.String(100), default="")
        givenname = db.Column(db.String(100), default="")
        password = db.Column(db.String(255), default="")

    @staticmethod
    def create_table(db_context):
        """
        create the table to store the users
        - internal function, called at the import start

        :param db_context: object to provide the database engine and connection
        :return: - nothing -
        """

        db.create_all()  # FIXME: This can probably be more targeted.

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

        try:
            admin_users = SetPasswordHandler.AdminUser.query.filter_by(
                username=username
            ).all()
            if len(admin_users) > 0:
                log.info("admin user %r already exist - user not updated!")
                return

            admin_user = SetPasswordHandler.AdminUser(
                userid=username,
                username=username,
                groupid="admin",
                givenname="created by setPassword",
                password=crypted_password,
            )
            db.session.add(admin_user)
            db.session.commit()

        except Exception as exx:
            log.error(exx)
            db.session.rollback()

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

        try:
            try:
                admin_user = SetPasswordHandler.AdminUser.query.filter_by(
                    username=username
                ).one()

            except NoResultFound:
                log.error("no user %r found!", username)
                raise Exception("no user %r found!" % username)

            except MultipleResultsFound:
                log.error("multiple users %r found!", username)
                raise Exception("multiple users %r found!" % username)

            crypted_password = admin_user.password

            if not utils.compare_password(old_password, crypted_password):
                raise Exception("old password missmatch!")

            admin_user.password = utils.crypt_password(new_password)

            db.session.add(admin_user)
            db.session.commit()

        except Exception as exx:
            log.error(exx)
            db.session.rollback()

            raise exx


# eof #

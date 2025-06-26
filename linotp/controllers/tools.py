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
tools controller
"""

import json
import logging

from flask import current_app, g, request
from werkzeug.datastructures import FileStorage

from linotp.controllers.base import BaseController, methods
from linotp.lib.context import request_context
from linotp.lib.error import ParameterError
from linotp.lib.policy import (
    PolicyException,
    checkPolicyPre,
    checkToolsAuthorisation,
)
from linotp.lib.reply import sendError, sendResult
from linotp.lib.resolver import DeleteForbiddenError, getResolverList
from linotp.lib.tools.import_user import (
    DefaultFormatReader,
    PasswdFormatReader,
    UserImport,
)
from linotp.lib.tools.import_user.SQLImportHandler import (
    LinOTP_DatabaseContext,
    SQLImportHandler,
)
from linotp.lib.tools.set_password import DataBaseContext, SetPasswordHandler
from linotp.lib.type_utils import boolean
from linotp.lib.user import getUserFromRequest
from linotp.model import db

log = logging.getLogger(__name__)


class ToolsController(BaseController):
    """"""

    def __before__(self, **params):
        """
        __before__ is called before every action

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        action = request_context["action"]

        try:
            checkToolsAuthorisation(action, params)

        except Exception as exx:
            log.error("[__before__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(exx)

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        action = request_context["action"]

        try:
            # finally create the audit entry
            current_app.audit_obj.log(g.audit)
            db.session.commit()
            return response

        except Exception as exx:
            log.error("[__after__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(exx)

    @methods(["POST"])
    def setPassword(self):
        """
        abilty to set password in managed / admin_user resolver

        :param old_password: the old password
        :param new_password: the new password

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        try:
            old_pw = self.request_params["old_password"]
            new_pw = self.request_params["new_password"]

            auth_user = getUserFromRequest()
            username = auth_user.login

            if not username:
                raise Exception("Missing authenticated user!")

            sql_url = db.engine.url

            # -------------------------------------------------------------- --

            # the set password handling:
            # any error will raise an excecption which will be displayed
            # to the user

            g.audit["administrator"] = username
            g.audit["info"] = "setPassword"

            set_pw_handler = SetPasswordHandler(DataBaseContext(sql_url))

            set_pw_handler.set_password(
                username, old_password=old_pw, new_password=new_pw
            )

            g.audit["success"] = True

            return sendResult(
                obj=True,
                opt={"detail": (f"password updated for {username!r}")},
            )

        except Exception as exx:
            g.audit["success"] = False

            log.error(exx)
            db.session.rollback()
            return sendError(exx)

    @methods(["POST"])
    def migrate_resolver(self):
        """
        migrate all users and their token into a new resolver

        Raises:
            Exception: _description_

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """

        from linotp.lib.tools.migrate_resolver import MigrateResolverHandler

        ret = {}

        try:
            src = self.request_params["from"]
            target = self.request_params["to"]

            from linotp.lib.resolver import getResolverList

            resolvers = getResolverList()

            src_resolver = resolvers.get(src, None)
            target_resolver = resolvers.get(target, None)

            if not target_resolver or not src_resolver:
                raise Exception("Src or Target resolver is undefined!")

            mg = MigrateResolverHandler()
            ret = mg.migrate_resolver(src=src_resolver, target=target_resolver)

            db.session.commit()
            return sendResult(ret)

        except Exception as e:
            log.error("migrate resolver failed")
            db.session.rollback()
            return sendError(e, 1)

    @methods(["POST"])
    def import_users(self):
        """
        import users from a csv file into an dedicated sql resolver

        :param file: the file containing the users
        :param resolver: the resolver where the users should belong to
        :param dryrun: only test a test run without real import of the users
        :param format: the import file format 'csv' or 'password'
        :param skip_header: in case of a csv file the first line might contain a description of the columns and could be skiped
        :param passwords_in_plaintext: bool - should the passwords be hashed?
        :param column_mapping: in case of the csv, define the meaning of the colums
        :param delimiter: in case of csv define the colum delimiter
        :param quotechar: define how text is quoted

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned
        """

        try:
            params = self.request_params

            # -------------------------------------------------------------- --
            # processing required arguments
            try:
                data_file = request.files["file"]
                resolver_name = params["resolver"]

            except KeyError as exx:
                log.error("Missing parameter: %r", exx)
                raise ParameterError(f"Missing parameter: {exx!r}") from exx

            if resolver_name == current_app.config["ADMIN_RESOLVER_NAME"]:
                raise DeleteForbiddenError(
                    f"default admin resolver {resolver_name} is not allowed "
                    "to be overwritten!"
                )

            groupid = resolver_name

            # process file upload data

            data = data_file

            # -- ----------------------------------------------------------- --
            # In case of form post requests, it is a "instance" of FileStorage
            # i.e. the Filename is selected in the browser and the data is
            # transferred in an iframe.
            #     see: http://jquery.malsup.com/form/#sample4
            # -- ----------------------------------------------------------- --

            if isinstance(data_file, FileStorage):
                data = data_file.read()

            data = data.decode()

            # -------------------------------------------------------------- --

            # process the other arguments
            dryrun = boolean(params.get("dryrun", False))

            passwords_in_plaintext = boolean(
                params.get("passwords_in_plaintext", False)
            )

            file_format = params.get("format", "csv")

            if file_format in ("password", "passwd"):
                column_mapping = {
                    "userid": 2,
                    "username": 0,
                    "phone": 8,
                    "mobile": 7,
                    "email": 9,
                    "surname": 5,
                    "givenname": 4,
                    "password": 1,
                }

                format_reader = PasswdFormatReader()

            elif file_format in ("csv"):
                skip_header = boolean(params.get("skip_header", False))
                if skip_header:
                    data = "\n".join(data.split("\n")[1:])

                column_mapping = {
                    "username": 0,
                    "userid": 1,
                    "surname": 2,
                    "givenname": 3,
                    "email": 4,
                    "phone": 5,
                    "mobile": 6,
                    "password": 7,
                }

                delimiter = str(params.get("delimiter", ","))
                quotechar = str(params.get("quotechar", '"'))

                format_reader = DefaultFormatReader()
                format_reader.delimiter = delimiter
                format_reader.quotechar = quotechar

                column_mapping = params.get("column_mapping", column_mapping)

            else:
                raise Exception("unspecified file foramt")

            # we have to convert the column_mapping back into an dict

            if isinstance(column_mapping, str):
                column_mapping = json.loads(column_mapping)

            # prevent overwrite of existing unmanaged resolver

            checkPolicyPre("system", "setResolver")

            resolvers = getResolverList()
            if resolver_name in resolvers:
                if not resolvers[resolver_name].get("readonly", False):
                    raise Exception(
                        f"Unmanged resolver with same name: {resolver_name!r}"
                        " already exists!"
                    )
            # -------------------------------------------------------------- --

            # feed the engine :)

            # use a LinOTP Database context for Sessions and Engine

            db_context = LinOTP_DatabaseContext(
                SqlSession=db.session, SqlEngine=db.engine
            )

            # define the import into an SQL database + resolver

            import_handler = SQLImportHandler(
                groupid=groupid,
                resolver_name=resolver_name,
                database_context=db_context,
            )

            # create the UserImporter with the required mapping

            user_import = UserImport(import_handler)

            user_import.set_mapping(column_mapping)

            # and run the data processing

            result = user_import.import_csv_users(
                data,
                dryrun=dryrun,
                format_reader=format_reader,
                passwords_in_plaintext=passwords_in_plaintext,
            )

            if dryrun:
                return sendResult(result)

            # -------------------------------------------------------------- --

            # create / extend target realm for the resolver

            _resolver_spec = import_handler.get_resolver_spec()

            db.session.commit()

            return sendResult(result)

        except PolicyException as pexx:
            log.error("Error during user import: %r", pexx)

            db.session.rollback()

            return sendError(f"{pexx!r}", 1)

        except Exception as exx:
            log.error("Error during user import: %r", exx)

            db.session.rollback()

            return sendError(exx)

        finally:
            log.debug("done")


# eof #########################################################################

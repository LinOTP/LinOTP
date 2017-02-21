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
tools controller
"""

from cgi import FieldStorage

from pylons import request, response
from pylons import tmpl_context as c

from linotp.lib.base import BaseController
from linotp.lib.reply import sendError
from linotp.lib.reply import sendResult

from linotp.lib.policy import PolicyException
from linotp.lib.policy import checkToolsAuthorisation
from linotp.lib.util import check_session
from linotp.lib.context import request_context

from linotp.lib.tools.import_user import UserImport
from linotp.lib.tools.import_user.SQLImportHandler import LinOTP_DatabaseContext
from linotp.lib.tools.import_user.SQLImportHandler import SQLImportHandler
from linotp.lib.tools.import_user import DefaultFormatReader
from linotp.lib.tools.import_user import PasswdFormatReader


import logging

# this is a hack for the static code analyser, which
# would otherwise show session.close() as error
import linotp.model
Session = linotp.model.Session

log = logging.getLogger(__name__)


class ToolsController(BaseController):
    """
    """

    def __before__(self, action, **params):
        """
        """

        try:

            # Session handling
            check_session(request)

            checkToolsAuthorisation(action, params)
            c.audit = request_context['audit']
            return request

        except PolicyException as exx:
            log.exception("policy failed %r" % exx)
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')

        except Exception as exx:
            log.exception("[__before__::%r] exception %r" % (action, exx))
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')


    def __after__(self, action):
        """
        """
        try:
            # finally create the audit entry
            Audit = request_context['Audit']
            audit = request_context.get('audit')

            c.audit.update(audit)
            Audit.log(c.audit)
            Session.commit()
            return request

        except Exception as exx:
            log.exception(exx)
            Session.rollback()
            return sendError(response, exx, context='after')

        finally:
            Session.close()

    def migrate_resolver(self):

        from linotp.lib.tools.migrate_resolver import MigrateResolverHandler

        params = {}
        ret = {}

        try:
            params.update(request.params)

            src = params['from']
            target = params['to']

            from linotp.lib.resolver import getResolverList
            resolvers = getResolverList()

            src_resolver = resolvers.get(src, None)
            target_resolver = resolvers.get(target, None)

            if not target_resolver or not src_resolver:
                raise Exception('Src or Target resolver is undefined!')

            mg = MigrateResolverHandler()
            ret = mg.migrate_resolver(src=src_resolver,
                                      target=target_resolver)

            Session.commit()
            return sendResult(response, ret)

        except Exception as e:
            log.exception("failed: %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()

    def import_users(self):
        """
        import users from a csv file into an dedicated sql resolver
        """

        try:

            params = {}
            params.update(request.POST)

            # argument processing

            user_column_map = {
                    "userid": 2,
                    "username": 0,
                    "phone": 8,
                    "mobile": 7,
                    "email": 9,
                    "surname": 5,
                    "givenname": 4,
                    "password": 1}

            csv_file = request.POST['file']
            csv_data = csv_file

            # -- ----------------------------------------------------------- --
            # In case of form post requests, it is a "instance" of FieldStorage
            # i.e. the Filename is selected in the browser and the data is
            # transferred in an iframe.
            #     see: http://jquery.malsup.com/form/#sample4
            # -- ----------------------------------------------------------- --

            if isinstance(csv_file, FieldStorage):
                csv_data = csv_file.value

            groupid = params['groupid']
            resolver_name = params['resolver']

            column_mapping = params.get('column_mapping', user_column_map)
            dryrun = str(params.get('dryrun', True)).lower() == "true"

            file_format = params.get('format', "")
            column_separator = params.get('column_separator', ",")
            text_delimiter = params.get('text_delimiter', '"')

            if file_format in ('password', 'passwd'):
                format_reader = PasswdFormatReader()
            else:
                format_reader = DefaultFormatReader()
                format_reader.seperator = column_separator
                format_reader.delimiter = text_delimiter

            # -------------------------------------------------------------- --

            # feed the engine

            db_context = LinOTP_DatabaseContext(
                                        SqlSession=Session,
                                        SqlEngine=linotp.model.meta.engine)

            import_handler = SQLImportHandler(
                                        groupid=groupid,
                                        resolver_name=resolver_name,
                                        database_context=db_context)

            user_import = UserImport(import_handler)

            user_import.set_mapping(column_mapping)

            result = user_import.import_csv_users(
                                        csv_data,
                                        dryrun=dryrun,
                                        format_reader=format_reader)

            Session.commit()

            return sendResult(response, result)

        except PolicyException as pexx:

            log.exception("Error during user import: %r" % pexx)

            Session.rollback()

            return sendError(response, "%r" % pexx, 1)

        except Exception as exx:

            log.exception("Error during user import: %r" % exx)

            Session.rollback()

            return sendError(response, "%r" % exx)

        finally:
            Session.close()
            log.debug('done')

# eof #########################################################################

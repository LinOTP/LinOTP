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
import json
from cgi import FieldStorage

from pylons import request, response
from pylons import tmpl_context as c

from linotp.lib.base import BaseController
from linotp.lib.reply import sendError
from linotp.lib.reply import sendResult
from linotp.lib.error import ParameterError

from linotp.lib.policy import PolicyException
from linotp.lib.policy import checkToolsAuthorisation
from linotp.lib.util import check_session
from linotp.lib.context import request_context

from linotp.lib.tools.import_user import UserImport
from linotp.lib.tools.import_user.SQLImportHandler import LinOTP_DatabaseContext
from linotp.lib.tools.import_user.SQLImportHandler import SQLImportHandler
from linotp.lib.tools.import_user import DefaultFormatReader
from linotp.lib.tools.import_user import PasswdFormatReader

from linotp.lib.tools.set_password import SetPasswordHandler
from linotp.lib.tools.set_password import DataBaseContext

from linotp.lib.realm import getRealms
from linotp.lib.user import setRealm
from linotp.lib.resolver import getResolverList

from linotp.lib.type_utils import boolean

import logging
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

    def setPassword(self):
        """
        abilty to set password in managed / admin_user resolver
        """
        params = {}
        try:
            params.update(request.params)

            old_pw = params['old_password']
            new_pw = params['new_password']

            username = request_context['AuthUser'].get('login', '')

            if not username:
                raise Exception("Missing authenticated user!")

            sql_url = linotp.model.meta.engine.url

            # -------------------------------------------------------------- --

            # the set password handling:
            # any error will raise an excecption which will be displayed
            # to the user

            c.audit['administrator'] = username
            c.audit['info'] = 'setPassword'

            set_pw_handler = SetPasswordHandler(DataBaseContext(sql_url))

            set_pw_handler.set_password(username,
                                        old_password=old_pw,
                                        new_password=new_pw)

            c.audit['success'] = True

            return sendResult(response, obj=True,
                              opt={'detail':
                                   ('password updated for %r' % username)
                                   })

        except Exception as exx:

            c.audit['success'] = False

            log.exception(exx)
            Session.rollback()
            return sendError(response, exx)

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

            # -------------------------------------------------------------- --
            # processing required arguments
            try:

                data_file = request.POST['file']
                resolver_name = params['resolver']

            except KeyError as exx:

                log.exception("Missing parameter: %r", exx)
                raise ParameterError("Missing parameter: %r" % exx)

            groupid = resolver_name

            # process file upload data

            data = data_file

            # -- ----------------------------------------------------------- --
            # In case of form post requests, it is a "instance" of FieldStorage
            # i.e. the Filename is selected in the browser and the data is
            # transferred in an iframe.
            #     see: http://jquery.malsup.com/form/#sample4
            # -- ----------------------------------------------------------- --

            if isinstance(data_file, FieldStorage):
                data = data_file.value

            # -------------------------------------------------------------- --

            # process the other arguments
            dryrun = boolean(params.get('dryrun', False))

            passwords_in_plaintext = boolean(params.get(
                                                'passwords_in_plaintext',
                                                False))

            file_format = params.get('format', "csv")

            if file_format in ('password', 'passwd'):

                column_mapping = {
                        "userid": 2,
                        "username": 0,
                        "phone": 8,
                        "mobile": 7,
                        "email": 9,
                        "surname": 5,
                        "givenname": 4,
                        "password": 1}

                format_reader = PasswdFormatReader()

            elif file_format in ('csv'):

                skip_header = boolean(params.get('skip_header', False))
                if skip_header:
                    data = '\n'.join(data.split('\n')[1:])

                column_mapping = {
                        "username": 0,
                        "userid": 1,
                        "surname": 2,
                        "givenname": 3,
                        "email": 4,
                        "phone": 5,
                        "mobile": 6,
                        "password": 7}

                delimiter = str(params.get('delimiter', ","))
                quotechar = str(params.get('quotechar', '"'))

                format_reader = DefaultFormatReader()
                format_reader.delimiter = delimiter
                format_reader.quotechar = quotechar

                column_mapping = params.get('column_mapping', column_mapping)

            else:

                raise Exception('unspecified file foramt')

            # we have to convert the column_mapping back into an dict

            if (isinstance(column_mapping, str) or
                isinstance(column_mapping, unicode)):
                column_mapping = json.loads(column_mapping)

            # prevent overwrite of existing unmanaged resolver

            resolvers = getResolverList()
            if resolver_name in resolvers:
                if not resolvers[resolver_name].get('readonly', False):
                    raise Exception("Unmanged resolver with same name: %r"
                                    " already exists!" % resolver_name)
            # -------------------------------------------------------------- --

            # feed the engine :)

            # use a LinOTP Database context for Sessions and Engine

            db_context = LinOTP_DatabaseContext(
                                        SqlSession=Session,
                                        SqlEngine=linotp.model.meta.engine)

            # define the import into an SQL database + resolver

            import_handler = SQLImportHandler(
                                        groupid=groupid,
                                        resolver_name=resolver_name,
                                        database_context=db_context)

            # create the UserImporter with the required mapping

            user_import = UserImport(import_handler)

            user_import.set_mapping(column_mapping)

            # and run the data processing

            result = user_import.import_csv_users(
                                data,
                                dryrun=dryrun,
                                format_reader=format_reader,
                                passwords_in_plaintext=passwords_in_plaintext
                                )

            if dryrun:

                return sendResult(response, result)

            # -------------------------------------------------------------- --

            # create / extend target realm for the resolver

            resolver_spec = import_handler.get_resolver_spec()

            Session.commit()

            return sendResult(response, result)

        except PolicyException as pexx:

            log.exception("Error during user import: %r", pexx)

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

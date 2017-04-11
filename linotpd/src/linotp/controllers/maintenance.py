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

import logging
import os

from pylons import request
from pylons import response

from pylons.controllers.util import abort

from linotp.lib.context import request_context

from linotp.lib.reply import sendResult
from linotp.lib.reply import sendError
from linotp.lib.base import BaseController
from linotp.lib.logs import set_logging_level

from linotp.model import Config
import linotp.model.meta

Session = linotp.model.meta.Session

log = logging.getLogger(__name__)


class MaintenanceController(BaseController):

    """
    The maintenance controller is an internal interface
    for maintainers to change certain parameters (such as
    log levels) at runtime
    """

    def __before__(self, action, **params):
        """
        we check if the client cert was valid by looking for
        the existance of an env variable. for apache this is
        SSL_CLIENT_S_DN_CN. to support other servers we read
        the name of the variable from the config
        """

        env_var = request_context['Config'].get(
            'maintenance_verify_client_env_var', False)

        if env_var:

            client_cert = request.environ.get(env_var)

            if client_cert is None:
                abort(401)

    def setLogLevel(self):

        """
        set the log level of a certain logger which is identified by
        the url parameter loggerName.

        example call:

            POST /maintenance/setLogLevel
            loggerName=linotp.lib.user
            level=10

        (sets the log level of the user library to DEBUG)
        if loggerName is omitted, the root logger is assumed.
        """

        try:

            # if no logger name is supplied we default to '' (which translates
            # to the root logger in the python stdlib logging api)

            name = request.POST.get('loggerName', '')

            # ----------------------------------------------------------------

            level_as_str = request.POST.get('level', '')

            if not level_as_str.isdigit():
                raise Exception("'level' %r contains nondigits!")

            level = int(level_as_str)

            # ----------------------------------------------------------------------

            set_logging_level(name, level)
            Session.commit()
            return sendResult(response, True)

        except Exception as exx:
            Session.rollback()
            log.exception(exx)
            return sendError(response, exx, 1)

        finally:
            Session.close()

    def check_status(self):
        """
        simple check if LinOTP backend services  are up and running

        - support for checking that the Config database could be accessed

        """
        try:
            opt = {}

            config_count = Session.query(Config).count()
            opt['config'] = {'entries': config_count}

            return sendResult(response, True, 0, opt=opt)

        except Exception as exx:
            Session.rollback()
            log.exception(exx)
            abort(500, "%r" % exx.message)

        finally:
            Session.close()

# eof #

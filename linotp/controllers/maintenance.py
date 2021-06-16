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
#

import logging
import os

from werkzeug.exceptions import InternalServerError

from linotp.controllers.base import BaseController
from linotp.flap import abort, config, request, response
from linotp.lib.context import request_context
from linotp.lib.logs import set_logging_level
from linotp.lib.reply import sendError, sendResult
from linotp.model import Config, db

log = logging.getLogger(__name__)


class MaintenanceController(BaseController):

    """
    The maintenance controller is an internal interface
    for maintainers to change certain parameters (such as
    log levels) at runtime
    """

    def __before__(self, **params):
        """
        __before__ is called before every action

        we check if the client cert was valid by looking for
        the existance of a CGI environment variable. For apache
        this is SSL_CLIENT_S_DN_CN. To support other servers we
        read the name of the variable from the config

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        env_var = config.get("MAINTENANCE_VERIFY_CLIENT_ENV_VAR", False)

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

            name = self.request_params.get("loggerName", "")

            # ----------------------------------------------------------------

            try:
                level = self.request_params.get("level", 0)
                level = int(level)
            except ValueError as e:
                raise Exception(
                    "debug level {} contains nondigits!".format(level)
                )

            # ----------------------------------------------------------------------

            set_logging_level(name, level)
            db.session.commit()
            return sendResult(response, True)

        except Exception as exx:
            db.session.rollback()
            log.error(exx)
            return sendError(response, exx, 1)

    def check_status(self):
        """
        simple check if LinOTP backend services  are up and running

        - support for checking that the Config database could be accessed

        """
        try:
            opt = {}

            # Using the session makes this easier to mock in tests.
            config_count = db.session.query(Config).count()
            opt["config"] = {"entries": config_count}

            return sendResult(response, True, 0, opt=opt)

        except Exception as exx:
            db.session.rollback()  # why?
            log.error(exx)
            raise InternalServerError(str(exx))


# eof #

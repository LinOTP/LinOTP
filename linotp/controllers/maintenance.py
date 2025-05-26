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
#

import logging

from werkzeug.exceptions import InternalServerError

from flask import abort, request

from linotp.controllers.base import BaseController, methods
from linotp.flap import config
from linotp.lib import deprecated_methods
from linotp.lib.logs import set_logging_level
from linotp.lib.reply import sendError, sendResult
from linotp.model import db
from linotp.model.config import Config

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

        env_var = config["MAINTENANCE_VERIFY_CLIENT_ENV_VAR"]

        if env_var:
            client_cert = request.environ.get(env_var)

            if client_cert is None:
                abort(401)

    @methods(["POST"])
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

        :param loggerName: the name of the logger
        :param level: the logging level

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

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
            return sendResult(True)

        except Exception as exx:
            db.session.rollback()
            log.error(exx)
            return sendError(exx, 1)

    @deprecated_methods(["POST"])
    def check_status(self):
        """
        simple check if LinOTP backend services  are up and running

        support for checking that the Config database could be accessed

        :return:
            a json result with a boolean status and request result

        :raises Exception:
            if an error occurs an exception is serialized and returned

        """
        try:
            opt = {}

            # Using the session makes this easier to mock in tests.
            config_count = db.session.query(Config).count()
            opt["config"] = {"entries": config_count}

            return sendResult(True, 0, opt=opt)

        except Exception as exx:
            db.session.rollback()  # why?
            log.error(exx)
            raise InternalServerError(str(exx))


# eof #

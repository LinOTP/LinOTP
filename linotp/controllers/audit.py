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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""
audit controller - to search the audit trail
"""

import logging

from flask import Response, current_app, g, stream_with_context

from linotp.controllers.base import BaseController
from linotp.flap import config, request, response
from linotp.lib import deprecated_methods
from linotp.lib.audit.iterator import (
    AuditQuery,
    CSVAuditIterator,
    JSONAuditIterator,
)
from linotp.lib.context import request_context
from linotp.lib.policy import PolicyException, checkPolicyPre
from linotp.lib.reply import sendError
from linotp.lib.user import getUserFromRequest
from linotp.lib.util import check_session, get_client
from linotp.model import db

optional = True
required = False

log = logging.getLogger(__name__)


class AuditController(BaseController):

    """
    this is the controller for doing some audit stuff

        https://server/audit/<functionname>

    """

    def __before__(self, **params):
        """
        __before__ is called before every action

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        action = request_context["action"]

        try:
            g.audit["client"] = get_client(request)
            check_session(request)
        except Exception as exx:
            log.error("[__before__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(response, exx, context="before")

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        g.audit["administrator"] = getUserFromRequest()
        current_app.audit_obj.log(g.audit)

        return response

    @deprecated_methods(["POST"])
    def search(self):
        """
        This functions searches within the audit trail
        It returns the audit information for the given search pattern


        arguments are key, value pairs as search patterns.

        :param outform: (optional) if set to "csv", than the token list will be given in CSV
            or: Usually the key=values will be locally AND concatenated.
                it a parameter or=true is passed, the filters will
                be OR concatenated.

            The Flexigrid provides us the following parameters:
                ('page', u'1'), ('rp', u'25'),
                ('sortname', u'number'),
                ('sortorder', u'asc'),
                ('query', u''), ('qtype', u'serial')]
        :return:
            JSON response or csv format
        """

        try:
            log.debug("[search] params: %r", self.request_params)

            checkPolicyPre("audit", "view", {})

            # remove the param outform (and other parameters that should not
            # be used for search!
            search_params = self.request_params.copy()
            for key in ["outform", "delimiter"]:
                if key in search_params:
                    del search_params[key]

            output_format = (
                self.request_params.get("outform", "json") or "json"
            )

            delimiter = self.request_params.get("delimiter", ",") or ","

            audit_obj = current_app.audit_obj
            audit_query = AuditQuery(search_params, audit_obj)

            # ------------------------------------------------------------- --

            # check if we are running with sqlite which does not support
            # streaming responses

            stream_output = True

            db_uri = current_app.config["SQLALCHEMY_BINDS"]["auditdb"]
            if db_uri.startswith("sqlite"):
                stream_output = False

            if output_format == "csv":
                audit_iterator = CSVAuditIterator(audit_query, delimiter)
                mimetype = "text/csv"
                reponse_headers_args = {
                    "_key": "Content-disposition",
                    "_value": "attachment",
                    "filename": "linotp-audit.csv",
                }
            else:
                audit_iterator = JSONAuditIterator(audit_query)
                mimetype = "application/json"
                reponse_headers_args = {}

            if stream_output:
                audit_output = stream_with_context(audit_iterator)
            else:
                audit_output = ""
                try:
                    while True:
                        audit_output = audit_output + next(audit_iterator)
                except StopIteration:
                    # continue if all data is joined
                    pass

            streamed_response = Response(audit_output, mimetype=mimetype)

            if reponse_headers_args:
                streamed_response.headers.set(**reponse_headers_args)

            g.audit["success"] = True
            db.session.commit()

            return streamed_response

        except PolicyException as pe:
            log.error("[getotp] gettoken/getotp policy failedi: %r", pe)
            db.session.rollback()
            return sendError(response, pe, 1)

        except Exception as exx:
            log.error("[search] audit/search failed: %r", exx)
            db.session.rollback()
            return sendError(response, "audit/search failed", 0)


# eof###########################################################################

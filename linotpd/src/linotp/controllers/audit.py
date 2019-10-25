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
"""
audit controller - to search the audit trail
"""

import logging

from flask import Response, stream_with_context

from linotp.flap import tmpl_context as c, request, response, config

from linotp.controllers.base import BaseController


from linotp.lib.util import check_session
from linotp.lib.user import getUserFromRequest
from linotp.lib.policy import checkPolicyPre
from linotp.lib.policy import PolicyException

from linotp.lib.reply import sendError
from linotp.lib.audit.iterator import AuditQuery
from linotp.lib.audit.iterator import CSVAuditIterator
from linotp.lib.audit.iterator import JSONAuditIterator

from linotp.lib.util import get_client

from linotp.lib.context import request_context

import linotp.model
Session = linotp.model.Session


optional = True
required = False

log = logging.getLogger(__name__)


class AuditController(BaseController):

    '''
    this is the controller for doing some audit stuff

        https://server/audit/<functionname>

    '''

    def __before__(self, **params):
        """
        __before__ is called before every action

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        action = request_context['action']

        try:
            c.audit = request_context['audit']
            c.audit['client'] = get_client(request)
            check_session(request)
            audit = config.get('audit')
            request_context['Audit'] = audit

        except Exception as exx:
            log.exception("[__before__::%r] exception %r" % (action, exx))
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')

    @staticmethod
    def __after__(response):
        '''
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        '''

        audit = config.get('audit')

        c.audit['administrator'] = getUserFromRequest(request).get("login")
        audit.log(c.audit)

        return response

    def search(self):

        '''
        This functions searches within the audit trail
        It returns the audit information for the given search pattern

        method:
            audit/search

        arguments:
            key, value pairs as search patterns.

            * outform - optional: if set to "csv", than the token list will be
                        given in CSV


            or: Usually the key=values will be locally AND concatenated.
                it a parameter or=true is passed, the filters will
                be OR concatenated.

            The Flexigrid provides us the following parameters:
                ('page', u'1'), ('rp', u'25'),
                ('sortname', u'number'),
                ('sortorder', u'asc'),
                ('query', u''), ('qtype', u'serial')]
        returns:
            JSON response or csv format
        '''

        try:
            log.debug("[search] params: %s" % self.request_params)

            checkPolicyPre('audit', 'view', {})

            # remove the param outform (and other parameters that should not
            # be used for search!
            search_params = self.request_params.copy()
            for key in ["outform", 'delimiter']:
                if key in search_params:
                    del search_params[key]

            output_format = self.request_params.get("outform", 'json') or 'json'

            streamed_response = None

            audit = config.get('audit')
            audit_query = AuditQuery(search_params, audit)

            if output_format == "csv":
                delimiter = self.request_params.get('delimiter', ',') or ','
                audit_iterator = CSVAuditIterator(audit_query, delimiter)
                # TODO: Use stream_with_context instead of list
                streamed_response = Response(list(audit_iterator),
                                    content_type="text/csv")
                filename = "linotp-audit.csv"
                streamed_response.headers['Content-disposition'] = (
                                        'attachment; filename=%s' % filename)
            else:
                audit_iterator = JSONAuditIterator(audit_query)
                # TODO: Use stream_with_context instead of list
                streamed_response = Response(list(audit_iterator),
                                    content_type="application/json")

            c.audit['success'] = True
            Session.commit()

            return streamed_response

        except PolicyException as pe:
            log.exception("[getotp] gettoken/getotp policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, str(pe), 1)

        except Exception as e:
            log.exception("[search] audit/search failed: %r" % e)
            Session.rollback()
            return sendError(response, "audit/search failed", 0)

        finally:
            Session.close()


#eof###########################################################################

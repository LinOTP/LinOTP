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
audit controller - to search the audit trail
"""




import logging


from pylons import tmpl_context as c
from pylons import request, response, config
from linotp.lib.base import BaseController


from linotp.lib.util import  check_session
from linotp.lib.user import  getUserFromRequest
from linotp.lib.policy import checkPolicyPre
from linotp.lib.policy import PolicyException

from linotp.lib.reply import sendError
from linotp.lib.audit.iterator import AuditQuery
from linotp.lib.audit.iterator import CSVAuditIterator
from linotp.lib.audit.iterator import JSONAuditIterator

from linotp.lib.util import getParam
from linotp.lib.util import get_client

from linotp.model.meta import Session

from linotp.lib.config import getLinotpConfig

from linotp.lib.context import request_context

import traceback


audit = config.get('audit')

optional = True
required = False

log = logging.getLogger(__name__)


class AuditController(BaseController):

    '''
    this is the controller for doing some audit stuff

        https://server/audit/<functionname>

    '''

    def __before__(self, action, **params):


        try:
            c.audit = request_context['audit']
            c.audit['client'] = get_client(request)
            check_session(request)
            request_context['Audit'] = audit


        except Exception as exx:
            log.exception("[__before__::%r] exception %r" % (action, exx))
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')


    def __after__(self):
        c.audit['administrator'] = getUserFromRequest(request).get("login")
        audit.log(c.audit)


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

        param = {}
        try:
            param.update(request.params)

            log.debug("[search] params: %s" % param)

            checkPolicyPre('audit', 'view', {})

            # remove the param outform (and other parameters that should not
            # be used for search!
            search_params = {}
            search_params.update(param)
            for key in ["outform", 'delimiter']:
                if key in search_params:
                    del search_params[key]

            output_format = param.get("outform", 'json') or 'json'
            delimiter = param.get('delimiter', ',') or ','

            audit_iterator = None

            audit_query = AuditQuery(search_params, audit)

            if output_format == "csv":
                filename = "linotp-audit.csv"
                response.content_type = "application/force-download"
                response.headers['Content-disposition'] = (
                                        'attachment; filename=%s' % filename)

                audit_iterator = CSVAuditIterator(audit_query, delimiter)
            else:
                response.content_type = 'application/json'
                audit_iterator = JSONAuditIterator(audit_query)

            c.audit['success'] = True
            Session.commit()
            return audit_iterator

        except PolicyException as pe:
            log.exception("[getotp] gettoken/getotp policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[search] audit/search failed: %r" % e)
            Session.rollback()
            return sendError(response, "audit/search failed", 0)

        finally:
            Session.close()


#eof###########################################################################

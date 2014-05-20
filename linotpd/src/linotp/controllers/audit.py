# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
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
from linotp.lib.policy import checkPolicyPre, PolicyException

from linotp.lib.reply import sendError
from linotp.lib.audit.base import search as audit_search
from linotp.lib.audit.iterator import AuditIterator
from linotp.lib.audit.iterator import CSVAuditIterator
from linotp.lib.audit.iterator import JSONAuditIterator

from linotp.lib.util import getParam
from linotp.lib.util import get_client

from linotp.model.meta import Session

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


        log.debug("[__before__::%r] %r" % (action, params))

        try:
            audit.initialize()
            c.audit['client'] = get_client()
            check_session()

        except Exception as exx:
            log.error("[__before__::%r] exception %r" % (action, exx))
            log.error("[__before__] %s" % traceback.format_exc())
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')

        finally:
            log.debug("[__before__::%r] done" % (action))

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
                ('page', u'1'), ('rp', u'100'),
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

            output_format = getParam(param, "outform", optional)
            checkPolicyPre('audit', 'view', {})

            log.debug("[search] params %r" % param)

            # remove the param outform (and other parameters that should not
            # be used for search!
            search_params = {}
            for p in param:
                if p not in ["outform"]:
                    search_params[p] = param[p]

            log.debug("[search] search params %r" % search_params)

            audit_iterator = None
            base_audit_iterator = AuditIterator(search_params, audit)
            if output_format == "csv":
                filename = "linotp-audit.csv"
                response.content_type = "application/force-download"
                response.headers['Content-disposition'] = (
                                        'attachment; filename=%s' % filename)
                delimiter = search_params.get('delimiter', ',') or ','
                audit_iterator = CSVAuditIterator(base_audit_iterator, delimiter)
            else:
                response.content_type = 'application/json'
                audit_iterator = JSONAuditIterator(base_audit_iterator)

            c.audit['success'] = True
            Session.commit()
            return audit_iterator

        except PolicyException as pe:
            log.error("[getotp] gettoken/getotp policy failed: %r" % pe)
            log.error("[getotp] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.error("[search] audit/search failed: %r" % e)
            log.error("[search] %s" % traceback.format_exc())
            Session.rollback()
            return sendError(response, "audit/search failed: %s" % unicode(e), 0)

        finally:
            Session.close()
            log.debug('[search] done')


#eof###########################################################################

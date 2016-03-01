# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
tools controller
"""

from pylons import request, response
from pylons import tmpl_context as c

from linotp.lib.base import BaseController
from linotp.lib.reply import sendError
from linotp.lib.reply import sendResult

from linotp.lib.policy import PolicyException
from linotp.lib.policy import checkToolsAuthorisation
from linotp.lib.util import check_session

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
            log.debug("[__before__::%r] %r" % (action, params))

            # Session handling
            check_session()

            checkToolsAuthorisation(action, params,
                                    context=self.request_context)

            c.audit = self.request_context['audit']
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

        finally:
            log.debug("[__before__::%r] done" % (action))

    def __after__(self, action):
        """
        """
        try:
            # finally create the audit entry
            Audit = self.request_context['Audit']
            audit = self.request_context.get('audit')
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
            log.debug("[__after__] done")

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

            mg = MigrateResolverHandler(context=self.request_context)
            ret = mg.migrate_resolver(src=src_resolver,
                                      target=target_resolver)

            Session.commit()
            return sendResult(response, ret)

        except Exception as e:
            log.exception("failed: %r" % e)
            Session.rollback()
            log.error('error getting token owner')
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('[enable] done')


#eof###########################################################################


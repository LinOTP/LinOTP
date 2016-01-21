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
account controller - used for loggin in to the selfservice
"""


import traceback

from pylons import request, response, tmpl_context as c
from pylons.controllers.util import abort, redirect

from linotp.lib.base import BaseController
from pylons.templating import render_mako as render

from linotp.lib.reply   import sendError
from linotp.model.meta  import Session

from linotp.lib.util    import get_version
from linotp.lib.util    import get_copyright_info

from linotp.lib.realm    import getRealms
from linotp.lib.realm    import getDefaultRealm
from linotp.lib.user     import getRealmBox



import logging
import webob


log = logging.getLogger(__name__)


optional = True
required = False

# The HTTP status code, that determines that
# the Login to the selfservice portal is required.
# Is also defined in selfservice.js
LOGIN_CODE = 576

class AccountController(BaseController):
    '''
    The AccountController
        /account/
    is responsible for authenticating the users for the selfservice portal.
    It has the following functions:
        /account/login
        /account/dologin
    '''


    def __before__(self, action, **params):

        log.debug("[__before__::%r] %r" % (action, params))

        try:
            c.version = get_version()
            c.licenseinfo = get_copyright_info()

        except webob.exc.HTTPUnauthorized as acc:
            ## the exception, when an abort() is called if forwarded
            log.exception("[__before__::%r] webob.exception %r" % (action, acc))
            Session.rollback()
            Session.close()
            raise acc

        except Exception as exx:
            log.exception("[__before__::%r] exception %r" % (action, exx))
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')

        finally:
            log.debug("[__before__::%r] done" % (action))

    def login(self):
        log.debug("[login] selfservice login screen")
        identity = request.environ.get('repoze.who.identity')
        if identity is not None:
            # After login We always redirect to the start page
            redirect("/")

        res = {}
        try:
            c.defaultRealm = getDefaultRealm()
            res = getRealms()

            c.realmArray = []
            #log.debug("[login] %s" % str(res) )
            for (k, v) in res.items():
                c.realmArray.append(k)

            c.realmbox = getRealmBox()
            log.debug("[login] displaying realmbox: %i" % int(c.realmbox))

            Session.commit()
            response.status = '%i Logout from LinOTP selfservice' % LOGIN_CODE
            return render('/selfservice/login.mako')

        except Exception as e:
            log.exception('[login] failed %r' % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()


    def test(self):
        identity = request.environ.get('repoze.who.identity')
        if identity is None:
            # Force skip the StatusCodeRedirect middleware; it was stripping
            #   the WWW-Authenticate header from the 401 response
            request.environ['pylons.status_code_redirect'] = True
            # Return a 401 (Unauthorized) response and signal the repoze.who
            #   basicauth plugin to set the WWW-Authenticate header.
            abort(401, 'You are not authenticated')

        log.debug(u"[test] identity: %r" % identity)
        return """
<body>
Hello, you are logged in as %s.
<a href="/account/logout">logout</a>
</body>
</html>
""" % identity['repoze.who.userid']


#eof##########################################################################


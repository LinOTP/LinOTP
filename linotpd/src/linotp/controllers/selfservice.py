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
selfservice controller - This is the controller for the self service interface,
                where users can manage their own tokens

                All functions starting with /selfservice/user...
                are data functions and protected by the session key
                i.e. the session key must be passed as the parameter session=

"""
import os
import json
import webob

from paste.httpexceptions import HTTPFound

from pylons import request
from pylons import response
from pylons import config
from pylons import tmpl_context as c
from pylons import url

from pylons.controllers.util import abort
from pylons.controllers.util import redirect
from pylons.templating import render_mako as render
from pylons.i18n.translation import _

from mako.exceptions import CompileException

import linotp.model
from linotp.lib.base import BaseController
from linotp.lib.error import ParameterError

from linotp.lib.token import getTokenType
from linotp.lib.token import getTokens4UserOrSerial

from linotp.lib.policy import getSelfserviceActions
from linotp.lib.policy import _get_auth_PinPolicy

from linotp.lib.util import remove_empty_lines

from linotp.lib.reply import sendError

from linotp.lib.realm import getRealms
from linotp.lib.realm import getDefaultRealm

from linotp.lib.user import getRealmBox

from linotp.lib.util import get_version
from linotp.lib.util import get_copyright_info
from linotp.lib.util import get_client


from linotp.lib.userservice import add_dynamic_selfservice_enrollment
from linotp.lib.userservice import add_dynamic_selfservice_policies
from linotp.lib.userservice import get_pre_context
from linotp.lib.userservice import remove_auth_cookie
from linotp.lib.userservice import check_session

from linotp.lib.selfservice import get_imprint

from linotp.lib.selftest import isSelfTest
from linotp.controllers.userservice import get_auth_user

from linotp.tokens import tokenclass_registry
from linotp.lib.context import request_context

import logging

Session = linotp.model.Session

ENCODING = "utf-8"
log = logging.getLogger(__name__)
audit = config.get('audit')


def getTokenForUser(user):
    """
    should be moved to token.py
    """
    tokenArray = []

    log.debug("[getTokenForUser] ...user %s in realm %s." %
              (user.login, user.realm))
    tokens = getTokens4UserOrSerial(user=user, serial=None, _class=False)

    for token in tokens:
        tok = token.get_vars()
        if tok.get('LinOtp.TokenInfo', None):
            token_info = json.loads(tok.get('LinOtp.TokenInfo'))
            tok['LinOtp.TokenInfo'] = token_info
        tokenArray.append(tok)

    log.debug("[getTokenForUser] found tokenarray: %r" % tokenArray)
    return tokenArray


class SelfserviceController(BaseController):

    authUser = None

    # the following actions don't require a session parameter
    # as they are only callbacks to render a form
    form_access_methods = [
        "activateocratoken",
        "assign",
        "custom_style",
        "delete",
        "disable",
        "enable",
        "getotp",
        "history",
        "index",
        "load_form",
        "reset",
        "resync",
        "setmpin",
        "setpin",
        "unassign",
        "webprovisiongoogletoken",
        "webprovisionoathtoken"
    ]

    def __before__(self, action):
        '''
        This is the authentication to self service. If you want to do
        ANYTHING with the selfservice, you need to be authenticated. The
        _before_ is executed before any other function in this controller.
        '''

        self.redirect = None

        try:
            c.version = get_version()
            c.licenseinfo = get_copyright_info()

            c.audit = request_context['audit']
            c.audit['success'] = False
            self.client = get_client(request)
            c.audit['client'] = self.client

            request_context['Audit'] = audit

            # -------------------------------------------------------------- --

            # handle requests which dont require authetication

            if action in ['logout', 'custom_style']:
                return

            # -------------------------------------------------------------- --

            # get the authenticated user

            auth_type, auth_user, auth_state = get_auth_user(request)

            # -------------------------------------------------------------- --

            # handle not authenticated requests

            if not auth_user or auth_type not in ['user_selfservice']:

                if action in ['login']:
                    return

                if action in ['index']:
                    self.redirect = True
                    redirect(url(controller='selfservice', action='login'))

                else:
                    abort(403, "No valid session")

            # -------------------------------------------------------------- --

            # handle authenticated requests

            # there is only one special case, which is the login that
            # could be forwarded to the index page

            if action in ['login']:
                if auth_state != 'authenticated':
                    return

                self.redirect = True
                redirect(url(controller='selfservice', action='index'))

            # -------------------------------------------------------------- --

            # in case of user_selfservice, an unauthenticated request should always go to login
            if auth_user and auth_type is 'user_selfservice' \
                    and auth_state is not 'authenticated':
                self.redirect = True
                redirect(url(controller='selfservice', action='login'))


            # futher processing with the authenticated user

            if auth_state != 'authenticated':
                abort(403, "No valid session")

            c.user = auth_user.login
            c.realm = auth_user.realm
            self.authUser = auth_user

            # -------------------------------------------------------------- --

            # authenticated session verification

            if auth_type == 'user_selfservice':

                # checking the session only for not_form_access actions
                if action not in self.form_access_methods:

                    valid_session = check_session(request,
                                                  auth_user,
                                                  self.client)

                    if not valid_session:
                        c.audit['action'] = request.path[1:]
                        c.audit['info'] = "session expired"
                        audit.log(c.audit)

                        abort(403, "No valid session")

            # -------------------------------------------------------------- --

            c.imprint = get_imprint(c.realm)

            c.tokenArray = []

            c.user = self.authUser.login
            c.realm = self.authUser.realm

            # only the defined actions should be displayed
            # - remark: the generic actions like enrollTT are allready approved
            #   to have a rendering section and included
            actions = getSelfserviceActions(self.authUser)
            c.actions = actions
            for policy in actions:
                if policy:
                    if "=" not in policy:
                        c.__setattr__(policy, -1)
                    else:
                        (name, val) = policy.split('=')
                        val = val.strip()
                        # try if val is a simple numeric -
                        # w.r.t. javascript evaluation
                        try:
                            nval = int(val)
                        except ValueError:
                            nval = val
                        c.__setattr__(name.strip(), nval)

            c.dynamic_actions = add_dynamic_selfservice_enrollment(config,
                                                                   c.actions)

            # we require to establish all token local defined
            # policies to be initialiezd
            additional_policies = add_dynamic_selfservice_policies(config,
                                                                   actions)
            for policy in additional_policies:
                c.__setattr__(policy, -1)

            c.otplen = -1
            c.totp_len = -1

            c.pin_policy = _get_auth_PinPolicy(user=self.authUser)

            return response

        except (webob.exc.HTTPUnauthorized, webob.exc.HTTPForbidden) as acc:
            # the exception, when an abort() is called if forwarded
            log.info("[__before__::%r] webob.exception %r" % (action, acc))
            Session.rollback()
            Session.close()
            raise acc

        except HTTPFound as exx:
            raise exx

        except Exception as e:
            log.exception("[__before__] failed with error: %r" % e)
            Session.rollback()
            Session.close()
            return sendError(response, e, context='before')

    def __after__(self, action,):
        '''

        '''
        if self.redirect:
            return

        param = request.params

        try:
            if c.audit['action'] in ['selfservice/index']:
                if isSelfTest():
                    log.debug("[__after__] Doing selftest!")

                    if "selftest_user" in param:
                        (c.user, _foo, c.realm) = param[
                            "selftest_user"].rpartition('@')
                    else:
                        c.realm = ""
                        c.user = "--ua--"
                        env = request.environ
                        uuser = env.get('REMOTE_USER')
                        if uuser is not None:
                            (c.user, _foo, c.realm) = uuser.rpartition('@')

                log.debug("[__after__] authenticating as %s in realm %s!"
                          % (c.user, c.realm))

                c.audit['user'] = c.user
                c.audit['realm'] = c.realm
                c.audit['success'] = True

                if 'serial' in param:
                    c.audit['serial'] = param['serial']
                    c.audit['token_type'] = getTokenType(param['serial'])

                audit.log(c.audit)

            return response

        except webob.exc.HTTPUnauthorized as acc:
            # the exception, when an abort() is called if forwarded
            log.exception("[__after__::%r] webob.exception %r" % (action, acc))
            Session.rollback()
            Session.close()
            raise acc

        except Exception as e:
            log.exception("[__after__] failed with error: %r" % e)
            Session.rollback()
            Session.close()
            return sendError(response, e, context='after')

    def index(self):
        '''
        This is the redirect to the first template
        '''

        c.title = _("LinOTP Self Service")
        return render('selfservice/base.mako')

    def logout(self):
        """
        handle the logout

        we delete the cookies from the server and the client and
        redirect to the login page
        """

        cookie = request.cookies.get('user_selfservice')
        if cookie:
            remove_auth_cookie(cookie)
            response.delete_cookie('user_selfservice')

        self.redirect = True
        redirect(url(controller='selfservice', action='login'))

    def login(self):
        '''
        render the selfservice login page
        '''

        cookie = request.cookies.get('user_selfservice')
        if cookie:
            remove_auth_cookie(cookie)
            response.delete_cookie('user_selfservice')

        c.title = _("LinOTP Self Service Login")

        # ------------------------------------------------------------------ --

        # prepare the realms and put the default realm on the top

        defaultRealm = getDefaultRealm()
        realmArray = [defaultRealm]

        for realm in getRealms():
            if realm != defaultRealm:
                realmArray.append(realm)

        # ------------------------------------------------------------------ --

        # prepare the global context c for the rendering context

        c.defaultRealm = defaultRealm
        c.realmArray = realmArray

        c.realmbox = getRealmBox()

        context = get_pre_context(c.audit['client'])

        mfa_login = context['mfa_login']
        mfa_3_fields = context['mfa_3_fields']

        c.otp = False
        c.mfa_3_fields = False
        if mfa_login and mfa_3_fields:
            c.mfa_3_fields = True

        return render('/selfservice/login.mako')

    def load_form(self):
        '''
        This shows the enrollment form for a requested token type.

        implicit parameters are:

        :param type: token type
        :param scope: defines the rendering scope

        :return: rendered html of the requested token
        '''
        res = ''
        param = {}

        try:

            param.update(request.params)

            try:
                act = param["type"]
            except KeyError:
                raise ParameterError("Missing parameter: 'type'", id=905)

            try:
                (tok, section, scope) = act.split('.')
            except Exception:
                return res

            if section != 'selfservice':
                return res

            if tok in tokenclass_registry:
                tclt = tokenclass_registry.get(tok)
                if hasattr(tclt, 'getClassInfo'):
                    sections = tclt.getClassInfo(section, {})
                    if scope in sections.keys():
                        section = sections.get(scope)
                        page = section.get('page')
                        c.scope = page.get('scope')
                        c.authUser = self.authUser
                        html = page.get('html')
                        res = render(os.path.sep + html)
                        res = remove_empty_lines(res)

            Session.commit()
            return res

        except CompileException as exx:
            log.exception("[load_form] compile error while processing %r.%r:"
                          "Exeption was %r" % (tok, scope, exx))
            Session.rollback()
            raise exx

        except Exception as exx:
            Session.rollback()
            error = ('error (%r) accessing form data for: tok:%r, scope:%r'
                     ', section:%r' % (exx, tok, scope, section))
            log.exception(error)
            return '<pre>%s</pre>' % error

        finally:
            Session.close()

    def custom_style(self):
        '''
        In case the user hasn't defined a custom css, Pylons calls this action.
        Return an empty file instead of a 404 (which would mean hitting the
        debug console)
        '''
        response.headers['Content-type'] = 'text/css'
        return ''

    def assign(self):
        '''
        In this form the user may assign an already existing Token to himself.
        For this, the user needs to know the serial number of the Token.
        '''
        return render('/selfservice/assign.mako')

    def resync(self):
        '''
        In this form, the user can resync an HMAC based OTP token
        by providing two OTP values
        '''
        return render('/selfservice/resync.mako')

    def reset(self):
        '''
        In this form the user can reset the Failcounter of the Token.
        '''
        return render('/selfservice/reset.mako')

    def getotp(self):
        '''
        In this form, the user can retrieve OTP values
        '''
        return render('/selfservice/getotp.mako')

    def disable(self):
        '''
        In this form the user may select a token of his own and
        disable this token.
        '''
        return render('/selfservice/disable.mako')

    def enable(self):
        '''
        In this form the user may select a token of his own and
        enable this token.
        '''
        return render('/selfservice/enable.mako')

    def unassign(self):
        '''
        In this form the user may select a token of his own and
        unassign this token.
        '''
        return render('/selfservice/unassign.mako')

    def delete(self):
        '''
        In this form the user may select a token of his own and
        delete this token.
        '''
        return render('/selfservice/delete.mako')

    def setpin(self):
        '''
        In this form the user may set the OTP PIN, which is the static password
        he enters when logging in in front of the otp value.
        '''
        return render('/selfservice/setpin.mako')

    def setmpin(self):
        '''
        In this form the user my set the PIN for his mOTP application soft
        token on his phone. This is the pin, he needs to enter on his phone,
        before a otp value will be generated.
        '''
        return render('/selfservice/setmpin.mako')

    def history(self):
        '''
        This is the form to display the history table for the user
        '''
        return render('/selfservice/history.mako')

    def webprovisionoathtoken(self):
        '''
        This is the form for an oathtoken to do web provisioning.
        '''
        return render('/selfservice/webprovisionoath.mako')

    def activateocratoken(self):
        '''
        return the form for an ocra token activation
        '''
        return render('/selfservice/activateocra.mako')

    def webprovisiongoogletoken(self):
        '''
        This is the form for an google token to do web provisioning.
        '''
        try:
            c.actions = getSelfserviceActions(self.authUser)
            return render('/selfservice/webprovisiongoogle.mako')

        except Exception as exx:
            log.exception(
                "[webprovisiongoogletoken] failed with error: %r" % exx)
            return sendError(response, exx)

    def usertokenlist(self):
        '''
        This returns a tokenlist as html output
        '''
        c.tokenArray = getTokenForUser(self.authUser)
        res = render('/selfservice/tokenlist.mako')
        return res


# eof #

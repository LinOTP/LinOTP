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
userservice controller -
     This is the controller for the user self service
     interface, where an authenitcated users can manage their own tokens

There are three types of requests
  * the context requests: before, context
  * the auth requests: auth, userinfo
  * the admin requests

At least all admin request must provide the auth cookie and the username
- the auth cookie is verified by decryption
- the username is checked for valid policy acceptance

Remarks:
 * the userinfo request could use the cookie check as it is running after
   the authorization request,  but no policy definition is required
 * the context request might as well run for an authenticated user, thus
   auth request but no policy check

"""

import copy
import os
import logging
import base64

try:
    import json
except ImportError:
    import simplejson as json

from pylons import (request,
                     response,
                     config,
                     tmpl_context as c
                     )

from pylons.controllers.util import abort

from pylons.templating import render_mako as render
from mako.exceptions import CompileException


from linotp.model.meta import Session

from linotp.lib.base import BaseController

from linotp.lib.policy import (checkPolicyPre,
                               checkPolicyPost,
                               PolicyException,
                               getOTPPINEncrypt,
                               checkOTPPINPolicy,
                               get_client_policy,
                               )

from linotp.lib.reply import (sendResult,
                              sendError,
                              sendQRImageResult,
                              create_img
                              )

from linotp.lib.util import (generate_otpkey,
                             get_client,
                             remove_empty_lines
                             )

from linotp.lib.realm import getDefaultRealm

from linotp.lib.user import (getUserInfo,
                              User,
                              getUserId)

from linotp.lib.token import (enableToken,
                              isTokenOwner,
                              removeToken,
                              resetToken,
                              unassignToken,
                              setPin,
                              setPinUser,
                              resyncToken,
                              getTokenRealms,
                              hasOwner,
                              assignToken,
                              get_serial_by_otp,
                              initToken,
                              genSerial,
                              get_multi_otp,
                              getTokenType,
                              newToken,
                              get_tokenserial_of_transaction,
                              getTokens4UserOrSerial,
                              checkSerialPass,
                              )

from linotp.lib.tokenclass import OcraTokenClass

from linotp.lib.apps import (create_google_authenticator,
                             create_oathtoken_url
                             )

from pylons.i18n.translation import _

from linotp.lib.audit.base import (logTokenNum,
                                   search as audit_search
                                   )

from linotp.lib.userservice import (get_userinfo,
                                    check_userservice_session,
                                    get_pre_context,
                                    get_context,
                                    create_auth_cookie,
                                    getTokenForUser
                                    )

from linotp.lib.util import (check_selfservice_session,
                             isSelfTest
                            )

from linotp.lib.token import (checkUserPass,
                              auto_enrollToken,
                              auto_assignToken,
                              )

from linotp.lib.resolver import getResolverObject

from linotp.lib.error import ParameterError

log = logging.getLogger(__name__)
audit = config.get('audit')

ENCODING = "utf-8"


def get_auth_user(request):
    """
    retrieve the authenticated user either from
    - repoze or userservice or selftest

    remark: should be moved in a utils thing, as it is used as well from
            selfservice

    :param request: the request object
    :return: tuple of (authentication type and authenticated user)
    """
    auth_type = ''

    repose_auth = request.environ.get('repoze.who.identity')
    if repose_auth:
        log.debug("getting identity from repoze.who: %r" % repose_auth)
        user_id = request.environ.get('repoze.who.identity', {})\
                                 .get('repoze.who.userid', '')
        auth_type = "repoze"
    else:
        log.debug("getting identity from params: %r" % request.params)
        user_id = request.params.get('user', None)
        auth_type = "userservice"

    if not user_id and isSelfTest():
        user_id = request.params.get('selftest_user', '')
        auth_type = "selftest"

    if not user_id:
        return ('unauthenticated', None)

    if type(user_id) == unicode:
        user_id = user_id.encode(ENCODING)
    identity = user_id.decode(ENCODING)

    return (auth_type, identity)


class UserserviceController(BaseController):
    """
    the interface from the service into linotp to execute the actions for the
    user in the scope of the selfservice

    after the login, the selfservice user gets an auth cookie, which states
    that he already has been authenticated. This cookie is provided on every
    request during which the auth_cookie and session is verified
    """

    def __before__(self, action, **parameters):
        # if action is not an authentication request:
        # - check if there is a cookie in the headers and in the session param
        # - check if the decrypted cookie user and client are the same as
        #   the requesting user / client

        self.client = get_client() or ''

        if action not in ['auth', 'pre_context']:
            auth_type, identity = get_auth_user(request)
            if not identity:
                abort(401, _("You are not authenticated"))

            login, _foo, realm = identity.rpartition('@')
            self.authUser = User(login, realm)

            if auth_type == "userservice":
                res = check_userservice_session(request, config,
                                                self.authUser, self.client)
            elif auth_type == 'repoze':
                call_url = "userservice/%s" % action
                res = check_selfservice_session(url=call_url,
                                                cookies=request.cookies,
                                                params=request.params)
            elif auth_type == 'selftest':
                res = True
            else:
                abort(401, _("No valid authentication session %r") % auth_type)

            if not res:
                abort(401, _("No valid session"))

        context = get_pre_context(self.client)
        self.otpLogin = context['otpLogin']
        self.autoassign = context['autoassign']
        self.autoenroll = context['autoenroll']

        audit.initialize()
        c.audit['success'] = False
        c.audit['client'] = self.client

        return

    def __after__(self, action, **params):
        '''
        '''
        param = request.params

        try:
            if c.audit['action'] not in ['userservice/context',
                                         'userservice/pre_context',
                                         'userservice/userinfo',
                                         'userservice/load_form'
                                         ]:

                if hasattr(self, 'authUser') and not self.authUser.isEmpty():
                    c.audit['user'] = self.authUser.login
                    c.audit['realm'] = self.authUser.realm
                else:
                    c.audit['user'] = ''
                    c.audit['realm'] = ''

                log.debug("[__after__] authenticating as %s in realm %s!"
                          % (c.audit['user'], c.audit['realm']))

                if param.has_key('serial'):
                    c.audit['serial'] = param['serial']
                    c.audit['token_type'] = getTokenType(param['serial'])

                audit.log(c.audit)
            return response

        except Exception as acc:
            # the exception, when an abort() is called if forwarded
            log.exception("[__after__::%r] webob.exception %r" % (action, acc))
            raise acc

        finally:
            log.debug("%s done" % action)

###############################################################################
# authentication hooks

    def auth(self):
        """
        user authentication for example to the remote selfservice

        :param login: login name of the user normaly in the user@realm format
        :param realm: the realm of the user
        :param password: the password for the user authentication
                         which is base32 encoded to seperate the
                         os_passw:pin+otp in case of otpLogin

        :return: {result : {value: bool} }
        :rtype: json dict with bool value
        """

        ok = False
        param = {}

        try:
            param.update(request.params)
            login = param['login']
            password = param['password']
        except KeyError as exx:
            return sendError(response, "Missing Key: %r" % exx)

        try:
            res = False
            uid = ""
            user = User()

            (otp, passw) = password.split(':')
            otp = base64.b32decode(otp)
            passw = base64.b32decode(passw)


            if '@' in login:
                user, rrealm = login.split("@")
                user = User(user, rrealm)
            else:
                realm = getDefaultRealm()
                user = User(login, realm)

            uid = "%s@%s" % (user.login, user.realm)

            if self.otpLogin:
                res = self._otpLogin_check(user, passw, otp)
            else:
                res = self._default_auth_check(user, passw, otp)

            if res:
                log.debug("Successfully authenticated user %s:" % uid)
                cookie = create_auth_cookie(config, user, self.client)
                response.set_cookie('userauthcookie' , cookie, max_age=180 * 24 * 360)
                ok = uid
            else:
                log.info("User %s failed to authenticate!" % uid)


            c.audit['success'] = True
            Session.commit()
            return sendResult(response, ok, 0)

        except Exception as exx:
            c.audit['info'] = ("%r" % exx)[:80]
            Session.rollback()
            return sendError(response, exx)

        finally:
            Session.close()

    def _default_auth_check(self, user, password, otp=None):
        """
        the former selfservice login controll:
         check for username and os_pass

        :param user: user object
        :param password: the expected os_password
        :param otp: not used

        :return: bool
        """
        (uid, _resolver, resolver_class) = getUserId(user)
        r_obj = getResolverObject(resolver_class)
        res = r_obj.checkPass(uid, password)
        return res

    def _otpLogin_check(self, user, password, otp):
        """
        secure auth requires the os password and the otp (pin+otp)
        - secure auth supports autoassignement, where the user logs in with
                      os_password and only the otp value. If user has no token,
                      a token with a matching otp in the window is searched
        - secure auth supports autoenrollment, where a user with no token will
                      get automaticaly enrolled one token.

        :param user: user object
        :param password: the os_password
        :param otp: empty (for autoenrollment),
                    otp value only for auto assignment or
                    pin+otp for standard authentication (respects otppin ploicy)

        :return: bool
        """
        ret = False

        passwd_match = self._default_auth_check(user, password, otp)

        if passwd_match:
            toks = getTokenForUser(user)

            # if user has no token, we check for auto assigneing one to him
            if len(toks) == 0:

                # if no token and otp, we might do an auto assign
                if self.autoassign and otp:
                    ret = auto_assignToken(password + otp, user)

                # if no token no otp, we might trigger an aouto enroll
                elif self.autoenroll and not otp:
                    (auto_enroll_return, reply) = auto_enrollToken(password, user)
                    if auto_enroll_return is False:
                        error = ("autoenroll: %r" % reply.get('error', ''))
                        log.error(error)
                        raise Exception(error)
                    # we always have to return a false, as we have a challenge tiggered
                    ret = False

            # user has at least one token, so we do a check on pin + otp
            else:
                (ret, _reply) = checkUserPass(user, otp)
        return ret



    def userinfo(self):
        """
        hook for the repoze auth, which requests additional user info
        """
        param = {}

        try:
            param.update(request.params)
            login = param['user']
        except KeyError as exx:
            return sendError(response, "Missing Key: %r" % exx)

        try:

            uinfo = get_userinfo(login)

            c.audit['success'] = True

            Session.commit()
            return sendResult(response, uinfo, 0)


        except Exception as exx:
            Session.rollback()
            error = ('error (%r) ' % exx)
            log.exception(error)
            return '<pre>%s</pre>' % error

        finally:
            Session.close()
            log.debug('done')


###############################################################################
# context setup functionsa

    def pre_context(self):
        '''
        This is the authentication to self service
        If you want to do ANYTHING with selfservice, you need to be authenticated
        The _before_ is executed before any other function in this controller.
        '''
        param = {}
        try:
            param.update(request.params)

            context = get_pre_context(self.client)
            response.content_type = 'application/json'
            return json.dumps(context, indent=3)

        except Exception as e:
            log.exception("failed with error: %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            log.debug('done')
            Session.close()

    def context(self):
        '''
        This is the authentication to self service
        If you want to do ANYTHING with selfservice, you need to be authenticated
        The _before_ is executed before any other function in this controller.
        '''
        param = {}
        try:
            param.update(request.params)
            user = param['user']

            if "@" in user:
                user, realm = user.split('@')
            else:
                realm = getDefaultRealm()

            context = get_context(config, user, realm, self.client)
            response.content_type = 'application/json'
            return json.dumps(context, indent=3)

        except KeyError as err:
            log.exception("[context] failed with error: %r" % err)
            Session.rollback()
            return sendError(response, "required parameter: %r" % err)

        except Exception as e:
            log.exception("[context] failed with error: %r" % e)
            Session.rollback()
            return sendError(response, e)

        finally:
            Session.close()
            log.debug('[context] done')


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
                act = param[ "type"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            try:
                (tok, section, scope) = act.split('.')
            except Exception:
                return res

            if section != 'selfservice':
                return res

            user = self.authUser.login
            realm = self.authUser.realm

            context = get_context(config, user, realm, self.client)
            for k, v in context.items():
                setattr(c, k, v)

            g = config['pylons.app_globals']
            tokenclasses = copy.deepcopy(g.tokenclasses)

            if tok in tokenclasses:
                tclass = tokenclasses.get(tok)
                tclt = newToken(tclass)
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
            c.audit['success'] = True
            return res

        except CompileException as exx:
            log.exception("[load_form] compile error while processing %r.%r:" %
                                                                (tok, scope))
            log.exception("[load_form] %r" % exx)
            Session.rollback()
            raise Exception(exx)

        except Exception as exx:
            Session.rollback()
            error = ('error (%r) accessing form data for: %r' % exx)
            log.exception(error)
            return '<pre>%s</pre>' % error

        finally:
            Session.close()
            log.debug('[load_form] done')



# action hooks for the js methods #############################################
    def enable (self):
        """
        enables a token or all tokens of a user

        as this is a controller method, the parameters are taken from
        request.params

        :param serial: serial number of the token *required
        :param user: username in format user@realm *required

        :return: a linotp json doc with result {u'status': True, u'value': 2}

        """
        param = {}
        res = {}
        log.debug("remoteservice enable to enable/disable a token")

        try:
            param.update(request.params)
            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'userenable', param, authUser=self.authUser)

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("[userenable] user %s@%s is enabling his token with serial %s."
                            % (self.authUser.login, self.authUser.realm, serial))
                ret = enableToken(True, None, serial)
                res["enable token"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("[enable] policy failed %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[enable] failed: %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('[enable] done')

########################################################
    def disable (self):
        """
        disables a token

        as this is a controller method, the parameters are taken from
        request.params

        :param serial: serial number of the token *required
        :param user: username in format user@realm *required

        :return: a linotp json doc with result {u'status': True, u'value': 2}

        """
        param = {}
        res = {}
        log.debug("remoteservice disable a token")

        try:
            param.update(request.params)

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'userdisable', param,
                           authUser=self.authUser)

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is disabling his token with serial %s."
                            % (self.authUser.login, self.authUser.realm, serial))
                ret = enableToken(False, None, serial)
                res["disable token"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("policy failed %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("failed: %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('done')

    def delete(self):
        '''
        This is the internal delete token function that is called from within the self service portal
        The user is only allowed to delete token, that belong to him.
        '''
        param = {}
        res = {}

        try:
            param.update(request.params)
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userdelete', param, self.authUser)

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("[userdelete] user %s@%s is deleting his token with serial %s."
                            % (self.authUser.login, self.authUser.realm, serial))
                ret = removeToken(serial=serial)
                res["delete token"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("[userdelete] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[userdelete] deleting token %s of user %s failed! %r"
                      % (serial, c.user, e))
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('[userdelete] done')

    def reset(self):
        '''
        This internally resets the failcounter of the given token.
        '''
        res = {}
        param = {}
        serial = None

        try:
            param.update(request.params)
            checkPolicyPre('selfservice', 'userreset', param, self.authUser)
            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("[userreset] user %s@%s is resetting the failcounter"
                                " of his token with serial %s"
                        % (self.authUser.login, self.authUser.realm, serial))
                ret = resetToken(serial=serial)
                res["reset Failcounter"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("error resetting token with serial %s: %r"
                      % (serial, e))
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('done')

    def unassign(self):
        '''
        This is the internal unassign function that is called from within
        the self service portal. The user is only allowed to unassign token,
        that belong to him.
        '''
        param = {}
        res = {}

        try:
            # check selfservice authorization
            param.update(request.params)
            checkPolicyPre('selfservice', 'userunassign', param, self.authUser)

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            upin = param.get("pin", None)

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is unassigning his token with serial %s."
                         % (self.authUser.login, self.authUser.realm, serial))

                ret = unassignToken(serial, None, upin)
                res["unassign token"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("unassigning token %s of user %s failed! %r"
                       % (serial, c.user, e))
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('done')

    def setpin(self):
        '''
        When the user hits the set pin button, this function is called.
        '''
        res = {}
        param = {}

        # # if there is a pin
        try:
            param.update(request.params)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'usersetpin', param, self.authUser)
            try:
                userPin = param["userpin"]
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is setting the OTP PIN "
                         "for token with serial %s" %
                         (self.authUser.login, self.authUser.realm, serial))

                check_res = checkOTPPINPolicy(userPin, self.authUser)

                if not check_res['success']:
                    log.warning("Setting of OTP PIN for Token %s"
                                " by user %s failed: %s" %
                                        (serial, c.user, check_res['error']))
                    return sendError(response, _("Error: %s")
                                                        % check_res['error'])

                if 1 == getOTPPINEncrypt(serial=serial,
                                         user=User(c.user, "", c.realm)):
                    param['encryptpin'] = "True"
                ret = setPin(userPin, None, serial, param)
                res["set userpin"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pex:
            log.exception("policy failed: %r" % pex)
            Session.rollback()
            return sendError(response, unicode(pex), 1)

        except Exception as exx:
            log.exception("Error setting OTP PIN: %r" % exx)
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()
            log.debug('done')

    def setmpin(self):
        '''
        When the user hits the set pin button, this function is called.
        '''
        res = {}
        param = {}
        # # if there is a pin
        try:
            param.update(request.params)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'usersetmpin', param, self.authUser)
            try:
                pin = param["pin"]
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is setting the mOTP PIN"
                         " for token with serial %s"
                          % (self.authUser.login, self.authUser.realm, serial))
                ret = setPinUser(pin, serial)
                res["set userpin"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pex:
            log.exception("policy failed: %r" % pex)
            Session.rollback()
            return sendError(response, unicode(pex), 1)

        except Exception as exx:
            log.exception("Error setting the mOTP PIN %r" % exx)
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()
            log.debug('done')

    def resync(self):
        '''
        This is the internal resync function that is called from within the self service portal
        '''

        res = {}
        param = {}
        serial = "N/A"

        try:
            param.update(request.params)
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userresync', param, self.authUser)

            try:
                serial = param["serial"]
                otp1 = param["otp1"]
                otp2 = param["otp2"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            if (True == isTokenOwner(serial, self.authUser)):
                log.info("user %s@%s is resyncing his "
                          "token with serial %s"
                        % (self.authUser.login, self.authUser.realm, serial))
                ret = resyncToken(otp1, otp2, None, serial)
                res["resync Token"] = ret

                c.audit['success'] = ret

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("error resyncing token with serial %s:%r"
                       % (serial, e))
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('done')

    def assign(self):
        '''
        This is the internal assign function that is called from within
        the self service portal
        '''
        param = {}
        res = {}

        try:
            param.update(request.params)
            # check selfservice authorization
            checkPolicyPre('selfservice', 'userassign', param, self.authUser)

            upin = param.get("pin", None)

            try:
                serial = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)


            # check if token is in another realm
            realm_list = getTokenRealms(serial)
            if (not self.authUser.realm.lower() in realm_list
                        and len(realm_list)):
                # if the token is assigned to realms, then the user must be in
                # one of the realms, otherwise the token can not be assigned
                raise Exception(_("The token you want to assign is "
                                             " not contained in your realm!"))

            if (False == hasOwner(serial)):
                log.info("user %s@%s is assign the token with "
                                                    "serial %s to himself."
                        % (self.authUser.login, self.authUser.realm, serial))
                ret = assignToken(serial, self.authUser, upin)
                res["assign token"] = ret

                c.audit['success'] = ret
            else:
                raise Exception(_("The token is already assigned "
                                             "to another user."))

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("[userassign] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx:
            log.exception("[userassign] token assignment failed! %r" % exx)
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            Session.close()
            log.debug('[userassign] done')


    def getSerialByOtp(self):
        '''
         method:
            selfservice/usergetSerialByOtp

        description:
            searches for the token, that generates the given OTP value.
            The search can be restricted by several critterions
            This method only searches tokens in the realm of the user
            and tokens that are not assigned!

        arguments:
            otp      - required. Will search for the token, that produces
                       this OTP value
            type     - optional, will only search in tokens of type

        returns:
            a json result with the serial


        exception:
            if an error occurs an exception is serialized and returned

        '''
        param = {}
        res = {}
        try:
            param.update(request.params)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'usergetserialbyotp', param,
                                                                self.authUser)
            try:
                otp = param["otp"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            ttype = param.get("type", None)

            c.audit['token_type'] = ttype
            serial, _username, _resolverClass = get_serial_by_otp(None,
                    otp, 10, typ=ttype, realm=self.authUser.realm, assigned=0)
            res = {'serial' : serial}

            c.audit['success'] = 1
            c.audit['serial'] = serial

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx:
            log.exception("token getSerialByOtp failed! %r" % exx)
            Session.rollback()
            return sendError(response, exx, 1)

        finally:
            log.debug('done')
            Session.close()

    def enroll(self):
        '''
        enroll token
        '''
        response_detail = {}
        param = {}

        try:
            param.update(request.params)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'userinit', param, self.authUser)

            try:
                tok_type = param["type"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            serial = param.get('serial', None)
            prefix = param.get('prefix', None)

            if not serial:
                serial = genSerial(tok_type, prefix)
                param['serial'] = serial

            desc = param.get("description", '')
            otppin = param.get("otppin")

            log.info("[userinit] initialize a token with serial %s "
                     "and type %s by user %s@%s"
                % (serial, tok_type, self.authUser.login, self.authUser.realm))

            log.debug("[userinit] Initializing the token serial: %s,"
                      " desc: %s, otppin: %s for user %s @ %s." %
            (serial, desc, otppin, self.authUser.login, self.authUser.realm))
            log.debug(param)

            # extend the interface by parameters, so that decisssion could
            # be made in the token update method
            param['::scope::'] = {'selfservice': True,
                                  'user': self.authUser
                                  }

            (ret, tokenObj) = initToken(param, self.authUser)
            if tokenObj is not None and hasattr(tokenObj, 'getInfo'):
                info = tokenObj.getInfo()
                response_detail.update(info)

            # result enrichment - if the token is sucessfully created,
            # some processing info is added to the result document,
            #  e.g. the otpkey :-) as qr code
            initDetail = tokenObj.getInitDetail(param, self.authUser)
            response_detail.update(initDetail)

            c.audit['success'] = ret
            c.audit['user'] = self.authUser.login
            c.audit['realm'] = self.authUser.realm

            logTokenNum()
            c.audit['success'] = ret
            checkPolicyPost('selfservice', 'enroll', param, user=self.authUser)

            Session.commit()

            # # finally we render the info as qr image, if the qr parameter
            # # is provided and if the token supports this
            if 'qr' in param and tokenObj is not None:
                (rdata, hparam) = tokenObj.getQRImageData(response_detail)
                hparam.update(response_detail)
                hparam['qr'] = param.get('qr') or 'html'
                return sendQRImageResult(response, rdata, hparam)
            else:
                return sendResult(response, ret, opt=response_detail)

        except PolicyException as pe:
            log.exception("[userinit] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[userinit] token initialization failed! %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('[userinit] done')


    def webprovision(self):
        '''
        This function is called, when the create OATHtoken button is hit.
        This is used for web provisioning. See:
            http://code.google.com/p/oathtoken/wiki/WebProvisioning
            and
            http://code.google.com/p/google-authenticator/wiki/KeyUriFormat

        in param:
            type: valid values are "oathtoken" and "googleauthenticator" and "googleauthenticator_time"
        It returns the data and the URL containing the HMAC key
        '''
        log.debug("[userwebprovision] calling function")
        param = {}

        try:

            ret = {}
            ret1 = False
            ret2 = False
            param.update(request.params)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'userwebprovision', param, self.authUser)

            typ = param["type"]
            t_type = "hmac"

            serial = param.get('serial', None)
            prefix = param.get('prefix', None)

            desc = ""
            # date = datetime.datetime.now().strftime("%y%m%d%H%M%S")
            # rNum = random.randrange(1000, 9999)

            if typ.lower() == "oathtoken":
                t_type = 'hmac'
                desc = "OATHtoken web provisioning"

                if prefix is None:
                    prefix = 'LSAO'
                if serial is None:
                    serial = genSerial(t_type, prefix)

                # deal: 32 byte. We could use 20 bytes.
                # we must take care, that the url is not longer than 119 chars.
                # otherwise qrcode.js will fail.Change to 32!
                # Usually the URL is 106 bytes long
                otpkey = generate_otpkey(20)

                log.debug("[userwebprovision] Initializing the token serial: %s, desc: %s for user %s @ %s." %
                        (serial, desc, self.authUser.login, self.authUser.realm))
                (ret1, tokenObj) = initToken({ 'type': t_type,
                                'serial': serial,
                                'description' : desc,
                                'otpkey' : otpkey,
                                'otplen' : 6,
                                'timeStep' : 30,
                                'timeWindow' : 180,
                                'hashlib' : "sha1"
                                }, self.authUser)

                if ret1:
                    url = create_oathtoken_url(self.authUser.login,
                                               self.authUser.realm ,
                                               otpkey, serial=serial)
                    ret = {
                        'url' : url,
                        'img' : create_img(url, width=300, alt=serial),
                        'key' : otpkey,
                        'name' : serial,
                        'serial' : serial,
                        'timeBased' : False,
                        'counter' : 0,
                        'numDigits': 6,
                        'lockdown' : True
                    }

            elif typ.lower() in [ "googleauthenticator", "googleauthenticator_time"]:
                desc = "Google Authenticator web prov"

                # ideal: 32 byte.
                otpkey = generate_otpkey(32)
                t_type = "hmac"
                if typ.lower() == "googleauthenticator_time":
                    t_type = "totp"

                if prefix is None:
                    prefix = "LSGO"
                if serial is None:
                    serial = genSerial(t_type, prefix)

                log.debug("Initializing the token serial: "
                          "%s, desc: %s for user %s @ %s." %
                        (serial, desc, self.authUser.login, self.authUser.realm))
                (ret1, tokenObj) = initToken({ 'type': t_type,
                                'serial': serial,
                                'otplen': 6,
                                'description' : desc,
                                'otpkey' : otpkey,
                                'timeStep' : 30,
                                'timeWindow' : 180,
                                'hashlib' : "sha1"
                                }, self.authUser)

                if ret1:
                        pparam = {'user.login': self.authUser.login,
                                  'user.login': self.authUser.realm,
                                  'otpkey': otpkey,
                                  'serial': serial,
                                  'type': t_type,
                                  'description': desc,
                                  }
                        url = create_google_authenticator(pparam,
                                                          user=self.authUser)
                        label = "%s@%s" % (self.authUser.login, self.authUser.realm)
                        ret = {
                            'url' :     url,
                            'img' :     create_img(url, width=300, alt=serial),
                            'key' :     otpkey,
                            'label' :   label,
                            'serial' :  serial,
                            'counter' : 0,
                            'digits':   6,
                        }
            else:
                return sendError(response, _(
                "valid types are 'oathtoken' and 'googleauthenticator' and "
                "'googleauthenticator_time'. You provided %s") % typ)

            logTokenNum()
            c.audit['serial'] = serial
            # the Google and OATH are always HMAC; sometimes (FUTURE) totp"
            c.audit['token_type'] = t_type
            c.audit['success'] = ret1
            param['serial'] = serial

            checkPolicyPost('selfservice', 'enroll', param, user=self.authUser)

            Session.commit()
            return sendResult(response, {'init': ret1,
                                         'setpin' : False,
                                         'oathtoken' : ret})

        except PolicyException as pe:
            log.exception("[userwebprovision] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[userwebprovision] token initialization failed! %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('[userwebprovision] done')

    def getmultiotp(self):
        '''
        Using this function the user may receive OTP values for his own tokens.

        method:
            selfservice/getmultiotp

        arguments:
            serial  - the serial number of the token
            count   - number of otp values to return
            curTime - used ONLY for internal testing: datetime.datetime object

        returns:
            JSON response
        '''
        log.debug("[usergetmultiotp] calling function")

        getotp_active = config.get("linotpGetotp.active")
        if "True" != getotp_active:
            return sendError(response, _("getotp is not activated."), 0)

        param = {}
        ret = {}

        try:
            param.update(request.params)

            try:
                serial = param["serial"]
                count = int(param["count"])
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            curTime = param.get("curTime", None)

            if (True != isTokenOwner(serial, self.authUser)):
                error = (_("The serial %s does not belong to user %s@%s") %
                          (serial, self.authUser.login, self.authUser.realm))
                log.error(error)
                return sendError(response, error, 1)

            max_count = checkPolicyPre('selfservice', 'max_count', param, self.authUser)
            log.debug("checkpolicypre returned %s" % max_count)

            if count > max_count:
                count = max_count

            log.debug("[usergetmultiotp] retrieving OTP value for token %s" % serial)
            ret = get_multi_otp(serial, count=int(count), curTime=curTime)
            if ret['result'] == False and max_count == -1:
                ret['error'] = "%s - %s" % (ret['error'], _("see policy definition."))

            ret["serial"] = serial
            c.audit['success'] = True

            Session.commit()
            return sendResult(response, ret , 0)

        except PolicyException as pe:
            log.exception("[usergetmultiotp] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[usergetmultiotp] gettoken/getmultiotp failed: %r" % e)
            Session.rollback()
            return sendError(response, _(u"selfservice/usergetmultiotp failed: %s")
                             % unicode(e), 0)

        finally:
            Session.close()
            log.debug('[usergetmultiotp] done')

    def history(self):
        '''
        This returns the list of the tokenactions of this user
        It returns the audit information for the given search pattern

        method:
            selfservice/userhistory

        arguments:
            key, value pairs as search patterns.

            or: Usually the key=values will be locally AND concatenated.
                it a parameter or=true is passed, the filters will be OR
                concatenated.

            The Flexigrid provides us the following parameters:
                ('page', u'1'), ('rp', u'100'),
                ('sortname', u'number'),
                ('sortorder', u'asc'),
                ('query', u''), ('qtype', u'serial')]
        returns:
            JSON response
        '''

        param = {}
        res = {}

        try:
            param.update(request.params)
            log.debug("params: %s" % param)
            checkPolicyPre('selfservice', 'userhistory', param, self.authUser)

            lines, total, page = audit_search(param, user=self.authUser,
                                columns=['date', 'action', 'success', 'serial',
                                        'token_type', 'administrator',
                                        'action_detail', 'info'])

            response.content_type = 'application/json'

            if not total:
                total = len(lines)

            res = { "page" : page,
                "total" : total,
                "rows" : lines }

            c.audit['success'] = True

            Session.commit()
            return json.dumps(res, indent=3)

        except PolicyException as pe:
            log.exception("[search] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as exx:
            log.exception("[search] audit/search failed: %r" % exx)
            Session.rollback()
            return sendError(response, _("audit/search failed: %s")
                                                        % unicode(exx), 0)

        finally:
            Session.close()
            log.error("[search] done")

    def activateocratoken(self):
        '''

        activateocratoken - called from the selfservice web ui to activate the  OCRA token

        :param type:    'ocra'
        :type type:     string
        :param serial:    serial number of the token
        :type  serial:    string
        :param activationcode: the calculated activation code
        :type  activationcode: string - activationcode format

        :return:    dict about the token
        :rtype:     { 'activate': True, 'ocratoken' : {
                        'url' :     url,
                        'img' :     '<img />',
                        'label' :   "%s@%s" % (self.authUser.login,
                                                   self.authUser.realm),
                        'serial' :  serial,
                    }  }
        '''
        log.debug("calling function activateocratoken")
        param = {}
        ret = {}

        try:
            param.update(request.params)

            # check selfservice authorization
            checkPolicyPre('selfservice', 'useractivateocratoken',
                                                    param, self.authUser)
            try:
                typ = param["type"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            if typ and typ.lower() not in ["ocra", "ocra2"]:
                return sendError(response, _("valid types are 'ocra' "
                                             "or 'ocra2'. You provided %s")
                                 % typ)

            helper_param = {}
            helper_param['type'] = typ
            try:
                helper_param['serial'] = param["serial"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            acode = param["activationcode"]
            helper_param['activationcode'] = acode.upper()

            try:
                helper_param['genkey'] = param["genkey"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)


            (ret, tokenObj) = initToken(helper_param, self.authUser)

            info = {}
            serial = ""
            if tokenObj is not None:
                info = tokenObj.getInfo()
                serial = tokenObj.getSerial()
            else:
                raise Exception('Token not found!')

            url = info.get('app_import')
            trans = info.get('transactionid')

            ret = {
                'url'       : url,
                'img'       : create_img(url, width=400, alt=url),
                'label'     : "%s@%s" % (self.authUser.login,
                                            self.authUser.realm),
                'serial'    : serial,
                'transaction' : trans,
            }

            logTokenNum()

            c.audit['serial'] = serial
            c.audit['token_type'] = typ
            c.audit['success'] = True

            Session.commit()
            return sendResult(response, {'activate': True, 'ocratoken': ret})

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("token initialization failed! %r" % e)
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('done')

    def finshocratoken(self):
        '''

        finshocratoken - called from the selfservice web ui to finish the
                         OCRA token to run the final check_t for the token

        :param passw: the calculated verificaton otp
        :type  passw: string
        :param transactionid: the transactionid
        :type  transactionid: string

        :return:    dict about the token
        :rtype:     { 'result' = ok
                      'failcount' = int(failcount)
                    }

        '''

        log.debug("calling function finshocratoken")
        param = request.params

        try:
            ''' check selfservice authorization '''

            checkPolicyPre('selfservice', 'userwebprovision',
                                                    param, self.authUser)

            try:
                transid = param['transactionid']
                passw = param['pass']
                p_serial = param['serial']
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            value = {}

            ocraChallenge = OcraTokenClass.getTransaction(transid)
            if ocraChallenge is None:
                error = ('[userfinshocratoken] No challenge for transaction'
                            ' %s found' % unicode(transid))
                log.error(error)
                raise Exception(error)

            serial = ocraChallenge.tokenserial
            if serial != p_serial:
                error = ('[userfinshocratoken] token mismatch for token '
                      'serial: %s - %s' % (unicode(serial), unicode(p_serial)))
                log.error(error)
                raise Exception(error)

            tokens = getTokens4UserOrSerial(serial=serial)
            if len(tokens) == 0 or len(tokens) > 1:
                error = ('[userfinshocratoken] no token found for '
                         'serial: %s' % (unicode(serial)))
                log.error(error)
                raise Exception(error)

            theToken = tokens[0]
            tok = theToken.token
            desc = tok.get()
            realms = desc.get('LinOtp.RealmNames')
            if realms is None or len(realms) == 0:
                realm = getDefaultRealm()
            elif len(realms) > 0:
                realm = realms[0]

            userInfo = getUserInfo(tok.LinOtpUserid, tok.LinOtpIdResolver,
                                                        tok.LinOtpIdResClass)
            user = User(login=userInfo.get('username'), realm=realm)

            (ok, opt) = checkSerialPass(serial, passw, user=user,
                                            options={'transactionid': transid})

            failcount = tokens[0].getFailCount()
            typ = tokens[0].type

            value['result'] = ok
            value['failcount'] = int(failcount)

            c.audit['transactionid'] = transid
            c.audit['token_type'] = typ
            c.audit['success'] = value.get('result')

            Session.commit()
            return sendResult(response, value, opt)

        except PolicyException as pe:
            log.exception("policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            error = "token finitialization failed! %r" % e
            log.exception(error)
            Session.rollback()
            return sendError(response, error, 1)

        finally:
            Session.close()
            log.debug('done')

# #--
    def finshocra2token(self):
        '''

        finshocra2token - called from the selfservice web ui to finish
                        the OCRA2 token to run the final check_t for the token

        :param passw: the calculated verificaton otp
        :type  passw: string
        :param transactionid: the transactionid
        :type  transactionid: string

        :return:    dict about the token
        :rtype:     { 'result' = ok
                      'failcount' = int(failcount)
                    }

        '''

        log.debug("calling function finshocra2token")
        param = {}
        param.update(request.params)
        if 'session' in param:
            del param['session']

        value = {}
        ok = False
        typ = ''

        try:
            ''' check selfservice authorization '''

            checkPolicyPre('selfservice', 'userwebprovision',
                                                        param, self.authUser)
            try:
                passw = param["pass"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            transid = param.get('state', None)
            if transid is not None:
                param['transactionid'] = transid
                del param['state']

            if transid is None:
                transid = param.get('transactionid', None)

            if transid is None:
                raise Exception("missing parameter: state or transactionid!")

            serial = get_tokenserial_of_transaction(transId=transid)
            if serial is None:
                value['value'] = False
                value['failure'] = 'No challenge for transaction %r found'\
                                    % transid

            else:
                try:
                    param['serial'] = serial
                except KeyError as exx:
                    raise ParameterError("Missing parameter: '%s'" % exx.message)


                tokens = getTokens4UserOrSerial(serial=serial)
                if len(tokens) == 0 or len(tokens) > 1:
                    raise Exception('tokenmismatch for token serial: %s'
                                    % (unicode(serial)))

                theToken = tokens[0]
                tok = theToken.token
                typ = theToken.getType()
                realms = tok.getRealmNames()
                if realms is None or len(realms) == 0:
                    realm = getDefaultRealm()
                elif len(realms) > 0:
                    realm = realms[0]

                userInfo = getUserInfo(tok.LinOtpUserid, tok.LinOtpIdResolver, tok.LinOtpIdResClass)
                user = User(login=userInfo.get('username'), realm=realm)

                (ok, opt) = checkSerialPass(serial, passw, user=user,
                                     options=param)

                value['value'] = ok
                failcount = theToken.getFailCount()
                value['failcount'] = int(failcount)

            value['result'] = ok
            value['failcount'] = int(failcount)

            c.audit['transactionid'] = transid
            c.audit['token_type'] = typ
            c.audit['success'] = value.get('result')

            Session.commit()
            return sendResult(response, value, opt)

        except PolicyException as pe:
            log.exception("[userfinshocra2token] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            error = "[userfinshocra2token] token initialization failed! %r" % e
            log.exception(error)
            Session.rollback()
            return sendError(response, error, 1)

        finally:
            Session.close()
            log.debug('[userfinshocra2token] done')

    def token_call(self):
        '''
            the generic method call for an dynamic token
        '''
        param = {}

        res = {}

        try:
            param.update(request.params)

            # # method could be part of the virtual url
            context = request.path_info.split('/')
            if len(context) > 2:
                method = context[2]
            else:
                try:
                    method = param["method"]
                except KeyError as exx:
                    raise ParameterError("Missing parameter: '%s'" % exx.message)

            try:
                typ = param["type"]
            except KeyError as exx:
                raise ParameterError("Missing parameter: '%s'" % exx.message)

            serial = param.get("serial", None)

            # check selfservice authorization for this dynamic method
            pols = get_client_policy(self.client, scope="selfservice",
                                     realm=self.authUser.realm,
                                     action=method,
                                     userObj=self.authUser.realm,
                                     find_resolver=False)
            if not pols or len(pols) == 0:
                log.error('user %r not authorized to call %s'
                          % (self.authUser, method))
                raise PolicyException('user %r not authorized to call %s'
                                      % (self.authUser, method))

            glo = config['pylons.app_globals']
            tokenclasses = glo.tokenclasses

            if typ in tokenclasses.keys():
                tclass = tokenclasses.get(typ)
                tclt = None
                if serial is not None:
                    toks = getTokens4UserOrSerial(None, serial, _class=False)
                    tokenNum = len(toks)
                    if tokenNum == 1:
                        token = toks[0]
                        # object method call
                        tclt = newToken(tclass)(token)

                # static method call
                if tclt is None:
                    tclt = newToken(tclass)
                method = '' + method.strip()
                if hasattr(tclt, method):
                    # TODO: check that method name is a function / method
                    ret = getattr(tclt, method)(param)
                    if len(ret) == 1:
                        res = ret[0]
                    if len(ret) > 1:
                        res = ret[1]
                    c.audit['success'] = res
                else:
                    res['status'] = 'method %s.%s not supported!' % (typ, method)
                    c.audit['success'] = False

            Session.commit()
            return sendResult(response, res, 1)

        except PolicyException as pe:
            log.exception("[token_call] policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[token_call] calling method %s.%s of user %s failed! %r"
                      % (typ, method, c.user, e))
            Session.rollback()
            return sendError(response, e, 1)

        finally:
            Session.close()
            log.debug('[token_call] done')


#eof##########################################################################


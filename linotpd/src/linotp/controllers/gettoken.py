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
gettoken controller - to retrieve OTP values
"""




import logging

from pylons import tmpl_context as c
from pylons import request, response
from pylons import config
from pylons.templating import render_mako as render


from linotp.lib.base import BaseController

from linotp.lib.util import  getParam, check_session
from linotp.lib.util import  get_client
from linotp.lib.user import  getUserFromParam
from linotp.lib.user import  getDefaultRealm
from linotp.lib.user import  getUserFromRequest


from linotp.lib.token import getTokenType, getOtp, get_multi_otp, getTokens4UserOrSerial
from linotp.lib.policy import checkPolicyPre, PolicyException
from linotp.lib.reply import sendResult, sendError

from linotp.model.meta import Session
import traceback

audit = config.get('audit')

optional = True
required = False

log = logging.getLogger(__name__)


class GettokenController(BaseController):

    '''
    The linotp.controllers are the implementation of the web-API to talk to the LinOTP server.
    The ValidateController is used to validate the username with its given OTP value.

    The Tagespasswort Token uses this controller to retrieve the current OTP value of
    the Token and be able to set it in the application
    The functions of the GettokenController are invoked like this

        https://server/gettoken/<functionname>

    The functions are described below in more detail.
    '''

    def __before__(self, action, **params):

        log.debug("[__before__]")

        try:
            audit.initialize()
            c.audit['client'] = get_client()
            check_session()

        except Exception as exx:
            log.exception("[__before__::%r] exception %r" % (action, exx))
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')

        finally:
            log.debug("[__before__::%r] done" % (action))

    def __after__(self):
        c.audit['administrator'] = getUserFromRequest(request).get("login")
        if request.params.has_key('serial'):
                c.audit['serial'] = request.params['serial']
                c.audit['token_type'] = getTokenType(request.params['serial'])
        audit.log(c.audit)


    def getmultiotp(self):
        '''
        This function is used to retrieve multiple otp values for a given user or a given serial
        If the user has more than one token, the list of the tokens is returend.

        method:
            gettoken/getmultiotp

        arguments:
            serial  - the serial number of the token
            count   - number of otp values to return
            curTime - used ONLY for internal testing: datetime.datetime object

        returns:
            JSON response
        '''

        getotp_active = config.get("linotpGetotp.active")
        if "True" != getotp_active:
            return sendError(response, "getotp is not activated.", 0)

        param = request.params
        ret = {}

        try:
            serial = getParam(param, "serial", required)
            count = int(getParam(param, "count", required))
            curTime = getParam(param, "curTime", optional)
            view = getParam(param, "view", optional)

            r1 = checkPolicyPre('admin', 'getotp', param)
            log.debug("[getmultiotp] admin-getotp returned %s" % r1)

            max_count = checkPolicyPre('gettoken', 'max_count', param)
            log.debug("[getmultiotp] checkpolicypre returned %s" % max_count)
            if count > max_count:
                count = max_count

            log.debug("[getmultiotp] retrieving OTP value for token %s" % serial)
            ret = get_multi_otp(serial, count=int(count), curTime=curTime)
            ret["serial"] = serial

            c.audit['success'] = True
            Session.commit()

            if view:
                c.ret = ret
                return render('/manage/multiotp_view.mako')
            else:
                return sendResult(response, ret , 0)

        except PolicyException as pe:
            log.exception("[getotp] gettoken/getotp policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[getmultiotp] gettoken/getmultiotp failed: %r" % e)
            Session.rollback()
            return sendError(response, "gettoken/getmultiotp failed: %s"
                             % unicode(e), 0)

        finally:
            Session.close()
            log.debug("[getmultiotp] done")


    def getotp(self):
        '''
        This function is used to retrieve the current otp value for a given user or a given serial
        If the user has more than one token, the list of the tokens is returend.

        method:
            gettoken/getotp

        arguments:
            user    - username / loginname
            realm   - additional realm to match the user to a useridresolver
            serial  - the serial number of the token
            curTime - used ONY for internal testing: datetime.datetime object

        returns:
            JSON response
        '''

        getotp_active = config.get("linotpGetotp.active")
        if "True" != getotp_active:
            return sendError(response, "getotp is not activated.", 0)

        param = request.params
        ret = {}
        res = -1
        otpval = ""
        passw = ""
        serials = []

        try:

            serial = getParam(param, "serial", optional)
            user = getUserFromParam(param, optional)
            curTime = getParam(param, "curTime", optional)

            c.audit['user'] = user.login
            if "" != user.login:
                c.audit['realm'] = user.realm or getDefaultRealm()

            if serial:
                log.debug("[getotp] retrieving OTP value for token %s" % serial)
            elif user.login:
                log.debug("[getotp] retrieving OTP value for token for user %s@%s" % (user.login, user.realm))
                toks = getTokens4UserOrSerial(user, serial)
                tokennum = len(toks)
                if tokennum > 1:
                    log.debug("[getotp] The user has more than one token. Returning the list of serials")
                    res = -3
                    for token in toks:
                        serials.append(token.getSerial())
                elif 1 == tokennum:
                    serial = toks[0].getSerial()
                    log.debug("[getotp] retrieving OTP for token %s for user %s@%s" %
                                (serial, user.login, user.realm))
                else:
                    log.debug("[getotp] no token found for user %s@%s" % (user.login, user.realm))
                    res = -4
            else:
                res = -5

            # if a serial was given or a unique serial could be received from the given user.
            if serial:
                max_count = checkPolicyPre('gettoken', 'max_count', param)
                log.debug("[getmultiotp] checkpolicypre returned %s" % max_count)
                if max_count <= 0:
                    return sendError(response, "The policy forbids receiving OTP values for the token %s in this realm" % serial , 1)

                (res, pin, otpval, passw) = getOtp(serial, curTime=curTime)

            c.audit['success'] = True

            if int(res) < 0:
                ret['result'] = False
                if -1 == otpval:
                    ret['description'] = "No Token with this serial number"
                if -2 == otpval:
                    ret['description'] = "This Token does not support the getOtp function"
                if -3 == otpval:
                    ret['description'] = "The user has more than one token"
                    ret['serials'] = serials
                if -4 == otpval:
                    ret['description'] = "No Token found for this user"
                if -5 == otpval:
                    ret['description'] = "you need to provide a user or a serial"
            else:
                ret['result'] = True
                ret['otpval'] = otpval
                ret['pin'] = pin
                ret['pass'] = passw

            Session.commit()
            return sendResult(response, ret , 0)

        except PolicyException as pe:
            log.exception("[getotp] gettoken/getotp policy failed: %r" % pe)
            Session.rollback()
            return sendError(response, unicode(pe), 1)

        except Exception as e:
            log.exception("[getotp] gettoken/getotp failed: %r" % e)
            Session.rollback()
            return sendError(response, "gettoken/getotp failed: %s" % unicode(e), 0)

        finally:
            Session.close()
            log.debug('[getotp] done')


#eof###########################################################################


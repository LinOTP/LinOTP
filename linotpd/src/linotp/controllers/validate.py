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
validate controller - to check the authentication request
"""





import logging
import webob

from pylons import tmpl_context as c
from pylons import request, response, config
from pylons.controllers.util import abort
from linotp.lib.base import BaseController

from linotp.lib.util import get_client
from linotp.lib.util import  getParam
from linotp.lib.user import  getUserFromParam
from linotp.lib.realm import  getDefaultRealm
from linotp.lib.user import  getUserInfo
from linotp.lib.user import  getUserId
from linotp.lib.user    import User

from linotp.lib.config  import getFromConfig

from linotp.lib.token import checkUserPass, checkSerialPass
from linotp.lib.token import get_tokenserial_of_transaction

from linotp.lib.reply import sendResult, sendError
from linotp.lib.reply import sendQRImageResult

from linotp.model.meta import Session
from linotp.lib.selftest import isSelfTest
from linotp.lib.policy import check_user_authorization
from linotp.lib.policy import check_auth_tokentype
from linotp.lib.policy import check_auth_serial
from linotp.lib.policy import AuthorizeException
from linotp.lib.policy import set_realm
from linotp.lib.policy import is_auth_return

from linotp.lib.token import checkYubikeyPass
from linotp.lib.token import getTokens4UserOrSerial

from linotp.lib.error import ParameterError

import traceback

audit = config.get('audit')

optional = True
required = False

log = logging.getLogger(__name__)


#from paste.debug.profile import profile_decorator


class ValidateController(BaseController):

    '''
    The linotp.controllers are the implementation of the web-API to talk to the LinOTP server.
    The ValidateController is used to validate the username with its given OTP value.
    An Authentication module like pam_linotp2 or rlm_linotp2 uses this ValidateController.
    The functions of the ValidateController are invoked like this

        https://server/validate/<functionname>

    The functions are described below in more detail.
    '''

    def __before__(self, action, **params):

        log.debug("[__before__::%r] %r" % (action, params))

        try:
            audit.initialize()
            c.audit['client'] = get_client()
            return response

        except Exception as exx:
            log.exception("[__before__::%r] exception %r" % (action, exx))
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')

        finally:
            log.debug("[__before__::%r] done" % (action))


    def __after__(self, action, **params):
        audit.log(c.audit)
        return response


    def _check(self, param):
        '''
        basic check function, that can be used by different controllers

        :param param: dict of all caller parameters
        :type param: dict

        :return: Tuple of True or False and opt
        :rtype: Tuple(boolean, opt)

        '''
        opt = None

        options = {}

        ## put everythin in the options but the user, pass, init
        options.update(param)
        for para in ["pass", "user", "init"]:
            if options.has_key(para):
                del options[para]

        passw = getParam(param, "pass", optional)
        user = getUserFromParam(param, optional)

        # support for ocra application challenge verification
        challenge = getParam(param, "challenge", optional)
        if challenge is not None:
            options = {}
            options['challenge'] = challenge

        c.audit['user'] = user.login
        realm = user.realm or getDefaultRealm()
        c.audit['realm'] = realm

        # AUTHORIZATION Pre Check
        # we need to overwrite the user.realm in case the user does not exist in the original realm (setrealm-policy)
        user.realm = set_realm(user.login, realm, exception=True)
        check_user_authorization(user.login, user.realm, exception=True)

        if isSelfTest() == True:
            initTime = getParam(param, "init", optional)
            if initTime is not None:
                if options is None:
                    options = {}
                options['initTime'] = initTime

        (ok, opt) = checkUserPass(user, passw, options=options)

        c.audit['success'] = ok

        if ok:
            # AUTHORIZATION post check
            check_auth_tokentype(c.audit['serial'], exception=True, user=user)
            check_auth_serial(c.audit['serial'], exception=True, user=user)

        # add additional details
        if is_auth_return(ok, user=user):
            if opt == None:
                opt = {}
            if ok:
                opt['realm'] = c.audit.get('realm')
                opt['user'] = c.audit.get('user')
                opt['tokentype'] = c.audit.get('token_type')
                opt['serial'] = c.audit.get('serial')
            else:
                opt['error'] = c.audit.get('action_detail')

        return (ok, opt)


    # @profile_decorator(log_file="/tmp/validate.prof")
    def check(self):

        '''
        This function is used to validate the username and the otp value/password.

        method:
            validate/check

        arguments:

           * user:    The username or loginname
           * pass:    The password that consist of a possible fixed password component and the OTP value
           * realm (optional): An optional realm to match the user to a useridresolver
           * challenge (optional): optional challenge + otp verification for challenge response token. This indicates, that tis request is a challenge request.
           * data (optional): optional challenge + otp verification for challenge response token.  This indicates, that tis request is a challenge request.
           * state (optional): The optional id to respond to a previous challenge.
           * transactionid (optional): The optional id to respond to a previous challenge.

        returns:
            JSON response::

                {
                    "version": "LinOTP 2.4",
                    "jsonrpc": "2.0",
                    "result": {
                        "status": true,
                        "value": false
                    },
                    "id": 0
                }

            If ``status`` is ``true`` the request was handled successfully.

            If ``value`` is ``true`` the user was authenticated successfully.
        '''

        param = {}
        ok = False
        opt = None

        try:
            param.update(request.params)

            # prevent the detection if a user exist
            # by sending a request w.o. pass parameter
            try:
                (ok, opt) = self._check(param)
            except (AuthorizeException, ParameterError) as exx:
                log.warning("[check] authorization failed for validate/check: %r"
                            % exx)
                c.audit['success'] = False
                c.audit['info'] = unicode(exx)
                ok = False
                if is_auth_return(ok):
                    if opt == None:
                        opt = {}
                    opt['error'] = c.audit.get('info')

            Session.commit()

            qr = param.get('qr', None)
            if qr and opt and 'message' in opt:
                try:
                    dataobj = opt.get('message')
                    param['alt'] = "%s" % opt
                    if 'transactionid' in opt:
                        param['transactionid'] = opt['transactionid']
                    return sendQRImageResult(response, dataobj, param)
                except Exception as exc:
                    log.warning("failed to send QRImage: %r " % exc)
                    return sendQRImageResult(response, opt, param)
            else:
                return sendResult(response, ok, 0, opt=opt)

        except Exception as exx:
            log.exception("[check] validate/check failed: %r" % exx)
            # If an internal error occurs or the SMS gateway did not send the SMS, we write this to the detail info.
            c.audit['info'] = unicode(exx)
            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()
            log.debug('[check] done')


    def check_yubikey(self):
        '''
        This function is used to validate the output of a yubikey

        method:
            validate/check_yubikey

        :param pass: The password that consist of the static yubikey prefix and the otp
        :type pass: string

        :return: JSON Object

        returns:
            JSON response::

                {
                    "version": "LinOTP 2.4",
                    "jsonrpc": "2.0",
                    "result": {
                        "status": true,
                        "value": false
                    },
                    "detail" : {
                        "username": username,
                        "realm": realm
                    },
                    "id": 0
                }
        '''

        param = request.params
        passw = getParam(param, "pass", required)
        try:

            ok = False
            try:
                ok, opt = checkYubikeyPass(passw)
                c.audit['success'] = ok

            except AuthorizeException as exx:
                log.warning("[check_yubikey] authorization failed for validate/check_yubikey: %r"
                            % exx)
                c.audit['success'] = False
                c.audit['info'] = unicode(exx)
                ok = False

            Session.commit()
            return sendResult(response, ok, 0, opt=opt)

        except Exception as exx:
            log.exception("[check_yubikey] validate/check_yubikey failed: %r" % exx)
            c.audit['info'] = unicode(exx)
            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()
            log.debug('[check_yubikey] done')

    def check_url(self):
        '''
        This function works with pam_url.
        '''
        ok = False
        param = {}
        try:
            param.update(request.params)

            try:
                (ok, opt) = self._check(param)
            except AuthorizeException as acc:
                log.warning("[check_url] authorization failed for validate/check_url: %r" % acc)
                c.audit['success'] = False
                c.audit['action_detail'] = unicode(acc)
                ok = False

            Session.commit()
            response.headers['blablafoo'] = 'application/json'

            ## TODO: this code seems not to be finished
            if not ok:
                abort(403)
            else:
                return "Preshared Key Todo"

        except webob.exc.HTTPUnauthorized as acc:
            ## the exception, when an abort() is called if forwarded
            log.exception("[__before__::%r] webob.exception %r" % acc)
            Session.rollback()
            raise acc

        except Exception as exx:
            log.exception("[check_url] validate/check_url failed: %r" % exx)
            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()
            log.debug("[check_url] done")


    def samlcheck(self):
        '''
        This function is used to validate the username and the otp value/password
        in a SAML environment. If ``linotp.allowSamlAttributes = True``
        then the attributes of the authenticated users are also contained
        in the response.

        method:
            validate/samlcheck

        arguments:
            * user:    username / loginname
            * pass:    the password that consists of a possible fixes password component and the OTP value
            * realm:   optional realm to match the user to a useridresolver

        returns:
            JSON response
        '''

        try:
            opt = None
            param = request.params
            (ok, opt) = self._check(param)
            attributes = {}

            if True == ok:
                allowSAML = False
                try:
                    allowSAML = getFromConfig("allowSamlAttributes")
                except:
                    log.warning("[samlcheck] Calling controller samlcheck. But allowSamlAttributes == False.")
                if "True" == allowSAML:
                    ## Now we get the attributes of the user
                    user = getUserFromParam(param, optional)
                    (uid, resId, resIdC) = getUserId(user)
                    userInfo = getUserInfo(uid, resId, resIdC)
                    #users   = getUserList({ 'username':user.getUser()} , user)
                    log.debug("[samlcheck] getting attributes for: %s@%s"
                              % (user.getUser(), user.getRealm()))

                    res = userInfo
                    for key in ['username',
                                'surname',
                                'mobile',
                                'phone',
                                'givenname',
                                'email']:
                        if key in res:
                            attributes[key] = res[key]

            Session.commit()
            return sendResult(response, { 'auth': ok, 'attributes' : attributes } , 0, opt)

        except Exception as exx:
            log.exception("[samlcheck] validate/check failed: %r" % exx)
            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()
            log.debug('[samlcheck] done')

    def check_t(self):

        param = {}
        value = {}
        ok = False
        opt = None

        try:
            param.update(request.params)
            passw = getParam(param, "pass", required)

            transid = param.get('state', None)
            if transid is not  None:
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
                param['serial'] = serial

                tokens = getTokens4UserOrSerial(serial=serial)
                if len(tokens) == 0 or len(tokens) > 1:
                    raise Exception('tokenmismatch for token serial: %s'
                                    % (unicode(serial)))

                theToken = tokens[0]
                tok = theToken.token
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

            c.audit['success'] = ok
            #c.audit['info'] += "%s=%s, " % (k, value)
            Session.commit()

            qr = param.get('qr', None)
            if qr and opt and 'message' in opt:
                try:
                    dataobj = opt.get('message')
                    param['alt'] = "%s" % opt
                    if 'transactionid' in opt:
                        param['transactionid'] = opt['transactionid']
                    return sendQRImageResult(response, dataobj, param)
                except Exception as exc:
                    log.warning("failed to send QRImage: %r " % exc)
                    return sendQRImageResult(response, opt, param)
            else:
                return sendResult(response, value, 1, opt=opt)

        except Exception as exx:
            log.exception("[check_t] validate/check_t failed: %r" % exx)
            c.audit['info'] = unicode(exx)
            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()
            log.debug('[check_t] done')


    def check_s(self):
        '''
        This function is used to validate the serial and the otp value/password.

        method:
            validate/check_s

        arguments:
            * serial:  the serial number of the token
            * pass:    the password that consists of a possible fixes password component
                        and the OTP value

        returns:
            JSON response
        '''
        param = {}
        param.update(request.params)

        options = {}
        options.update(param)
        for k in ['user', 'serial', "pass", "init"]:
            if k in options:
                del options[k]

        if 'init' in param:
            if isSelfTest() == True:
                options['initTime'] = param.get('init')

        try:
            passw = getParam(param, "pass", optional)
            serial = getParam(param, 'serial', optional)
            if serial is None:
                user = getParam(param, 'user', optional)
                if user is  not None:
                    user = getUserFromParam(param, optional)
                    toks = getTokens4UserOrSerial(user=user)
                    if len(toks) == 0:
                        raise Exception("No token found!")
                    elif len(toks) > 1:
                        raise Exception("More than one token found!")
                    else:
                        tok = toks[0].token
                        desc = tok.get()
                        realms = desc.get('LinOtp.RealmNames')
                        if realms is None or len(realms) == 0:
                            realm = getDefaultRealm()
                        elif len(realms) > 0:
                            realm = realms[0]

                        userInfo = getUserInfo(tok.LinOtpUserid, tok.LinOtpIdResolver, tok.LinOtpIdResClass)
                        user = User(login=userInfo.get('username'), realm=realm)

                        serial = tok.getSerial()

            c.audit['serial'] = serial

            if isSelfTest() == True:
                initTime = getParam(param, "init", optional)
                if initTime is not None:
                    if options is None:
                        options = {}
                    options['initTime'] = initTime

            (ok, opt) = checkSerialPass(serial, passw, options=options)

            c.audit['success'] = ok
            Session.commit()

            qr = param.get('qr', None)
            if qr and opt and 'message' in opt:
                try:
                    dataobj = opt.get('message')
                    param['alt'] = "%s" % opt
                    if 'transactionid' in opt:
                        param['transactionid'] = opt['transactionid']
                    return sendQRImageResult(response, dataobj, param)
                except Exception as exc:
                    log.warning("failed to send QRImage: %r " % exc)
                    return sendQRImageResult(response, opt, param)
            else:
                return sendResult(response, ok, 0, opt=opt)

        except Exception as exx:
            log.exception("[check_s] validate/check_s failed: %r" % exx)
            c.audit['info'] = unicode(exx)
            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()
            log.debug('[check_s] done')



    def simplecheck(self):
        '''
        This function is used to validate the username and the otp value/password.

        method:
            validate/simplecheck

        arguments:
            * user:    username / loginname
            * pass:    the password that consists of a possible fixes password component
                        and the OTP value
            * realm:   additional realm to match the user to a useridresolver

        returns:
            Simple ascii response:

            :-)
                in case of success
            :-(
                in case of failed authentication
            :-/
                in case of any error
        '''
        opt = None
        param = request.params
        res = []

        try:
            try:
                (ok, opt) = self._check(param)
            except AuthorizeException as e:
                log.warning("[simplecheck] validate/simplecheck: %r" % e)
                c.audit['success'] = False
                c.audit['action_detail'] = unicode(e)
                ok = False

            Session.commit()

            if ok == True:
                ret = u":-)"
            else:
                ret = u":-("
            res.append(ret)

            if opt != None:

                if 'state' in opt or 'transactionid' in opt:
                    stat = opt.get('transactionid') or opt.get('state')
                    res.append(stat)

                if "data" in opt or "message" in opt:
                    msg = opt.get('data') or opt.get('message')
                    res.append(msg)


            return " ".join(res).strip()

        except Exception as exx:
            log.exception("[simplecheck] failed: %r" % exx)
            Session.rollback()
            return u":-("

        finally:
            Session.close()
            log.debug('[simplecheck] done')

    def ok(self):
        return sendResult(response, True, 0)

    def fail(self):
        return sendResult(response, False, 0)

    def smspin(self):
        '''
        This function is used in conjunction with an SMS token:
        the user authenticates with user and pin (pass) and
        will receive on his mobile an OTP as message

        method:
            validate/smspin

        arguments:
            * user:    username / loginname
            * pass:    the password that consists of a possible fixed password
            * realm:   additional realm to match the user to a useridresolver

        returns:
            JSON response
        '''
        ret = False
        param = request.params
        state = ''
        message = 'No sms message defined!'

        try:
            user = getUserFromParam(param, optional)
            c.audit['user'] = user.login
            c.audit['realm'] = user.realm or getDefaultRealm()
            c.audit['success'] = 0

            (ret, opt) = self._check(param)

            ## here we build some backward compatibility
            if type(opt) is dict:
                state = opt.get('state', '') or ''
                message = opt.get('message', '') or 'No sms message defined!'

            # sucessfull submit
            if (message in ['sms with otp already submitted',
                            'sms submitted']
                and len(state) > 0):
                ret = True
                c.audit['success'] = 1

            # sending sms failed should be an error
            elif message in ['sending sms failed']:
                ret = True
                c.audit['success'] = 0

            # anything else is an exception
            else:
                raise Exception(message)

            Session.commit()
            return sendResult(response, ret, opt)

        except Exception as exx:
            log.exception("[smspin] validate/smspin failed: %r" % exx)
            # If an internal error occurs or the SMS gateway did not send the SMS, we write this to the detail info.
            c.audit['info'] = unicode(exx)
            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()
            log.debug("[smspin] done")

#eof###########################################################################


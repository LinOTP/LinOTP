# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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
validate controller - to check the authentication request
"""

import logging

import webob
from pylons import request, response, config
from pylons import tmpl_context as c
from pylons.controllers.util import abort
from pylons.i18n.translation import _

from linotp.lib.auth.validate import ValidationHandler
from linotp.lib.base import BaseController
from linotp.lib.config import getFromConfig
from linotp.lib.error import ParameterError

from linotp.lib.policy import AuthorizeException
from linotp.lib.policy import check_auth_serial
from linotp.lib.policy import check_auth_tokentype
from linotp.lib.policy import check_user_authorization
from linotp.lib.policy import is_auth_return
from linotp.lib.policy import set_realm

from linotp.lib.realm import getDefaultRealm
from linotp.lib.reply import sendQRImageResult
from linotp.lib.reply import sendResult, sendError
from linotp.lib.selftest import isSelfTest
from linotp.lib.token import getTokens4UserOrSerial
from linotp.lib.token import get_tokenserial_of_transaction
from linotp.tokens.base import TokenClass

from linotp.lib.user import User
from linotp.lib.user import getUserFromParam
from linotp.lib.user import getUserId
from linotp.lib.user import getUserInfo
from linotp.lib.util import get_client

from linotp.lib.context import request_context
from linotp.lib.error import ValidateError
from linotp.lib.pairing import decrypt_pairing_response

import linotp.model


Session = linotp.model.Session

CONTENT_TYPE_PAIRING = 1

audit = config.get('audit')

log = logging.getLogger(__name__)


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

        try:
            c.audit = request_context['audit']
            c.audit['client'] = get_client(request)
            request_context['Audit'] = audit
            return response

        except Exception as exx:
            log.exception("[__before__::%r] exception %r" % (action, exx))
            Session.rollback()
            Session.close()
            return sendError(response, exx, context='before')


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

        # put everything in the options but the user, pass, init
        options.update(param)
        for para in ["pass", "user", "init"]:
            if options.has_key(para):
                del options[para]

        passw = param.get("pass")
        user = getUserFromParam(param)

        # support for ocra application challenge verification
        challenge = param.get("challenge")
        if challenge is not None:
            options = {}
            options['challenge'] = challenge

        c.audit['user'] = user.login
        realm = user.realm or getDefaultRealm()
        c.audit['realm'] = realm

        # AUTHORIZATION Pre Check
        # we need to overwrite the user.realm in case the
        # user does not exist in the original realm (setrealm-policy)
        user.realm = set_realm(user.login, realm, exception=True)
        check_user_authorization(user.login, user.realm, exception=True)

        if isSelfTest() is True:
            initTime = param.get("init")
            if initTime is not None:
                if options is None:
                    options = {}
                options['initTime'] = initTime
        vh = ValidationHandler()
        (ok, opt) = vh.checkUserPass(user, passw, options=options)

        c.audit.update(request_context.get('audit'))
        c.audit['success'] = ok

        if ok:
            # AUTHORIZATION post check
            check_auth_tokentype(c.audit['serial'], exception=True, user=user)
            check_auth_serial(c.audit['serial'], exception=True, user=user)

        # add additional details
        if is_auth_return(ok, user=user):
            if opt is None:
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
                    if opt is None:
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
            c.audit['info'] = "%r" % exx
            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()

    def check_status(self):
        """
        check the status of a transaction - for polling support
        """

        try:

            param = {}
            param.update(request.params)

            #
            # we require either state or transactionid as parameter

            transid = param.get('state', param.get('transactionid', None))
            if not transid:
                raise ParameterError(_('Missing required parameter "state" or '
                                     '"transactionid"!'))

            #
            # serial is an optional parameter

            serial = param.get('serial', None)

            #
            # but user is an required parameter

            if "user" not in param:
                raise ParameterError(_('Missing required parameter "serial"'
                                     ' or "user"!'))

            user = getUserFromParam(param)

            passw = param.get('pass')
            if passw is None:
                raise ParameterError(_('Missing required parameter "pass"!'))

            use_offline = param.get('use_offline', False)

            va = ValidationHandler()
            ok, opt = va.check_status(transid=transid, user=user,
                                      serial=serial, password=passw,
                                      use_offline=use_offline)

            c.audit['success'] = ok
            c.audit['info'] = unicode(opt)

            Session.commit()
            return sendResult(response, ok, 0, opt=opt)

        except Exception as exx:
            log.exception("check_status failed: %r" % exx)
            c.audit['info'] = unicode(exx)
            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()


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

        try:

            try:
                passw = param['pass']
            except KeyError:
                raise ParameterError("Missing parameter: 'pass'")

            ok = False
            try:
                vh = ValidationHandler()
                ok, opt = vh.checkYubikeyPass(passw)
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
                    log.warning("[samlcheck] Calling controller samlcheck. But allowSamlAttributes is False.")
                if "True" == allowSAML:
                    ## Now we get the attributes of the user
                    user = getUserFromParam(param)
                    (uid, resId, resIdC) = getUserId(user)
                    userInfo = getUserInfo(uid, resId, resIdC)
                    log.debug("[samlcheck] getting attributes for: %s@%s"
                              % (user.login, user.realm))

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

    def check_t(self):

        param = {}
        value = {}
        ok = False
        opt = {}

        try:
            param.update(request.params)

            if 'pass' not in param:
                raise ParameterError("Missing parameter: 'pass'")

            passw = param['pass']

            transid = param.get('state', None)
            if transid is not None:
                param['transactionid'] = transid
                del param['state']

            if transid is None:
                transid = param.get('transactionid', None)

            if transid is None:
                raise Exception("missing parameter: state or transactionid!")

            vh = ValidationHandler()
            (ok, opt) = vh.check_by_transactionid(transid=transid,
                                                  passw=passw,
                                                  options=param)

            value['value'] = ok
            value['failcount'] = int(opt.get('failcount', 0))

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
                return sendResult(response, value, 1, opt=opt)

        except Exception as exx:
            log.exception("[check_t] validate/check_t failed: %r" % exx)
            c.audit['info'] = unicode(exx)
            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()

    # ------------------------------------------------------------------------ -

    def accept_transaction(self):

        """
        confirms a transaction.

        needs the mandatory url query parameters:

            * transactionid: unique id for the transaction
            * signature: signature for the confirmation
        """

        try:

            param = {}
            param.update(request.params)

            # -------------------------------------------------------------- --

            # check the parameters

            if 'signature' not in param:
                raise ParameterError("Missing parameter: 'signature'!")

            if 'transactionid' not in param:
                raise ParameterError("Missing parameter: 'transactionid'!")

            # -------------------------------------------------------------- --

            # start the processing

            passw = {'accept': param['signature']}
            transid = param['transactionid']

            vh = ValidationHandler()
            ok, _opt = vh.check_by_transactionid(transid=transid,
                                                 passw=passw,
                                                 options=param)

            # -------------------------------------------------------------- --

            # finish the result

            c.audit['info'] = 'accept transaction: %r' % ok

            c.audit['success'] = ok
            Session.commit()

            return sendResult(response, ok)

        except Exception as exx:

            log.exception("validate/accept_transaction failed: %r" % exx)
            c.audit['info'] = "%r" % exx
            Session.rollback()

            return sendResult(response, False, 0)

        finally:
            Session.close()

    # ------------------------------------------------------------------------ -

    def reject_transaction(self):

        """
        rejects a transaction.

        needs the mandatory url query parameters:

            * transactionid: unique id for the transaction
            * signature: signature for the rejection
        """

        try:

            param = {}
            param.update(request.params)

            # -------------------------------------------------------------- --

            # check the parameters

            if 'signature' not in param:
                raise ParameterError("Missing parameter: 'signature'!")

            if 'transactionid' not in param:
                raise ParameterError("Missing parameter: 'transactionid'!")

            # -------------------------------------------------------------- --

            # start the processing

            passw = {'reject': param['signature']}
            transid = param['transactionid']

            vh = ValidationHandler()
            ok, _opt = vh.check_by_transactionid(transid=transid,
                                                 passw=passw,
                                                 options=param)

            # -------------------------------------------------------------- --

            # finish the result

            c.audit['info'] = 'reject transaction: %r' % ok

            c.audit['success'] = ok
            Session.commit()

            return sendResult(response, ok)

        except Exception as exx:

            log.exception("validate/reject_transaction failed: %r" % exx)
            c.audit['info'] = "%r" % exx
            Session.rollback()

            return sendResult(response, False, 0)

        finally:
            Session.close()

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
            if isSelfTest() is True:
                options['initTime'] = param.get('init')

        try:
            passw = param.get("pass")
            serial = param.get('serial')
            if serial is None:
                user = param.get('user')
                if user is not None:
                    user = getUserFromParam(param)
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

                        userInfo = getUserInfo(tok.LinOtpUserid,
                                               tok.LinOtpIdResolver,
                                               tok.LinOtpIdResClass)
                        user = User(login=userInfo.get('username'),
                                    realm=realm)

                        serial = tok.getSerial()

            c.audit['serial'] = serial

            if isSelfTest() is True:
                initTime = param.get("init")
                if initTime is not None:
                    if options is None:
                        options = {}
                    options['initTime'] = initTime

            options['scope'] = {"check_s": True}
            vh = ValidationHandler()
            (ok, opt) = vh.checkSerialPass(serial, passw, options=options)
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
            return sendResult(response, False, id=0, status=False)

        finally:
            Session.close()



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

            if ok is True:
                ret = u":-)"
            else:
                ret = u":-("
            res.append(ret)

            if opt is not None:

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
            user = getUserFromParam(param)
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
            # If an internal error occurs or the SMS gateway did not send
            # the SMS, we write this to the detail info.
            c.audit['info'] = unicode(exx)
            Session.rollback()
            return sendResult(response, False, 0)

        finally:
            Session.close()

    def pair(self):
        """
        validate/pair: for the enrollment of qr and push token
        """

        try:

            # -------------------------------------------------------------- --

            params = dict(**request.params)

            enc_response = params.get('pairing_response')

            if enc_response is None:
                raise Exception('Parameter missing')

            # -------------------------------------------------------------- --

            dec_response = decrypt_pairing_response(enc_response)
            token_type = dec_response.token_type
            pairing_data = dec_response.pairing_data

            if not hasattr(pairing_data, 'serial') or \
               pairing_data.serial is None:

                raise ValidateError('Pairing responses with no serial attached'
                                    ' are currently not implemented.')

            # --------------------------------------------------------------- -

            # TODO: pairing policy
            tokens = getTokens4UserOrSerial(None, pairing_data.serial)

            if not tokens:
                raise Exception('Invalid serial in pairing response')

            if len(tokens) > 1:
                raise Exception('Multiple tokens found. Pairing not possible')

            token = tokens[0]

            # prepare some audit entries
            t_owner = token.getUser()

            realms = token.getRealms()
            realm = ''
            if realms:
                realm = realms[0]

            c.audit['user'] = t_owner or ''
            c.audit['realm'] = realm

            # --------------------------------------------------------------- --

            if token.type != token_type:
                raise Exception('Serial in pairing response doesn\'t match '
                                'supplied token_type')

            # --------------------------------------------------------------- --

            token.pair(pairing_data)
            c.audit['success'] = 1

            Session.commit()
            return sendResult(response, False)

        # ------------------------------------------------------------------- --

        except Exception as exx:
            log.exception("validate/pair failed: %r" % exx)
            c.audit['info'] = unicode(exx)
            Session.rollback()
            return sendResult(response, False, 0, status=False)

        finally:
            Session.close()

# eof #########################################################################

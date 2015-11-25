# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
""" validation processing logic"""

import logging
import linotp

import linotp.lib.policy

from linotp.lib.challenges import Challenges
from linotp.lib.error import ParameterError
from linotp.lib.realm import getDefaultRealm
from linotp.lib.resolver import getResolverObject
from linotp.lib.token import TokenHandler
from linotp.lib.user import (User, getUserId, getUserInfo)


log = logging.getLogger(__name__)



def check_pin(token, passw, user=None, options=None):
    '''
    check the provided pin w.r.t. the policy definition

    :param passw: the to be checked pass
    :param user: if otppin==1, this is the user, which resolver should
                 be checked
    :param options: the optional request parameters

    :return: boolean, if pin matched True
    '''
    res = False
    context = token.context
    pin_policies = linotp.lib.policy.get_pin_policies(user, context=context)

    if 1 in pin_policies:
        # We check the Users Password as PIN
        log.debug('pin policy=1: checking the users password as pin')
        if (user is None or not user.login):
            log.info('- fail for pin policy == 1 with user = None')
            return False

        (uid, _resolver, resolver_class) = getUserId(user)

        r_obj = getResolverObject(resolver_class)
        if r_obj.checkPass(uid, passw):
            log.debug('[__checkToken] Successfully authenticated user %r.'
                                                                    % uid)
            res = True
        else:
            log.info('[__checkToken] user %r failed to authenticate.'
                                                                    % uid)

    elif 2 in pin_policies:
        # NO PIN should be entered atall
        log.debug('[__checkToken] pin policy=2: checking no pin')
        if len(passw) == 0:
            res = True
    else:
        # old stuff: We check The fixed OTP PIN
        log.debug('[__checkToken] pin policy=0: checkin the PIN')
        res = token.checkPin(passw, options=options)

    return res



def check_otp(token, otpval, options=None):
    """
    check the otp value

    :param otpval: the to be checked otp value
    :param options: the additional request parameters

    :return: result of the otp check, which is
            the matching otpcounter or -1 if not valid
    """

    log.debug('entering function check_otp()')
    log.debug('token  : %r' % token)
    # This is only the OTP value, not the OTP PIN
    log.debug('OtpVal : %r' % otpval)

    res = -1

    counter = token.getOtpCount()
    window = token.getOtpCountWindow()

    res = token.checkOtp(otpval, counter, window, options=options)
    return res

def split_pin_otp(token, passw, user=None, options=None):
    """
    split the pin and the otp fron the given password

    :param passw: the to be splitted password
    :param options: currently not used, but might be forwarded to the
                    token.splitPinPass
    :return: tuple of (split status, pin and otpval)
    """
    context = token.context
    pin_policies = linotp.lib.policy.get_pin_policies(user, context=context)

    policy = 0

    if 1 in pin_policies:
        log.debug('pin policy=1: checking the '
                                                'users password as pin')
        # split the passw into password and otp value
        (pin, otp) = token.splitPinPass(passw)
        policy = 1
    elif 2 in pin_policies:
        # NO PIN should be entered atall
        log.debug('pin policy=2: checking no pin')
        (pin, otp) = ('', passw)
        policy = 2
    else:
        # old stuff: We check The fixed OTP PIN
        log.debug('pin policy=0: checkin the PIN')
        (pin, otp) = token.splitPinPass(passw)

    res = policy
    return (res, pin, otp)

class ValidationHandler(object):

    def __init__(self, context):
        self.context = context

    def checkSerialPass(self, serial, passw, options=None, user=None):
        """
        This function checks the otp for a given serial

        :attention: the parameter user must be set, as the pin policy==1 will
                    verify the user pin
        """

        log.debug('checking for serial %r' % serial)
        tokenList = linotp.lib.token.getTokens4UserOrSerial(None, serial,
                                                  context=self.context)

        if passw is None:
            #  other than zero or one token should not happen, as serial is unique
            if len(tokenList) == 1:
                theToken = tokenList[0]
                tok = theToken.token
                realms = tok.getRealmNames()
                if realms is None or len(realms) == 0:
                    realm = getDefaultRealm()
                elif len(realms) > 0:
                    realm = realms[0]
                userInfo = getUserInfo(tok.LinOtpUserid, tok.LinOtpIdResolver,
                                       tok.LinOtpIdResClass)
                user = User(login=userInfo.get('username'), realm=realm)
                user.info = userInfo

                if theToken.is_challenge_request(passw, user, options=options):
                    (res, opt) = Challenges.create_challenge(
                        theToken, self.context, options)
                else:
                    raise ParameterError('Missing parameter: pass', id=905)

            else:
                raise Exception('No token found: unable to create challenge for %s'
                                 % serial)

        else:
            log.debug('checking len(pass)=%r for serial %r'
                  % (len(passw), serial))

            (res, opt) = linotp.lib.token.checkTokenList(tokenList, passw,
                                                        user=user,
                                                        options=options,
                                                        context=self.context)

        return (res, opt)

    def checkUserPass(self, user, passw, options=None):
        """
        :param user: the to be identified user
        :param passw: the identifiaction pass
        :param options: optional parameters, which are provided
                    to the token checkOTP / checkPass

        :return: tuple of True/False and optional information
        """

        log.debug('entering function checkUserPass(%r)'
                  % (user.login))
        # the upper layer will catch / at least should ;-)

        opt = None
        serial = None
        resolverClass = None
        uid = None

        audit = self.context['audit']

        if user is not None and (user.isEmpty() == False):
        # the upper layer will catch / at least should
            try:
                (uid, _resolver, resolverClass) = getUserId(user)
            except:
                passOn = self.context.get('Config').get(
                                            'linotp.PassOnUserNotFound', False)
                # passOn = getFromConfig(passOnNoUser, False)
                if False != passOn and 'true' == passOn.lower():
                    audit['action_detail'] = (
                                        'authenticated by PassOnUserNotFound')
                    return (True, opt)
                else:
                    audit['action_detail'] = 'User not found'
                    return (False, opt)

        tokenList = linotp.lib.token.getTokens4UserOrSerial(user, serial,
                                                            context=self.context)

        if len(tokenList) == 0:
            audit['action_detail'] = 'User has no tokens assigned'

            # here we check if we should to autoassign and try to do it
            log.debug('about to check auto_assigning')

            th = TokenHandler(context=self.context)
            auto_assign_return = th.auto_assignToken(passw, user)
            if auto_assign_return == True:
                # We can not check the token, as the OTP value is already used!
                # but we will authenticate the user....
                return (True, opt)

            auto_enroll_return, opt = th.auto_enrollToken(passw, user,
                                                            options=options)
            if auto_enroll_return is True:
                # we always have to return a false, as
                # we have a challenge tiggered
                return (False, opt)

            passOn = self.context.get('Config').get('linotp.PassOnUserNoToken',
                                                         False)
            if passOn and 'true' == passOn.lower():
                audit['action_detail'] = 'authenticated by PassOnUserNoToken'
                return (True, opt)

            #  Check if there is an authentication policy passthru
            from linotp.lib.policy import get_auth_passthru
            if get_auth_passthru(user, context=self.context):
                log.debug('user %r has no token. Checking for '
                          'passthru in realm %r' % (user.login, user.realm))
                y = getResolverObject(resolverClass)
                audit['action_detail'] = 'Authenticated against Resolver'
                if y.checkPass(uid, passw):
                    return (True, opt)

            #  Check if there is an authentication policy passOnNoToken
            from linotp.lib.policy import get_auth_passOnNoToken
            if get_auth_passOnNoToken(user, context=self.context):
                log.info('user %r has not token. PassOnNoToken'
                         ' set - authenticated!')
                audit['action_detail'] = (
                    'Authenticated by passOnNoToken policy')
                return (True, opt)

            return (False, opt)

        if passw is None:
            raise ParameterError(u"Missing parameter:pass", id=905)

        (res, opt) = linotp.lib.token.checkTokenList(
            tokenList, passw, user, options=options, context=self.context)
        log.debug('return of __checkTokenList: %r ' % (res,))

        return (res, opt)


# eof###########################################################################

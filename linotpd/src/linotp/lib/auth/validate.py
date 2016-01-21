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
""" validation processing logic"""

import logging

import linotp
import linotp.lib.policy

from pylons import config

from linotp.lib.auth.finishtokens import FinishTokens
from linotp.lib.auth.request import HttpRequest
from linotp.lib.auth.request import RadiusRequest
from linotp.lib.challenges import Challenges
from linotp.lib.error import ParameterError
from linotp.lib.realm import getDefaultRealm
from linotp.lib.resolver import getResolverObject
from linotp.lib.token import TokenHandler
from linotp.lib.user import (User, getUserId, getUserInfo)
from linotp.lib.util import modhex_decode

from linotp.lib.context import request_context as context

log = logging.getLogger(__name__)


def check_pin(token, passw, user=None, options=None):
    """
    check the provided pin w.r.t. the policy definition

    :param token: the token to be checked
    :param passw: the to be checked pass
    :param user: if otppin==1, this is the user, which resolver should
                 be checked
    :param options: the optional request parameters

    :return: boolean, if pin matched True
    """
    res = False
    pin_policies = linotp.lib.policy.get_pin_policies(user)

    if 1 in pin_policies:
        # We check the Users Password as PIN
        log.debug('pin policy=1: checking the users password as pin')
        if user is None or not user.login:
            log.info('- fail for pin policy == 1 with user = None')
            return False

        (uid, _resolver, resolver_class) = getUserId(user)

        r_obj = getResolverObject(resolver_class)
        if r_obj.checkPass(uid, passw):
            log.debug('[__checkToken] Successfully authenticated user %r.'
                      % uid)
            res = True
        else:
            log.info('[__checkToken] user %r failed to auth.' % uid)

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

    :param token: the corresponding token
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

    :param token: the corresponding token
    :param passw: the to be splitted password
    :param user: the tokenuser
    :param options: currently not used, but might be forwarded to the
                    token.splitPinPass
    :return: tuple of (split status, pin and otpval)
    """
    pin_policies = linotp.lib.policy.get_pin_policies(user)

    policy = 0

    if 1 in pin_policies:
        log.debug('pin policy=1: checking the users password as pin')
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

    def checkSerialPass(self, serial, passw, options=None, user=None):
        """
        This function checks the otp for a given serial

        :attention: the parameter user must be set, as the pin policy==1 will
                    verify the user pin
        """

        log.debug('checking for serial %r' % serial)
        tokenList = linotp.lib.token.getTokens4UserOrSerial(
            None, serial)

        if passw is None:
            # other than zero or one token should not happen, as serial is unique
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
                        theToken, options)
                else:
                    raise ParameterError('Missing parameter: pass', id=905)

            else:
                raise Exception('No token found: '
                                'unable to create challenge for %s' % serial)

        else:
            log.debug('checking len(pass)=%r for serial %r' %
                      (len(passw), serial))

            (res, opt) = self.checkTokenList(
                tokenList, passw, user=user, options=options)

        return (res, opt)

    def do_request(self):

        return

    def checkUserPass(self, user, passw, options=None):
        """
        :param user: the to be identified user
        :param passw: the identifiaction pass
        :param options: optional parameters, which are provided
                    to the token checkOTP / checkPass

        :return: tuple of True/False and optional information
        """

        log.debug('entering function checkUserPass(%r)'
                  % user.login)
        # the upper layer will catch / at least should ;-)

        opt = None
        serial = None
        resolverClass = None
        uid = None
        audit = context['audit']
        user_exists = False

        if user is not None and (user.isEmpty() == False):
            # the upper layer will catch / at least should
            try:
                (uid, _resolver, resolverClass) = getUserId(user)
                user_exists = True
            except:
                pass_on = context.get('Config').get(
                                            'linotp.PassOnUserNotFound', False)
                if pass_on and 'true' == pass_on.lower():
                    audit['action_detail'] = (
                                        'authenticated by PassOnUserNotFound')
                    return (True, opt)
                else:
                    audit['action_detail'] = 'User not found'
                    return (False, opt)

        # if we have an user, check if we forward the request to another server
        if user_exists:
            from linotp.lib.policy import get_auth_forward
            servers = get_auth_forward(user)
            if servers:
                if 'radius://' in servers:
                    rad = RadiusRequest(servers=servers)
                    res, opt = rad.do_request(servers, user, passw, options)
                    return res, opt
                elif 'http://' in servers or 'https://' in servers:
                    http = HttpRequest(servers=servers)
                    res, opt = http.do_request(user, passw, options)
                    return res, opt

        tokenList = linotp.lib.token.getTokens4UserOrSerial(user, serial)

        if len(tokenList) == 0:
            audit['action_detail'] = 'User has no tokens assigned'

            # here we check if we should to autoassign and try to do it
            log.debug('about to check auto_assigning')

            th = TokenHandler()
            auto_assign_return = th.auto_assignToken(passw, user)
            if auto_assign_return is True:
                # We can not check the token, as the OTP value is already used!
                # but we will auth the user....
                return (True, opt)

            auto_enroll_return, opt = th.auto_enrollToken(passw, user,
                                                            options=options)
            if auto_enroll_return is True:
                # we always have to return a false, as
                # we have a challenge tiggered
                return (False, opt)

            pass_on = context.get('Config').get('linotp.PassOnUserNoToken',
                                                         False)
            if pass_on and 'true' == pass_on.lower():
                audit['action_detail'] = 'authenticated by PassOnUserNoToken'
                return (True, opt)

            #  Check if there is an authentication policy passthru
            from linotp.lib.policy import get_auth_passthru
            if get_auth_passthru(user):
                log.debug('user %r has no token. Checking for '
                          'passthru in realm %r' % (user.login, user.realm))
                y = getResolverObject(resolverClass)
                audit['action_detail'] = 'Authenticated against Resolver'
                if y.checkPass(uid, passw):
                    return (True, opt)

            #  Check if there is an authentication policy passOnNoToken
            from linotp.lib.policy import get_auth_passOnNoToken
            if get_auth_passOnNoToken(user):
                log.info('user %r has not token. PassOnNoToken'
                         ' set - authenticated!')
                audit['action_detail'] = (
                    'Authenticated by passOnNoToken policy')
                return (True, opt)

            return (False, opt)

        if passw is None:
            raise ParameterError(u"Missing parameter:pass", id=905)

        (res, opt) = self.checkTokenList(
            tokenList, passw, user, options=options)
        log.debug('return of __checkTokenList: %r ' % (res,))

        return (res, opt)

    def checkTokenList(self, tokenList, passw, user=User(), options=None):
        """
        identify a matching token and test, if the token is valid, locked ..
        This function is called by checkSerialPass and checkUserPass to

        :param tokenList: list of identified tokens
        :param passw: the provided passw (mostly pin+otp)
        :param user: the identified use - as class object
        :param options: additonal parameters, which are passed to the token

        :return: tuple of boolean and optional response
        """
        log.debug("[__checkTokenList] checking tokenlist: %r" % tokenList)
        reply = None

        tokenclasses = config['tokenclasses']

        #  add the user to the options, so that every token could see the user
        if not options:
            options = {}

        options['user'] = user

        # if there has been one token in challenge mode, we only handle challenges

        # if we got a validation against a sub_challenge, we extend this to
        # be a validation to all challenges of the transaction id
        import copy
        check_options = copy.deepcopy(options)
        state = check_options.get('state', check_options.get('transactionid', ''))
        if state and '.' in state:
            transid = state.split('.')[0]
            if 'state' in check_options:
                check_options['state'] = transid
            if 'transactionid' in check_options:
                check_options['transactionid'] = transid

        audit_entry = {}
        audit_entry['action_detail'] = "no token found!"


        challenge_tokens = []
        pin_matching_tokens = []
        invalid_tokens = []
        valid_tokens = []
        related_challenges = []

        # we have to preserve the result / reponse for token counters
        validation_results = {}

        for token in tokenList:
            log.debug('Found user with loginId %r: %r:\n',
                      token.getUserId(), token.getSerial())

            audit_entry['serial'] = token.getSerial()
            audit_entry['token_type'] = token.getType()

            # preselect: the token must be in the same realm as the user
            if user is not None:
                t_realms = token.token.getRealmNames()
                u_realm = user.getRealm()
                if (len(t_realms) > 0 and len(u_realm) > 0 and
                        u_realm.lower() not in t_realms):

                    audit_entry['action_detail'] = ("Realm mismatch for "
                                                    "token and user")

                    continue

            # check if the token is the list of supported tokens
            # if not skip to the next token in list
            typ = token.getType()
            if typ.lower() not in tokenclasses:
                log.error('token typ %r not found in tokenclasses: %r' %
                          (typ, tokenclasses))
                audit_entry['action_detail'] = "Unknown Token type"
                continue

            if not token.isActive():
                audit_entry['action_detail'] = "Token inactive"
                continue
            if token.getFailCount() >= token.getMaxFailCount():
                audit_entry['action_detail'] = "Failcounter exceeded"
                continue
            if not token.check_auth_counter():
                audit_entry['action_detail'] = "Authentication counter exceeded"
                continue
            if not token.check_validity_period():
                audit_entry['action_detail'] = "validity period mismatch"
                continue

            # start the token validation
            try:
                # are there outstanding challenges
                challenges = token.get_token_challenges(check_options)
                (ret, reply) = token.check_token(
                    passw, user, options=check_options, challenges=challenges)
            except Exception as exx:
                # in case of a failure during checking token, we log the error
                # and continue with the next one
                log.exception("checking token %r failed: %r" % (token, exx))
                ret = -1
                reply = "%r" % exx
                audit_entry['action_detail'] = ("checking token %r "
                                                "failed: %r" % (token, exx))
                continue
            finally:
                validation_results[token.getSerial()] = (ret, reply)

            (cToken, pToken, iToken, vToken) = token.get_verification_result()
            related_challenges.extend(token.related_challenges)

            challenge_tokens.extend(cToken)
            pin_matching_tokens.extend(pToken)
            invalid_tokens.extend(iToken)
            valid_tokens.extend(vToken)

        # end of token verification loop

        # if there are related / sub challenges, we have to call their janitor
        Challenges.handle_related_challenge(related_challenges)

        # now we finalize the token validation result
        fh = FinishTokens(valid_tokens,
                          challenge_tokens,
                          pin_matching_tokens,
                          invalid_tokens,
                          validation_results,
                          user, options,
                          audit_entry=audit_entry)

        (res, reply) = fh.finish_checked_tokens()

        # add to all tokens the last accessd time stamp
        linotp.lib.token.add_last_accessed_info(
            [valid_tokens, pin_matching_tokens, challenge_tokens, valid_tokens])

        log.debug("Number of valid tokens found "
                  "(validTokenNum): %d" % len(valid_tokens))

        return (res, reply)

    def checkYubikeyPass(self, passw):
        """
        Checks the password of a yubikey in Yubico mode (44,48), where
        the first 12 or 16 characters are the tokenid

        :param passw: The password that consist of the static yubikey prefix
                        and the otp
        :type passw: string

        :return: True/False and the User-Object of the token owner
        :rtype: dict
        """

        audit = context['audit']
        opt = None
        res = False

        tokenList = []

        # strip the yubico OTP and the PIN
        modhex_serial = passw[:-32][-16:]
        try:
            serialnum = "UBAM" + modhex_decode(modhex_serial)
        except TypeError as exx:
            log.error("Failed to convert serialnumber: %r" % exx)
            return res, opt

        #  build list of possible yubikey tokens
        serials = [serialnum]
        for i in range(1, 3):
            serials.append("%s_%s" % (serialnum, i))

        for serial in serials:
            tokens = linotp.lib.token.getTokens4UserOrSerial(serial=serial)
            tokenList.extend(tokens)

        if len(tokenList) == 0:
            audit['action_detail'] = (
                                'The serial %s could not be found!' % serialnum)
            return res, opt

        # FIXME if the Token has set a PIN and the User does not want to enter
        # the PIN for authentication, we need to do something different here...
        #  and avoid PIN checking in __checkToken.
        #  We could pass an "option" to __checkToken.
        (res, opt) = self.checkTokenList(tokenList, passw)

        # Now we need to get the user
        if res is not False and 'serial' in audit:
            serial = audit.get('serial', None)
            if serial is not None:
                user = self.getTokenOwner(serial)
                audit['user'] = user.login
                audit['realm'] = user.realm
                opt = {'user': user.login, 'realm': user.realm}

        return res, opt

# eof###########################################################################

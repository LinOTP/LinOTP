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
"""This file file contains the Forward token class"""

import logging

from linotp.lib.context import request_context as context

from linotp.lib.policy import getPolicy

from linotp.lib.auth.validate import check_pin
from linotp.lib.auth.validate import split_pin_otp

from linotp.lib.tokenclass import TokenClass
from linotp.lib.token import getTokenRealms
from linotp.lib.token import get_token_owner


log = logging.getLogger(__name__)

###############################################


def do_forward_failcounter(token):
    '''
    this function checks the for the policy

        scope=authentication,
        action=forwardtoken:no_failcounter_forwarding

    defining if the target token failcounter should be incremented / reseted

    :param serial: the token serial number, which allows to derive the
                   realm(s) and owner from
    :return: boolean
    '''
    boolean = True

    owner = get_token_owner(token)
    if owner and owner.realm:
        realms = [owner.realm]
    else:
        realms = getTokenRealms(token.getSerial())

    if not realms:
        realms = ['*']

    for realm in realms:
        params = {'scope': 'authentication',
                  'realm': realm,
                  'action': "forwardtoken:no_failcounter_forwarding"
                  }

        if owner and owner.login:
            params['user'] = owner.login

        pol = getPolicy(params)

        if pol:
            boolean = False
            break

    return boolean


class ForwardTokenClass(TokenClass):
    """
    The Forward token forwards an authentication request to another token.
    specified by a serial number. The PIN is only checked local.

    Using the Forward token you can assign one physical token to many
    different users.
    """

    def __init__(self, aToken):
        """
        constructor - create a token class object with it's db token binding

        :param aToken: the db bound token
        """
        TokenClass.__init__(self, aToken)
        self.setType(u"forward")

        self.forwardSerial = None
        self.mode = ['authenticate', 'challenge']

        self.targetToken = None
        self.target_otp_count = -1

    @classmethod
    def getClassType(cls):
        """
        return the class type identifier
        """
        return "forward"

    @classmethod
    def getClassPrefix(cls):
        """
        return the token type prefix
        """
        return "LSFW"

    @classmethod
    def getClassInfo(cls, key=None, ret='all'):
        """
        getClassInfo - returns a subtree of the token definition

        :param key: subsection identifier
        :param ret: default return value, if nothing is found
        :return: subsection if key exists or user defined

        """

        _ = context['translate']

        log.debug("[getClassInfo] begin. Get class render info for section: "
                  "key %r, ret %r " % (key, ret))

        res = {'type': 'forward',
               'title': 'Forward Token',
               'description': ('Forward token to forward the'
                               ' otp authentication request to another token'),

               'init': {'page': {'html': 'forwardtoken.mako',
                                 'scope': 'enroll', },
                        'title': {'html': 'forwardtoken.mako',
                                  'scope': 'enroll.title', },
                        },

               'selfservice': {},
               'policy': {
                'authentication': {
                   'forwardtoken:no_failcounter_forwarding': {
                      'type': 'bool',
                      'desc': _('Specify if the target token fail counter'
                                ' should be incremented / resets or not')
                        },
                    },
                },  # end of policy
               }

        if key is not None and key in res:
            ret = res.get(key)
        else:
            if ret == 'all':
                ret = res

        log.debug("[getClassInfo] end. Returned the configuration section: "
                  "returned %r ", ret)
        return ret

    def update(self, param):
        """
        second phase of the init process - updates token specific parameters

        :param param: the request parameters
        :return: - nothing -
        """

        self.forwardSerial = param["forward.serial"]

        # get the otplen of the target token
        targetToken = self._getTargetToken(self.forwardSerial)

        TokenClass.update(self, param)

        self.setOtpLen(targetToken.getOtpLen())
        self.addToTokenInfo("forward.serial", self.forwardSerial)

        return

    def authenticate(self, passw, user, options=None):
        """
        do the authentication on base of password / otp and serial and
        options, the request parameters.

        :param passw: the password / otp
        :param user: the requesting user
        :param options: the additional request parameters

        :return: tupple of (success, otp_count - 0 or -1, reply)

        """
        log.debug("authenticate")

        otp_count = -1
        reply = None

        # we do a local pin check
        _res, pin, otpval = split_pin_otp(self, passw, user, options=options)

        res = check_pin(self, pin, user, options)
        if res is False:
            return res, otp_count, reply

        res, otp_count, reply = self.do_request(otpval, user=user)
        return res, otp_count, reply

    def is_challenge_request(self, passw, user, options=None):
        """
        This method checks, if this is a request, that triggers a challenge.
        The pin is checked locally only

        :param passw: password, which might be pin or pin+otp
        :param user: The user from the authentication request
        :param options: dictionary of additional request parameters

        :return: true or false
        """

        request_is_valid = False

        pin_match = check_pin(self, passw, user=user, options=options)
        if pin_match is True:
            request_is_valid = True

        return request_is_valid

    def do_request(self, passw, transactionid=None, user=None):
        """
        run the http request against the forward host

        :param passw: the password which should be checked on the forward host
        :param transactionid: provided,  if this is a challenge response
        :param user: the requesting user - used if no forward serial or forward
                     user is provided

        :return: Tuple of (success, otp_count= -1 or 0, reply=forward response)
        """

        forwardSerial = self.getFromTokenInfo("forward.serial") or ""

        log.debug("checking OTP len:%r  for target serial: %r",
                  len(passw), forwardSerial)

        targetToken = self._getTargetToken(forwardSerial)

        counter = targetToken.getOtpCount()
        window = targetToken.getOtpCountWindow()
        self.target_otp_count = targetToken.checkOtp(passw, counter, window)

        res = self.target_otp_count >= 0

        return (res, self.target_otp_count, None)

    def _getTargetToken(self, forwardSerial):
        """
        helper - to get the target token
        """
        if self.targetToken:
            return self.targetToken

        from linotp.lib.token import getTokens4UserOrSerial
        tokens = getTokens4UserOrSerial(serial=forwardSerial)

        if not tokens:
            raise Exception('no target token with serial %r found' %
                            forwardSerial)

        self.targetToken = tokens[0]
        return self.targetToken

    def checkResponse4Challenge(self, user, passw, options=None,
                                challenges=None):
        '''
        This method verifies if the given ``passw`` matches any
        existing ``challenge`` of the token.

        It then returns the new otp_counter of the token and the
        list of the matching challenges.

        In case of success the otp_counter needs to be >= 0.
        The matching_challenges is passed to the method
        :py:meth:`~linotp.lib.tokenclass.TokenClass.challenge_janitor`
        to clean up challenges.

        :param user: the requesting user
        :param passw: the password (pin+otp)
        :param options:  additional arguments from the request, which could
                         be token specific
        :param challenges: A sorted list of valid challenges for this token.
        :return: tuple of (otpcounter and the list of matching challenges)

        '''
        otp_counter = -1
        transid = None
        matching_challenges = []

        if 'transactionid' in options or 'state' in options:
            # fetch the transactionid
            transid = options.get('transactionid', options.get('state', None))

        if transid:
            matching_challenge = None
            # check if transaction id is in list of challenges
            for challenge in challenges:
                if challenge.transid == transid:
                    matching_challenge = challenge
                    break

            if matching_challenge:
                res, otp_counter, _reply = self.do_request(passw, user=user)

                # everything is ok, we mark the challenge as a matching one
                if res is True and otp_counter >= 0:
                    matching_challenges.append(matching_challenge)

        return (otp_counter, matching_challenges)

    def statusValidationSuccess(self):
        """
        with this hook we
        * increment the target token otp count to prevent replay and
        * optionally reset the target token failcounter
        """
        forwardSerial = self.getFromTokenInfo("forward.serial") or ""
        targetToken = self._getTargetToken(forwardSerial)

        # we have to increment the target token otp counter here, as none
        # else is involved, using the preserved matching otp counter
        targetToken.incOtpCounter(self.target_otp_count)

        if not do_forward_failcounter(self):
            return

        targetToken.reset()

    def statusValidationFail(self):
        """
        with this hook we
        * increment the target token otp count to prevent replay and
        * optionally increment the target fail count
        """

        if not do_forward_failcounter(self):
            return

        forwardSerial = self.getFromTokenInfo("forward.serial") or ""
        targetToken = self._getTargetToken(forwardSerial)
        targetToken.incOtpFailCounter()


# eof ########################################################################

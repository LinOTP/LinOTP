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

from sqlalchemy import and_

import linotp.lib.policy
import linotp.lib.token
from linotp.lib.challenges import Challenges
from linotp.lib.config import getFromConfig
from linotp.lib.resolver import getResolverObject
from linotp.lib.user import getUserId
from linotp.model import Challenge
from linotp.model.meta import Session

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
        log.debug("[check_pin] pin policy=1: checking the users"
                                                    " password as pin")
        if (user is None or not user.login):
            log.info("[check_pin] - fail for pin policy == 1 "
                                                      "with user = None")
            return False

        (uid, _resolver, resolver_class) = getUserId(user)

        r_obj = getResolverObject(resolver_class)
        if  r_obj.checkPass(uid, passw):
            log.debug("[__checkToken] Successfully authenticated user %r."
                                                                    % uid)
            res = True
        else:
            log.info("[__checkToken] user %r failed to authenticate."
                                                                    % uid)

    elif 2 in pin_policies:
        # NO PIN should be entered atall
        log.debug("[__checkToken] pin policy=2: checking no pin")
        if len(passw) == 0:
            res = True
    else:
        # old stuff: We check The fixed OTP PIN
        log.debug("[__checkToken] pin policy=0: checkin the PIN")
        res = token.checkPin(passw, options=options)

    return res



def check_otp(token, otpval, options=None):
    '''
    check the otp value

    :param otpval: the to be checked otp value
    :param options: the additional request parameters

    :return: result of the otp check, which is
            the matching otpcounter or -1 if not valid
    '''

    log.debug("[check_otp] entering function check_otp()")
    log.debug("[check_otp] token  : %r" % token)
    # This is only the OTP value, not the OTP PIN
    log.debug("[check_otp] OtpVal : %r" % otpval)

    res = -1

    counter = token.getOtpCount()
    window = token.getOtpCountWindow()

    res = token.checkOtp(otpval, counter, window, options=options)
    return res

def split_pin_otp(token, passw, user=None, options=None):
    '''
    split the pin and the otp fron the given password

    :param passw: the to be splitted password
    :param options: currently not used, but might be forwarded to the
                    token.splitPinPass
    :return: tuple of (split status, pin and otpval)
    '''
    context = token.context
    pin_policies = linotp.lib.policy.get_pin_policies(user, context=context)

    policy = 0

    if 1 in pin_policies:
        log.debug("[split_pin_otp] pin policy=1: checking the "
                                                "users password as pin")
        # split the passw into password and otp value
        (pin, otp) = token.splitPinPass(passw)
        policy = 1
    elif 2 in pin_policies:
        # NO PIN should be entered atall
        log.debug("[split_pin_otp] pin policy=2: checking no pin")
        (pin, otp) = ("", passw)
        policy = 2
    else:
        # old stuff: We check The fixed OTP PIN
        log.debug("[split_pin_otp] pin policy=0: checkin the PIN")
        (pin, otp) = token.splitPinPass(passw)

    res = policy
    return (res, pin, otp)

class ValidationHandler(object):

    def __init__(self, context):
        self.context = context


# eof###########################################################################

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

import datetime
from linotp.lib.HMAC import HmacOtp

from linotp.lib.user import getUserDetail

from linotp.lib.auth.validate import check_pin
from linotp.lib.auth.validate import check_otp
from linotp.lib.auth.validate import split_pin_otp

from linotp.lib.config import getFromConfig
import binascii

from linotp.lib.policy import getPolicyActionValue
from linotp.lib.policy import getPolicy, get_client_policy
from linotp.lib.policy import trigger_phone_call_on_empty_pin


from linotp.lib.context import request_context as context
from linotp.lib.error import ParameterError

from linotp.tokens.hmactoken import HmacTokenClass
from linotp.tokens import tokenclass_registry

import logging

LOG = logging.getLogger(__name__)


@tokenclass_registry.class_entry('voice')
@tokenclass_registry.class_entry(
    'linotp.tokens.voicetoken.VoicetokenClass')
class VoiceTokenClass(HmacTokenClass):

    """
    Voice token class implementation
    """

# --------------------------------------------------------------------------- --

    def __init__(self, token_obj):
        """
        Constructor for VoiceToken
        :param token_obj: instance of the orm db object
        :type token_obj:  orm object
        """
        HmacTokenClass.__init__(self, token_obj)
        self.setType(u'voice')
        self.hKeyRequired = False # what is hkeyRequired... will be checked
        # if otpKey is none while updating - By init update will also be called
        # is hkeyRequired if seed is required by request? Where comes the
        # param variable from - request context ?

        # we support various hashlib methods, but only one create
        # which is effectively set in the update
        self.hashlibStr = getFromConfig("hotp.hashlib", "sha256")
        # we have no challenge mode
        self.mode = ['challenge'] # user want to login
        # challenge is triggered and otp comes via phone call to the user

    @classmethod
    def getClassType(cls):
        """
        getClassType - return the token type shortname

        :return: 'voice'
        :rtype: string

        """
        return "voice"

    @classmethod
    def getClassPrefix(cls):
        # OATH standard compliant prefix: XXYY XX= vendor, YY - token type
        return "LSVO"

    def get_challenge_validity(self):
        """
        This method returns the token specific challenge validity

        :return: int - validity in seconds (120 sec on ValueError)
        """

        try:
            validity = int(getFromConfig('DefaultChallengeValidityTime', 120))
            lookup_for = 'VOICEProviderTimeout'
            validity = int(getFromConfig(lookup_for, validity))

            # instance specific timeout
            validity = int(self.getFromTokenInfo('challenge_validity_time',
                                                 validity))

        except ValueError:
            validity = 120

        return validity
# --------------------------------------------------------------------------- --

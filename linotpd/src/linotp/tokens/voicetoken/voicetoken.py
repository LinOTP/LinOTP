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


# --------------------------------------------------------------------------- --
def get_auth_voice_text(user="", realm=""):
    """
    This function checks the policy scope=authentication, action=voicetext
    This is a string policy
    The function returns the tuple (bool, string),
        bool: If a policy is defined
        string: the string to use
    """
    # the default string is the OTP value
    ret = False
    voice_text = "<otp>"

    pol = get_client_policy(context['Client'], scope="authentication",
                            realm=realm, user=user, action="voicetext")

    if len(pol) > 0:
        voice_text = getPolicyActionValue(pol, "voicetext", is_string=True)
        LOG.debug("[get_auth_voicetext] got the voice text = %s" % voice_text)
        ret = True

    return ret, voice_text


def is_voice_editable(user=""):
    """
    this function checks the policy scope=selfservice, action=edit_voice
    This is a int policy, while the '0' is a deny
    """
    # the default string is the OTP value
    ret = True
    realm = user.realm
    login = user.login

    policies = getPolicy({'scope': 'selfservice',
                          'realm': realm,
                          "action": "edit_voice",
                          "user": login})
    if policies:
        edit_voice = getPolicyActionValue(policies, "edit_voice")
        if edit_voice == 0:
            ret = False

    return ret


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

    @classmethod
    def getClassInfo(cls, key=None, ret='all'):
        """
        getClassInfo - returns a subtree of the token definition

        :param key: subsection identifier
        :type key: string

        :param ret: default return value, if nothing is found
        :type ret: user defined

        :return: subsection if key exists or user defined
        :rtype: s.o.

        """
        LOG.debug("[getClassInfo] begin. Get class render info for section: "
                  "key %r, ret %r " % (key, ret))

        _ = context['translate']

        res = {
            'type': 'voice',
            'title': 'Voice Token',
            'description': 'An voice token.',
            'init': {
                'page': {
                    'html': 'voicetoken.mako',
                    'scope': 'enroll',
                },
                'title': {
                    'html': 'voicetoken.mako',
                    'scope': 'enroll.title',
                },
            },
            'config': {
                'title': {
                    'html': 'voicetoken.mako',
                    'scope': 'config.title',
                },
                'page': {
                    'html': 'voicetoken.mako',
                    'scope': 'config',
                },
            },
            'selfservice': {
                'enroll':
                    {'page': {
                        'html': 'voicetoken.mako',
                        'scope': 'selfservice.enroll', },
                        'title': {
                            'html': 'voicetoken.mako',
                            'scope': 'selfservice.title.enroll', },
                    },
            }
            ,
            'policy': {
                'selfservice': {
                    'edit_voice':
                        {'type': 'int',
                         'value': [0, 1],
                         'desc': _('define if the user should be allowed'
                                   ' to define the phone number')
                         }
                },
                'authentication': {
                    'voice_language': {
                        'type': 'str',
                        'desc': _('Define the language which should be used'
                                  'to render the voice message.')
                    },
                    'voice_message': {
                        'type': 'str',
                        'desc': _('Define the message which will be send'
                                  'to the voice service for the phone'
                                  'call.')
                    },
                    'voice_dynamic_mobile_number': {
                        'type': 'bool',
                        'desc': _('If set, a new mobile number will be '
                                  'retrieved from the user info instead '
                                  'of the token')
                    },
                }
            }
        }
        # do we need to define the lost token policies here...
        # [comment copied from sms token]
        if key is not None and key in res:
            ret = res.get(key)
        else:
            if ret == 'all':
                ret = res
        LOG.debug("[getClassInfo] end. Returned the configuration section:"
                  " ret %r " % ret)
        return ret

# --------------------------------------------------------------------------- --

    def update(self, param, reset_fail_count=True):
        """
        Process initialization parameters

        :param param: dict of initialization parameters (request context?
        where comes it from?
                      if entries we add missing entries for calling the
                      parent class method
        :param reset_fail_count : boolean if the fail count should be reset

        :return: nothing
        """

        _ = context['translate']

        # if no hash algorithm in param; add sha256. Otherwise the
        # parent classes update method will set sha1 which is not intended
        self.hashlibStr = param.get('hashlib', 'sha256')
        param['hashlib'] = self.hashlibStr


        # specific - phone
        try:
            phone = param['phone']
        except KeyError:
            raise ParameterError("Missing parameter: 'phone'")

        # in scope self service - check if edit_voice is allowed
        # if not allowed to edit, check if the phone is the same
        # as from the user data
        if param.get('::scope::', {}).get('selfservice', False):
            user = param['::scope::']['user']
            if not is_voice_editable(user):
                u_info = getUserDetail(user)
                u_phone = u_info.get('mobile', u_info.get('phone', None))
                if u_phone != phone:
                    raise Exception(_('User is not allowed to '
                                      'set phone number'))

        self.set_phone(phone)

        # in case of the voice token, only the server must know the otpkey
        # thus if none is provided, we let create one (in the TokenClass)
        if 'genkey' not in param and 'otpkey' not in param:
            param['genkey'] = 1

        # call update from parent
        HmacTokenClass.update(self, param, reset_fail_count)

# --------------------------------------------------------------------------- --

    def is_challenge_response(self, passw, user, options=None,
                              challenges=None):
        """
        check, if the request contains the result of a challenge

        :param passw: password, which might be pin or pin+otp
        :param user: the requesting user
        :param options: dictionary of additional request parameters
        :param challenges: Not used in this method #TODO
        :return: returns true or false
        """

        if "state" in options or "transactionid" in options:
            return True

        # it as well might be a challenge response,
        # if the passw is longer than the pin
        (policy_type, pin, otp_val) = split_pin_otp(self, passw, user=user,
                                           options=options)
        if policy_type >= 0:
            otp_counter = check_otp(self, otp_val, options=options)
            if otp_counter >= 1:
                pin_match = check_pin(self, pin, user=user, options=options)
                if not pin_match:
                    return False
            if otp_counter >= 0:
                return True

        return False

    def is_challenge_request(self, passw, user, options=None):
        """
        check, if the request would start a challenge

        - default: if the passw contains only the pin, this request would
        trigger a challenge

        - in this place as well the policy for a token is checked

        :param passw: password, which might be pin or pin+otp
        :param options: dictionary of additional request parameters

        :return: returns true or false
        """

        # Todo: distinguish passw contains a (pin + otp) or b (transactionid
        # + otp)
        # case a occurs if a user is unable to send a transaction id (radius)
        # a) pin + otp

        # b) otp but a transactionID is given via request

        request_is_valid = False

        realms = self.token.getRealmNames()

        if trigger_phone_call_on_empty_pin(realms):
            if 'check_s' in options.get('scope', {}) and 'challenge' in options:
                request_is_valid = True
                return request_is_valid

        # if its a challenge, the passw contains only the pin
        pin_match = check_pin(self, passw, user=user, options=options)
        if pin_match is True:
            request_is_valid = True

        return request_is_valid

# --------------------------------------------------------------------------- --

    def initChallenge(self, transaction_id, challenges=None, options=None):
        """
        initialize the challenge -
        in the linotp server a challenge object has been allocated and
        this method is called to confirm the need of a new challenge
        or if for the challenge request, there is an already outstanding
        challenge to which then could be referred (s. ticket #2986)

        :param transaction_id: the id of the new challenge
        :param challenges: the challenges list.
        :param options: the request parameters

        :return: tuple of
                success - bool
                trans_id - the best transaction id for this request context
                message - which is shown to the user
                attributes - further info (dict) shown to the user
        """

        success = True
        trans_id = transaction_id
        message = 'challenge init ok'
        attributes = {}

        now = datetime.datetime.now()
        blocking_time = int(getFromConfig('VoiceBlockingTimeout', 60))

        # reuse challenge
        for challenge in challenges:
            if not challenge.is_open():
                continue
            start = challenge.get('timestamp')
            expiry = start + datetime.timedelta(seconds=blocking_time)
            # # check if there is already a challenge underway
            if now <= expiry:
                trans_id = challenge.getTransactionId()
                message = 'voice call with otp already submitted'
                success = False
                attributes = {'info': 'challenge already submitted',
                              'state': trans_id}
                break

        return success, trans_id, message, attributes

    def createChallenge(self, transaction_id, options=None):
        """
        create a challenge, which is submitted to the user

        Create a random counter and return it to the challenge dict,
        as well to the submit method which create an otp for the phone
        call based on this counter.

        :param transaction_id: the id of this challenge
        :param options: the request context parameters / data
        :return: tuple of (bool, message and data)
                 bool, if submit was successful
                 message is submitted to the user
                 data is preserved in the challenge
                 attributes - additional attributes, which are added in to the
                              challenge dict (in the method which calls this
                              method)
        """

        # use a random number as counter which will be stored in the
        # challenge context to verify the otp.
        random_int = self._get_rand_int(length=8)

        # send calculated otp to user via voice provider
        otp_value = self.get_otp(counter=random_int)
        # get message from policy
        # TODO get message from policy, german and english
        message = 'Hello, your O<pause>T<pause>P<pause> is <otp>'

        success, info = self._submit_to_provider(otp_value, message)

        options['state'] = transaction_id

        if success is True:
            message = 'voice call triggered'
        else:
            attributes = {'state': ''}
            message = 'triggering voice call failed'
            if info:
                message = info

        # prepare parameter to return
        data = {'counter': str(random_int)}
        # add state to attributes which will be set to a challenges dict
        # after this method. Radius will send the transactionID in the
        # state parameter, so this is for radius compatibility
        attributes = {'state': transaction_id}

        return success, message, data, attributes

    # Todo: move into a more reasonable place (hsm_object?)
    @staticmethod
    def _get_rand_int(length=8):
        """
        Create random integer based on hsm objects random method.

        :param length: length in bytes
        :return: random number with length of len bytes
        """
        hsm_obj = context.get('hsm', {}).get('obj')
        random_bytes = hsm_obj.random(len=length)
        return int(binascii.hexlify(random_bytes), 16)

# --------------------------------------------------------------------------- --

    def checkResponse4Challenge(self, user, passw, options=None, challenges=None):
        """
        verify the response of a previous challenge

        :param user:     requesting user
        :param passw:    to be checked pass (pin+otp)
        :param options:  an additional argument, which could be token
                         specific
        :param challenges: list of challenges, where each challenge is
                           described as dict
        :return: tuple containing a) otp counter and b) the list of matching
                 challenges: (a,b)

        do the standard check for the response of the challenge +
        change the tokeninfo data of the last challenge
        """
        otp_count = -1
        matching = []

        tok = super(VoiceTokenClass, self)

        # in var passw might be only the otp, otherwise otp_val will be
        # overwritten later.
        otp_val = passw

        # # fallback: do we have pin+otp ??
        (active_pin_policy, pin, otp) = split_pin_otp(self, passw, user=user,
                                                      options=options)

        if active_pin_policy >= 0:
            res = check_pin(self, pin, user=user, options=options)
            if res is True:
                otp_val = otp

        for challenge in challenges:
            counter_from_challenge = challenge.get('data').get('counter')
            otp_count = self.check_otp(otp_value=otp_val,
                                       counter=int(counter_from_challenge))
            if otp_count > 0:
                matching.append(challenge)
                break

        return otp_count, matching

    def submit_challenge_to_provider(self, otp_value, message):
        """
        submit the voice message - former method name was checkPin

        :param otp_value: One time password to transfer to voice provider
        :type otp_value: string
        :param message: Text message to be read from the voice service
        :type message: string

        :return: Tuple of success and message
        """
        _ = context['translate']

        success = True  # not successful
        message = u'Not implemented at this time'

        return success, message

    def getOtp(self, curTime=None):
        """
        get the next OTP value from hmactoken.py

        In voice token this method will not be used

        :return: next otp value
        :rtype: string
        """
        raise NotImplemented('Voice Token have no curTime attribute for get '
                             'otp')

    def get_otp(self, counter):
        """
        Get next otp value for given data used as counter for hotp
        algorithm

        :param counter: data to give as counter into the hotp algorithm
        :type counter: base64 encoded string

        :return: otp value
        :rtype: string
        """
        # get otp length from stored token in database
        try:
            otp_length = int(self.token.LinOtpOtpLen)
        except ValueError as value_error_ex:
            log.exception('[getOTP]: Could not convert otplen - value error '
                          '%r' % (value_error_ex))
            raise value_error_ex

        # get otp for data using secret object and hotp algorithm
        secret_object = self._get_secret_object()
        hmac_otp_obj = HmacOtp(secret_object, counter, otp_length,
                               self.getHashlib(self.hashlibStr))
        otp_value = hmac_otp_obj.generate(inc_counter=False)

        return otp_value

    def checkOtp(self, otp_value, counter, window, options=None):
        """
        checkOtp - validate the token otp against a given otpvalue

        :param otp_value: the to be verified otpvalue
        :type otp_value:  string

        :param counter: the counter state, that should be verified
        :type counter: int

        :param window: the counter +window, which should be checked
        :type window: int

        :param options: the dict, which could contain token specific info
        :type options: dict

        :return: the counter state or -1
        :rtype: int
        """

        success = -1
        if otp_value == self.get_otp(counter):
            success = 1

        if success >= 0:
            msg = "otp verification was successful!"
        else:
            msg = "otp verification failed!"
        log.debug(msg)
        return success

    # in the voice token we use the generic TokenInfo
    # to store the phone number
    def set_phone(self, phone):
        """
        setter for the phone number

        :param phone: phone number
        :type phone:  string

        :return: nothing
        """
        self.addToTokenInfo("phone", phone)
        return

    def getInitDetail(self, params, user=None):
        """
        to complete the token normalisation, the response of the initialiastion
        should be build by the token specific method, the getInitDetails
        """
        response_detail = {'serial': self.getSerial()}
        return response_detail

# eof #

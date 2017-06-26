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
"""
This file contains the e-mail token implementation:
              - EmailTokenClass   (HOTP)
"""
import datetime
import logging
import sys

from linotp.provider import loadProviderFromPolicy

from linotp.lib.token import get_token_owner

from linotp.lib.auth.validate import split_pin_otp
from linotp.lib.auth.validate import check_pin

from linotp.lib.HMAC import HmacOtp
from linotp.lib.challenges import Challenges
from linotp.lib.config import getFromConfig
from linotp.lib.policy import getPolicy, get_client_policy
from linotp.lib.policy import getPolicyActionValue

from linotp.lib.tokens.hmactoken import HmacTokenClass
from linotp.lib.user import getUserDetail
from linotp.lib.context import request_context as context

if sys.version_info[0:2] >= (2, 6):
    from json import loads
else:
    from simplejson import loads

optional = True
required = False

LOG = logging.getLogger(__name__)


def is_email_editable(user=""):
    '''
    this function checks the policy scope=selfservice, action=edit_email
    This is a int policy, while the '0' is a deny
    '''
    ret = True
    realm = user.realm
    login = user.login

    policies = getPolicy({'scope': 'selfservice',
                          'realm': realm,
                          "action": "edit_email",
                          "user": login},
                          )
    if policies:
        edit_email = getPolicyActionValue(policies, "edit_email")
        if edit_email == 0:
            ret = False

    return ret


class EmailTokenClass(HmacTokenClass):
    """
    E-mail token (similar to SMS token)
    """

    EMAIL_ADDRESS_KEY = "email_address"
    DEFAULT_EMAIL_PROVIDER = "linotp.provider.emailprovider.SMTPEmailProvider"
    DEFAULT_EMAIL_BLOCKING_TIMEOUT = 120

    def __init__(self, aToken):
        HmacTokenClass.__init__(self, aToken)
        self.setType(u"email")
        self.hKeyRequired = False

        # we support various hashlib methods, but only on create
        # which is effectively set in the update
        self.hashlibStr = context['Config'].get("hotp.hashlib", "sha1")
        self.mode = ['challenge']

    @property
    def _email_address(self):
        return self.getFromTokenInfo(self.EMAIL_ADDRESS_KEY)

    @_email_address.setter
    def _email_address(self, value):
        self.addToTokenInfo(self.EMAIL_ADDRESS_KEY, value)

    @classmethod
    def getClassType(cls):
        return "email"

    @classmethod
    def getClassPrefix(cls):
        return "LSEM"

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
            'type':         'email',
            'title':        'E-mail Token',
            'description':  'An e-mail token.',
            'init': {
                'page': {
                    'html': 'emailtoken.mako',
                    'scope': 'enroll',
                },
                'title': {
                    'html': 'emailtoken.mako',
                    'scope': 'enroll.title',
                },
            },
            'config': {
                'title': {
                    'html': 'emailtoken.mako',
                    'scope': 'config.title',
                },
                'page': {
                    'html': 'emailtoken.mako',
                    'scope': 'config',
                },
            },
            'selfservice': {
                'enroll':
                    {'page': {
                        'html': 'emailtoken.mako',
                        'scope': 'selfservice.enroll', },
                        'title': {
                            'html': 'emailtoken.mako',
                            'scope': 'selfservice.title.enroll', },
                    },
            },
            'policy': {
                'selfservice':  {
                    'edit_email':
                        {'type': 'int',
                         'value': [0, 1],
                         'desc': _('define if the user should be allowed'
                                   ' to define the email address')
                         }
                },
                'authentication': {
                    'emailtext': {
                        'type': 'str',
                        'desc': _('The text that will be send via email '
                                  'for an email token. Use <otp> '
                                  'and <serial> as parameters.')
                    },
                    'emailsubject': {
                        'type': 'str',
                        'desc': _('The subject that will be send via email '
                                  'for an email token. Use <otp> '
                                  'and <serial> as parameters.')
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

    def update(self, param, reset_failcount=True):
        """
        update - process initialization parameters

        :param param: dict of initialization parameters
        :type param: dict

        :return: nothing

        """
        LOG.debug("[update] begin. adjust the token class with: param %r"
                  % param)

        _ = context['translate']

        # specific - e-mail
        self._email_address = param[self.EMAIL_ADDRESS_KEY]
        # in scope selfservice - check if edit_email is allowed
        # if not allowed to edit, check if the email is the same
        # as from the user data
        if param.get('::scope::', {}).get('selfservice', False):
            user = param['::scope::']['user']
            if not is_email_editable(user):
                u_info = getUserDetail(user)
                u_email = u_info.get('email', None)
                if u_email.strip() != self._email_address.strip():
                    raise Exception(_('User is not allowed to set '
                                      'email address'))

        ## in case of the e-mail token, only the server must know the otpkey
        ## thus if none is provided, we let create one (in the TokenClass)
        if not 'genkey' in param and not 'otpkey' in param:
            param['genkey'] = 1

        HmacTokenClass.update(self, param, reset_failcount)

        LOG.debug("[update] end. all token parameters are set.")
        return

    def _getNextOtp(self):
        """
        access the nex valid otp

        :return: otpval
        :rtype: string
        """
        LOG.debug("[getNextOtp] begin. starting to look for the next otp")

        try:
            otplen = int(self.token.LinOtpOtpLen)
        except ValueError as ex:
            LOG.error("[getNextOtp] ValueError %r" % ex)
            raise Exception(ex)

        secObj = self._get_secret_object()
        counter = self.token.getOtpCounter()

        hmac2otp = HmacOtp(secObj, counter, otplen)
        nextotp = hmac2otp.generate(counter + 1)

        LOG.debug("[getNextOtp] end. got the next otp value: nextOtp %r"
                  % nextotp)
        return nextotp

    def initChallenge(self, transactionid, challenges=None, options=None):
        """
        initialize the challenge -
        This method checks if the creation of a new challenge (identified by
        transactionid) should proceed or if an old challenge should be used
        instead.

        :param transactionid: the id of the new challenge
        :param options: the request parameters

        :return: tuple of
                success - bool
                transactionid_to_use - the best transaction id for this
                                       request context
                message - which is shown to the user
                attributes - further info (dict) shown to the user
        """
        success = True
        transactionid_to_use = transactionid
        message = 'challenge init ok'
        attributes = {}

        now = datetime.datetime.now()
        blocking_time = int(getFromConfig('EmailBlockingTimeout',
                                          self.DEFAULT_EMAIL_BLOCKING_TIMEOUT))

        for challenge in challenges:
            challenge_timestamp = challenge.get('timestamp')
            block_timeout = challenge_timestamp + \
                             datetime.timedelta(seconds=blocking_time)
            # check if there is a challenge that is blocking
            # the creation of new challenges
            if now <= block_timeout:
                transactionid_to_use = challenge.getTransactionId()
                message = 'e-mail with otp already submitted'
                success = False
                attributes = {'info': 'challenge already submitted',
                              'state': transactionid_to_use}
                break

        return success, transactionid_to_use, message, attributes

    def createChallenge(self, transactionid, options=None):
        """
        create a challenge, which is submitted to the user

        :param transactionid: the id of this challenge
        :param options: the request context parameters / data
        :return: tuple of (bool, message, data and attributes)
                 bool, if submit was successful
                 message is status-info submitted to the user
                 data is preserved in the challenge
                 attributes - additional attributes, which are displayed in the
                    output
        :rtype: bool, string, dict, dict
        """
        attributes = {}
        counter = self.getOtpCount()
        data = {'counter_value': "%s" % counter}

        try:
            success, status_message = self._sendEmail()
            if success:
                attributes = {'state': transactionid}
        finally:
            self.incOtpCounter(counter, reset=False)

        return success, status_message, data, attributes

    def _getEmailMessage(self, user=""):
        """
        Could be used to implement some more complex logic similar to the
        SMS token where the SMS text is read from a policy.

        :return: The message that is sent to the user. It should contain
            at least the placeholder <otp>
        :rtype: string
        """
        message = '<otp>'

        if not user:
            return message

        realm = user.realm
        login = user.login

        policies = get_client_policy(context['Client'], scope="authentication",
                                     realm=realm, user=login,
                                     action="emailtext")

        if policies:
            message = getPolicyActionValue(policies, "emailtext", is_string=True)

        return message

    def _getEmailSubject(self, user=""):
        """
        Could be used to implement some more complex logic similar to the
        SMS token where the SMS text is read from a policy.

        :return: The message that is sent to the user. It should contain
            at least the placeholder <otp>
        :rtype: string
        """
        subject = ''

        if not user:
            return subject

        realm = user.realm
        login = user.login

        policies = get_client_policy(context['Client'], scope="authentication",
                                     realm=realm, user=login,
                                     action="emailsubject")

        if policies:
            subject = getPolicyActionValue(policies, "emailsubject",
                                           is_string=True)

        return subject

    def _sendEmail(self):
        """
        Prepares the e-mail by gathering all relevant information and
        then sends it out.

        :return: A tuple of success and status_message
        :rtype: bool, string
        """
        otp = self._getNextOtp()
        email_address = self._email_address
        if not email_address:
            raise Exception("No e-mail address was defined for this token.")

        owner = get_token_owner(self)
        message = self._getEmailMessage(user=owner)

        if "<otp>" not in message:
            message = message + "<otp>"

        message = message.replace("<otp>", otp)
        message = message.replace("<serial>", self.getSerial())

        subject = self._getEmailSubject(user=owner)
        subject = subject.replace("<otp>", otp)
        subject = subject.replace("<serial>", self.getSerial())

        email_provider = loadProviderFromPolicy(provider_type='email',
                                                user=owner)
        status, status_message = email_provider.submitMessage(email_address,
                                                              subject=subject,
                                                              message=message)
        return status, status_message

    def is_challenge_response(self, passw, user, options=None, challenges=None):
        """
        Checks if the request is a challenge response.

        With the e-mail token every request has to be either a challenge
        request or a challenge response.

        Normally the client is unable to generate OTP values for this token
        himself (because the seed is generated on the server and not published)
        and has to wait to get it by e-mail. Therefore he either makes a
        challenge-request (triggering the e-mail) or he makes a challenge-
        response (sending the OTP value he received).

        :return: Is this a challenge response?
        :rtype: bool
        """
        challenge_response = False
        if options and ("state" in options or "transactionid" in options):
            challenge_response = True
        elif not self.is_challenge_request(passw, user, options):
            # If it is not a request then it is a response
            challenge_response = True

        return challenge_response

    def checkResponse4Challenge(self, user, passw, options=None,
                                challenges=None):
        """
        verify the response of a previous challenge

        There are two possible cases:

        1) The 'transaction_id' (also know as 'state', which has the same
           value) is available in options
        2) No 'transaction_id'

        In the first case we can safely assume that the passw only contains
        the OTP (no pin). In the second case passw will contain both and we
        split to get the OTP.

        :param user:     the requesting user
        :param passw:    the to be checked pass (pin+otp)
        :param options:  options an additional argument, which could be token
                          specific
        :param challenges: the list of challenges, where each challenge is
                            described as dict
        :return: tuple of (otpcounter and the list of matching challenges)

        """
        transaction_id = None
        otp_counter = -1
        matching_challenges = []

        if challenges is None or len(challenges) == 0:
            # There are no challenges for this token
            return -1, []

        if options and ('transactionid' in options or 'state' in options):
            # fetch the transactionid
            transaction_id = options.get('transactionid', None)
            if transaction_id is None:
                transaction_id = options.get('state', None)

        if transaction_id:
            otp = passw
            # if the transaction_id is set we can assume that we have only
            # received a single challenge with that transaction_id thanks to
            # linotp.lib.validate.ValidateToken.get_challenges()
            assert(len(challenges) == 1)
            assert(Challenges.is_same_transaction(challenges[0], transaction_id))
        else:
            # If no transaction_id is set the request came through the WebUI
            # and we have to check all challenges
            split_status, pin, otp = split_pin_otp(self, passw, user, options)
            if split_status < 0:
                raise Exception("Could not split passw")
            if not check_pin(self, pin, user, options):
                return -1, []

        window = self.getOtpCountWindow()

        for challenge in challenges:
            challenge_data = challenge.getData()
            stored_counter = challenge_data.get("counter_value")
            temp_otp_counter = self.checkOtp(otp, int(stored_counter),
                                             window, options)
            if temp_otp_counter > 0:
                otp_counter = temp_otp_counter
                matching_challenges = [challenge]
                break

        # The matching_challenges list will either contain a single challenge
        # or will be empty. Returning multiple challenges is not useful in this
        # case because all older challenges arecleaned up anyway.
        return otp_counter, matching_challenges

    def authenticate(self, passw, user, options=None):
        """
        The e-mail token only supports challenge response mode therefore when
        a 'normal' authenticate' request arrives we return false.

        :return: pin_match, otp_counter, reply
        :rtype: bool, int, string
        """
        pin_match = False
        otp_counter = -1
        reply = None
        return pin_match, otp_counter, reply

    def getInitDetail(self, params, user=None):
        '''
        to complete the token normalisation, the response of the initialiastion
        should be build by the token specific method, the getInitDetails
        '''
        response_detail = {}

        info = self.getInfo()
        response_detail['serial'] = self.getSerial()

        return response_detail

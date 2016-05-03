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
    YubiKey token in HMAC Challenge Response Mode
"""

import logging
import os
import hmac

import binascii
from hashlib import sha1
from hashlib import sha512

from linotp.lib.validate import check_pin
from linotp.lib.token import getTokenRealms
from linotp.lib.token import getTokenOwner
from linotp.lib.tokenclass import TokenClass

from linotp.lib.policy import getPolicy
from linotp.lib.policy import getPolicyActionValue

log = logging.getLogger(__name__)


##################################################################
def is_autobinding(user="", realms=None):
    '''
    this function checks the policy scope=authentication,
                action=yk_challeng_response::autobinding (bool)

    The function returns bool - if a policy is defined, default is False
    '''
    ret = False
    login = None

    if not realms:
        realms = []

    if user and user.login and user.realm:
        realms = [user.realm]
        login = user.login

    params = {
        'scope': 'authentication',
        'action': 'yk_challenge_response::autobinding',
        }

    if not realms:
        realms = ['*']

    for realm in realms:
        params['realm'] = realm
        if login:
            params['user'] = login
        policies = getPolicy(params)

        if policies:
            autobinding = getPolicyActionValue(policies,
                                               "yk_challenge_response::autobinding")
            if autobinding is True:
                ret = True
                break

    return ret


class YubikeyChallengeTokenClass(TokenClass):
    """
    The YubiKey Token in the Yubico Challenge mode
    """

    def __init__(self, aToken):
        TokenClass.__init__(self, aToken)
        self.setType(u"yk_challenge_response")

        self.hKeyRequired = True
        self.mode = ['challenge']
        return

    @staticmethod
    def admin_methods():
        return ['get_challenge_reply']

    @classmethod
    def getClassType(cls):
        return "yk_challenge_response"

    @classmethod
    def getClassPrefix(cls):
        return "UBCH"

    @classmethod
    def getClassInfo(cls, key=None, ret='all'):
        """
        getClassInfo - returns a subtree of the token definition

        :param key: subsection identifier
        :param ret: default return value, if nothing is found
        :return: subsection if key exists or user defined
        """

        log.debug("[getClassInfo] begin. Get class render info for section:"
                  " key %r, ret %r ", key, ret)

        res = {
            'type':          'yk_challenge_response',
            'title':         'YubiKey in HMAC Challenge Mode',
            'description':   ('Yubico token to run the HMAC Challenge Mode.'),
            'init':          {},
            'config':        {},
            'selfservice':   {},
            'policy':        {
                'authentication': {
                    'yk_challenge_response::autobinding': {
                        'type': 'bool',
                        'desc': 'setup of a binding identity during the '
                                'first authentication request'
                    }
                }
            },
        }

        if key is not None and key in res:
            ret = res.get(key)
        else:
            if ret == 'all':
                ret = res
        log.debug("Returned the configuration section: ret %r ", ret)
        return ret

    def update(self, param, reset_failcount=True):
        '''
        update - process the initialization parameters

        :param param: dict of initialization parameters
        :return: nothing
        '''

        if 'otplen' not in param:
            param['otplen'] = 40  # sha1 result in binascii format

        TokenClass.update(self, param, reset_failcount)

        if 'id' in param:
            p_id = binascii.hexlify(param.get('id'))
            self.addToTokenInfo('pairing_id', p_id)

        return

    def is_challenge_request(self, passw, user, options=None):
        """
        check if this is a challenge request

        - treat as well the pairing case:
          * in case the token is not paired the pairing parameter 'id'
            is required to do the pairing
          *

        :param passw: the password
        :param user: the request user
        :param options: the additonal request options
        :return: success - boolean
        """

        # if its a challenge, the passw contains only the pin
        pin_match = check_pin(self, passw, user=user, options=options)
        if not pin_match:
            return False

        # get the realms for the policy lookup
        owner = getTokenOwner(self.getSerial())
        if owner and owner.login and owner.realm:
            realms = [owner.realm]
        else:
            realms = getTokenRealms(self.getSerial())

        # if we don't run in autobinding mode, we dont deal with the pairing id
        if not is_autobinding(user, realms):
            return True

        info = self.getTokenInfo()
        if "pairing_id" not in info:
            if 'id' in options:
                p_id = binascii.hexlify(options.get('id'))
                self.addToTokenInfo('pairing_id', p_id)
                ret = True
            else:  # not paired
                ret = False

        else:  # "pairing_id" in info:
            if 'id' in options:  # if id in info and id in request: deny
                ret = False
            else:  # paired and challenge request
                ret = True

        return ret

    def createChallenge(self, transactionid, options=None):
        """
        preserve the challenge data and return the challenge response

        :param transactionid: the reference to the transaction
        :param options: the dict with the additional request params
        :return: tuple of
                 result - success - boolean
                 message - to return to the response
                 data - to be stored data
                 attributes - the additional parameters to preserve
        """

        res = True
        attributes = {}
        data = 'challenge created'

        # just create a random output
        message = binascii.hexlify(os.urandom(20))

        return (res, message, data, attributes)

    def is_challenge_response(self, passw, user, options=None,
                              challenges=None):
        """
        check if the request is a response to a challenge

        :param passw: the password
        :param user: the requesting user
        :param options: the dict with the optional parameters
        :param challenges: the list of the token related challenges
        :return: boolean
        """

        res = False
        if 'transactionid' in options or 'state' in options:
            res = True
        return res

    def checkResponse4Challenge(self, user, passw, options=None,
                                challenges=None):
        """
        check the response for the challenge

        :param user: the user as parameter
        :param passw: the user password
        :param options: the additional parameters with the transactionis
        :param challenges: the list of token related challenges
        :return: tuple of otpcount, and array with matching challenges
        """

        transid = options.get('transactionid', options.get('state'))
        if not transid:
            return False

        matching_challenge = None
        for challenge in challenges:
            if (challenge.tokenserial == self.getSerial() and
               challenge.transid == transid):
                matching_challenge = challenge
                break

        if not matching_challenge:
            return False

        challenge = matching_challenge.challenge

        # get the realms for the policy lookup
        owner = getTokenOwner(self.getSerial())
        if owner and owner.login and owner.realm:
            realms = [owner.realm]
        else:
            realms = getTokenRealms(self.getSerial())

        b_challenge = binascii.unhexlify(challenge)
        if not is_autobinding(user, realms):
            ch_passw = self._hash_digest(b_challenge, sha1)
        else:
            ch_passw = self._create_response_from_challenge(b_challenge)

        h_ch_passw = binascii.hexlify(ch_passw)
        if passw.lower() == h_ch_passw.lower():
            return 1, [matching_challenge]

        return -1, []

    def _create_response_from_challenge(self, challenge):
        """
        helper to calculate the triple hash, which is done as
        well on the client side

            H5(H1(H5(C+id))+id):

            1.h1 = hmac(C, id, sha512)
            2.h2 = hmac(seed, h1, sha1)
            3 h3 = hmac(h2, id, sha512)

        :params challenge: the input challenge
        :return: triple hash result (as binary)
        """

        info = self.getTokenInfo()
        if "pairing_id" not in info:
            return None

        p_id = binascii.unhexlify(info["pairing_id"]).encode('utf-8')

        h1 = hmac.new(challenge, p_id, sha512).digest()
        h2 = self._hash_digest(h1, sha1)
        h3 = hmac.new(h2, p_id, sha512).digest()

        return h3

    def _hash_digest(self, challenge, sha_func):
        """
        helper to get the hmac digest of the challenge

        :param challenge: the input challenge as string
        :param sha_func: the hashing function sha1 or sha512
        :return: the hmac digest (as binary)
        """

        secretObj = self.token.getHOtpKey()
        digest = secretObj.hmac_digest(challenge, sha_func)

        return digest

    @staticmethod
    def get_challenge_reply(params, filter_realms=[]):
        """
        dedicated admin call entry:

          create the token list with challenges and the corresponding replies

        :param params: the request parameters from the token_
        :param filter_realms: the allowed realms
        :return: dict with response values
        """

        resp = {}
        prefix = YubikeyChallengeTokenClass.getClassPrefix()
        token_type = YubikeyChallengeTokenClass.getClassType()

        serial = params.get('serial', '*')
        challenge = params.get('challenge')
        yk_challenge = challenge

        from linotp.lib.token import getTokens4UserOrSerial

        tokens = getTokens4UserOrSerial(serial=serial, token_type=token_type)
        if not tokens and not serial.startswith(prefix):
            serial = prefix + serial

            if '*' not in serial and serial[-2:] not in ['_1', '_2']:
                serial = serial + '_*'

            tokens = getTokens4UserOrSerial(serial=serial,
                                            token_type=token_type)

        if not tokens:
            raise Exception('Token with serial %r not found' % serial)

        for yk_token in tokens:
            # we have to filter the realms, where the admin has access to
            if filter_realms:
                found = False
                t_realms = yk_token.token.getRealmNames()
                for filter_realm in filter_realms:
                    if filter_realm == "*":
                        found = True
                        break
                    if filter_realm.lower() in t_realms:
                        found = True
                        break
                if not found:
                    continue

            # prepare the yk serial and slot information
            serial = yk_token.getSerial()
            if serial.startswith(prefix):
                yk_serial = serial[len(prefix):]
            if serial[-2:] in ['_1', '_2']:
                slot = int(serial[-1:])
                yk_serial = yk_serial[:-2]

            # get the challenge reply
            digest = yk_token._hmac_digest(challenge, sha1)

            # handle empty / not given challenge parameter
            if not challenge:
                yk_challenge = binascii.hexlify(os.urandom(10))

            resp[serial] = {'challenge': yk_challenge,
                            'response': binascii.hexlify(digest),
                            'slot': slot,
                            'serial': yk_serial
                            }

        return resp

# eof ########################################################################

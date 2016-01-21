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

import json
import base64
import struct
import binascii
import re
from M2Crypto import X509, m2
from hashlib import sha256
from string import rfind
from linotp.lib.tokenclass import TokenClass
from linotp.lib.validate import check_pin
from linotp.lib.validate import check_otp, is_same_transaction
from linotp.lib.validate import get_challenges
from linotp.lib.util import getParam
from linotp.lib.policy import getPolicy, getPolicyActionValue
from linotp.lib.error import TokenTypeNotSupportedError

"""
    This file contains the U2F V2 token implementation as specified by the FIDO Alliance
"""

optional = True
required = False

import logging
log = logging.getLogger(__name__)

# Elliptic Curves support is not available on all platforms
try:
    from M2Crypto import EC
except (ImportError, AttributeError) as exx:
    log.debug("Could not import EC from M2Crypto: %r", exx)
    raise TokenTypeNotSupportedError("Missing EC support in M2Crypto (openssl). FIDO U2F token " \
                                     "can't be used.")

class U2FTokenClass(TokenClass):

    """
    U2F token class implementation

    The U2F protocol as specified by the FIDO Alliance uses public key cryptography
    to perform second factor authentications. On registration the U2F compatible token
    creates a public/private key pair and sends the public key to the relying party
    (i.e. this LinOTP class). On authentication the U2F compatible token uses the
    private key to sign a challenge received from the relying party. This signature
    can be checked by the relying party using the public key received during
    registration.
    """

    def __init__(self, aToken):
        """
        constructor - create a token object

        :param aToken: instance of the orm db object
        :type aToken:  orm object

        """
        log.debug("Create a token object with: aToken %r", (aToken))

        TokenClass.__init__(self, aToken)
        self.setType(u"u2f")
        self.mode = ['challenge']  # This is a challenge response token

        log.debug("Token object created")

    @classmethod
    def getClassType(cls):
        """
        getClassType - return the token type shortname

        :return: 'U2F'
        :rtype: string

        """
        return "u2f"

    @classmethod
    def getClassPrefix(cls):
        return "u2f"

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
        log.debug("Get class render info for section: key %r, ret %r ", key, ret)

        res = {
            'type': 'u2f',
            'title': 'U2F FIDO Token',
            'description': ('A U2F V2 token as specified by the FIDO Alliance. \
                Can be combined with the OTP PIN.'),
            'init': {},
            'config': {},
            'selfservice': {'enroll':
                            {'title':
                             {'html': 'u2ftoken.mako',
                              'scope': 'selfservice.title.enroll',
                              },
                             'page':
                                {'html': 'u2ftoken.mako',
                                 'scope': 'selfservice.enroll',
                                 },
                             }
                            },
            'policy': {
                'enrollment':
                {'u2f_valid_facets': {'type': 'str'},
                 'u2f_app_id': {'type': 'str'}}
                }
        }

        if key is not None and key in res:
            ret = res.get(key)
        else:
            if ret == 'all':
                ret = res
        log.debug("Returned the configuration section: ret %r ", (ret))
        return ret

    def update(self, param, reset_failcount=False):
        self.setSyncWindow(0)
        self.setOtpLen(32)
        self.setCounterWindow(0)

        tdesc = getParam(param, "description", optional)
        if tdesc is not None:
            self.token.setDescription(tdesc)

        # requested_phase must be either "registration1" or "registration2"
        # current_phase is either "registration" or "authentication"
        requested_phase = getParam(param, "phase", optional)
        current_phase = self.getFromTokenInfo('phase', None)

        if requested_phase == "registration1" and current_phase is None:
            # This initial registration phase triggers a challenge
            # which is sent to the FIDO U2F compatible client device

            # Set the optional token pin in this first phase
            pin = getParam(param, "pin", optional)
            if pin is not None:
                TokenClass.setPin(self, pin)

            # preserve the registration state
            self.addToTokenInfo('phase', 'registration')
            self.token.LinOtpIsactive = False
        elif requested_phase == "registration2" and current_phase == "registration":
            # Check the token pin
            pin = getParam(param, "pin", optional)
            if pin is None:
                pin = ''
            if check_pin(self, pin) is False:
                log.error("Wrong token pin!")
                raise ValueError("Wrong token pin!")
        # check for set phases which are not "registration1" or "registration2"
        elif requested_phase != "registration2" and requested_phase is not None:
            log.error('Wrong phase parameter!')
            raise Exception('Wrong phase parameter!')
        # only allow empty phase parameters once the token is registered successfully
        elif current_phase != "authentication" and requested_phase is None:
            log.error('Wrong phase parameter!')
            raise Exception('Wrong phase parameter!')
        # only allow "registration2" if the token already completed "registration1"
        elif current_phase != "registration" and requested_phase == "registration2":
            log.error(
                "Phase 'registration2' requested but we are not in the correct phase \
                to process the request.")
            raise Exception(
                "Phase 'registration2' requested but we are not in the correct phase \
                to process the request.")
        else:
            log.error('Unknown "phase" and "current_phase" parameter combination!')
            raise Exception('Unknown "phase" and "current_phase" parameter combination!')

    def splitPinPass(self, passw):
        """
        Split pin and otp given in the passw parameter

        :param passw: string representing pin+otp
        :return: returns tuple true or false for res, the pin value for pin
            and the otp value for otpval
        """
        # Split OTP from pin
        # Since we know that the OTP has to be valid JSON  with format {"a":"b", "b":"c", ...}
        # we can parse the OTP for '{' beginning at the end of the OTP string
        splitIndex = rfind(passw, "{")
        if splitIndex != -1:
            pin = passw[:splitIndex]
            otpval = passw[splitIndex:]
        else:
            # no valid JSON format - assume we got no otpval
            pin = passw
            otpval = ""

        return pin, otpval

    def is_challenge_request(self, passw, user, options=None):
        """
        check if the request would start a challenge

        - default: if the passw contains only the pin, this request would
        trigger a challenge

        - in this place as well the policy for a token is checked

        :param passw: password, which might be pin or pin+otp
        :param options: dictionary of additional request parameters

        :return: returns true or false
        """
        return check_pin(self, passw, user=user, options=options)

    def createChallenge(self, transactionid, options=None):
        """
        create a challenge, which is submitted to the user

        :param state: the state/transaction id
        :param options: the request context parameters / data
        :return: tuple of (bool, message and data)
                 message is submitted to the user
                 data is preserved in the challenge
                 attributes are additional attributes, which could be returned
        """
        # Create an otp key (from urandom) which is used as challenge, 32 bytes long
        challenge = base64.urlsafe_b64encode(binascii.unhexlify(self._genOtpKey_(32)))

        # We delete all '=' symbols we added during registration to ensure that the
        # challenge object is sent to exact the same keyHandle we received in the
        # registration. Otherwise some U2F tokens won't respond.
        keyHandle = self.getFromTokenInfo('keyHandle')
        keyHandleIndex = 1
        while keyHandle[-keyHandleIndex] == '=':
            keyHandleIndex = keyHandleIndex + 1
        if keyHandleIndex > 1:
            keyHandle = keyHandle[:-(keyHandleIndex - 1)]

        appId = self._get_app_id()

        data = {
            'challenge': "%s" % challenge,
            'version': 'U2F_V2',
            'keyHandle': keyHandle,
            'appId': appId
        }
        message = "U2F challenge"
        attributes = dict()
        attributes['signrequest'] = data

        return (True, message, data, attributes)

    @staticmethod
    def _is_supported_openssl_version():
        """
        check if the openssl version is supported by the U2FTokenClass

        :return:          boolean - True if supported, False if unsupported
        """
        # U2F needs OpenSSL 1.0.0 or higher
        # The EC OpenSSL API calls made by M2Crypto don't work with OpenSSl 0.9.8!
        version_text = m2.OPENSSL_VERSION_TEXT
        log.debug("OpenSSL version string: '%s'", version_text)

        match = re.match(r"OpenSSL (?P<version>\d\.\d\.\d)", version_text)
        if match is None:
            log.warning("Could not detect OpenSSL version - unknown version string format: '%s'",
                        version_text
                        )
        else:
            if match.group('version')[0] == '0':
                return False
        return True

    def _is_valid_facet(self, origin):
        """
        check if origin is in the valid facets if the u2f_valid_facets policy is set.
        Otherwise check if the origin matches the previously saved origin

        :return:          boolean - True if supported, False if unsupported
        """
        is_valid = False

        # Get the valid facets as specified in the enrollment policy 'u2f_valid_facets'
        # for the specific realm
        valid_facets_action_value = ''
        realms = self.token.getRealmNames()
        if len(realms) > 0:
            get_policy_params = {
                'action': 'u2f_valid_facets',
                'scope': 'enrollment',
                'realm': realms[0]
                }
            valid_facets_action_value = getPolicyActionValue(getPolicy(get_policy_params),
                                                             'u2f_valid_facets',
                                                             is_string=True
                                                             )

        if valid_facets_action_value != '':
            # 'u2f_valid_facets' policy is set - check if origin is in valid facets list
            valid_facets = valid_facets_action_value.split(';')
            for facet in valid_facets:
                facet = facet.strip()
            if origin in valid_facets:
                is_valid = True
        else:
            # 'u2f_valid_facets' policy is empty or not set
            # check if origin matches the origin stored in the token info or save it if no origin
            # is stored yet
            appId = self._get_app_id()
            if appId == origin:
                is_valid = True

        return is_valid

    def _get_app_id(self):
        """
        Get the appId saved in the TokenInfo.
        :return: appId
        """
        # Get the appId from TokenInfo
        appId = self.getFromTokenInfo('appId', '')
        if appId == '':
            log.error("appId could not be determined.")
            raise Exception("appId could not be determined.")

        return appId

    @staticmethod
    def _handle_client_errors(client_response):
        """
        Check the U2F client response for U2F client errors.
        Raises an Exception if an U2F client error code was found.
        :param client_response: U2F client response object
        :return:
        """
        error_codes = {0: 'OK',
                       1: 'OTHER_ERROR',
                       2: 'BAD_REQUEST',
                       3: 'CONFIGURATION_UNSUPPORTED',
                       4: 'DEVICE_INELIGIBLE',
                       5: 'TIMEOUT'}

        if "errorCode" in client_response:
            error_code = client_response['errorCode']
            error_text = error_codes.get(error_code, '')
            error_msg = client_response.get('errorMessage', '')
            log.info("U2F client error code received: %s (%d): %s", error_text,
                     error_code, error_msg)
            raise Exception("U2F client error code: %s (%d): %s" % (error_text,
                                                                    error_code,
                                                                    error_msg))

    def _checkClientData(self,
                         clientData,
                         clientDataType,
                         challenge
                         ):
        """
        checkClientData - checks whether the clientData object retrieved
        from the U2F token is valid

        :param clientData:        the stringified JSON clientData object
        :param clientDataType:    either 'registration' or 'authentication'
        :param challenge:         the challenge this clientData object belongs to
        :return:                  the origin as extracted from the clientData object
        """
        try:
            clientData = json.loads(clientData)
        except ValueError as ex:
            log.exception("Invalid client data JSON format - value error %r", (ex))
            raise Exception("Invalid client data JSON format")

        try:
            cdType = clientData['typ']
            cdChallenge = clientData['challenge']
            cdOrigin = clientData['origin']
            # TODO: Check for optional cid_pubkey
        except KeyError as err:
            log.exception("Wrong client data format %s: ", err)
            raise Exception('Wrong client data format!')

        # validate typ
        if clientDataType is 'registration':
            if cdType != 'navigator.id.finishEnrollment':
                log.error('Incorrect "typ" field in the client data object')
                raise Exception('Incorrect client data object received!')
        elif clientDataType is 'authentication':
            if cdType != 'navigator.id.getAssertion':
                log.error('Incorrect "typ" field in the client data object')
                raise Exception('Incorrect client data object received!')
        else:
            # Wrong function call
            log.error('Wrong validClientData function call - clientDataType must be either \
                       "registration" or "authentication".')
            raise Exception('Wrong validClientData function call.')

        # validate challenge
        if cdChallenge != challenge:
            log.debug('Challenge mismatch - The received challenge in the received client \
                       data object does not match the sent challenge!')
            return False

        # validate origin
        if not self._is_valid_facet(cdOrigin):
            log.debug('Facet "%s" is not in valid_facets.', cdOrigin)
            return False

        return True

    def _parseSignatureData(self, signatureData):
        """
        Internal helper function to parse the signatureData received on authentication
        according to the U2F specification

        :param signatureData: Raw signature data as sent from the U2F token
        :return:              Tuple of (userPresenceByte, counter, signature)
        """

        FIRST_BIT_MASK = 0b00000001
        COUNTER_LEN = 4

        # first bit has to be 1 in the current FIDO U2F_V2 specification
        # since authentication responses without requiring user presence
        # are not yet supported by the U2F specification
        if FIRST_BIT_MASK & ord(signatureData[:1]) != 0b00000001:
            log.error("Wrong signature data format: User presence bit must be set")
            raise ValueError("Wrong signature data format")
        userPresenceByte = signatureData[:1]
        signatureData = signatureData[1:]

        # next 4 bytes refer to the counter
        if len(signatureData) < COUNTER_LEN:
            log.error("Wrong signature data format: signature data too short")
            raise ValueError("Wrong signature data format")
        counter = signatureData[:COUNTER_LEN]
        signatureData = signatureData[COUNTER_LEN:]

        # the remaining part of the signatureData is the signature itself
        # We do not allow an empty string as a signature
        if len(signatureData) == 0:
            log.error("Wrong signature data format: signature data too short")
            raise ValueError("Wrong signature data format")
        signature = signatureData

        return (userPresenceByte, counter, signature)

    @staticmethod
    def _checkCounterOverflow(counter,
                              prevCounter
                              ):
        """
        Internal helper function to check the counter in the range of an overflow

        :param counter:       the received counter value
        :param prevCounter:   the previously saved counter value
        :return:              boolean, True on legal overflow, False on illegal counter decrease
        """
        # TODO: Create Policy to adjust the OVERFLOW_RANGE
        OVERFLOW_RANGE = 1000
        res = False
        if prevCounter >= (256 ** 4) - OVERFLOW_RANGE and counter <= OVERFLOW_RANGE:
            # This is the range of a legal overflow
            res = True
        return res

    def _verifyCounterValue(self, counter):
        """
        Internal helper function to verify the counter value received on an authentication response.
        This counter value MUST increase on every authentication event (except for an overflow to 0)
        as outlined in the FIDO U2F specification.
        However, this counter is allowed to be 'global' on the token device, i.e. one counter for
        ALL applications used with this token. Therefore we cannot check for a wrap around to
        exactly 0.
        Since we know that the maximum counter value is exactly 256 ** 4 (4 bytes counter), we can
        implement a range where a wrap around of the counter value is allowed.

        :param counter: the received counter value
        :return:
        """
        prevCounter = int(self.getFromTokenInfo('counter', None))

        # Did the counter not increase?
        if not counter > prevCounter:
            # Is this a legal overflow?
            if self._checkCounterOverflow(counter, prevCounter) is False:
                # Since a decreasing counter value is a hint to a device cloning, we
                # deactivate the token. This could also happen if you use the token
                # A LOT with other applications and very seldom with LinOTP.
                self.token.LinOtpIsactive = False
                log.error("Counter not increased! Possible device cloning!")
                raise ValueError("Counter not increased! Possible device cloning!")

        # save the new counter
        self.addToTokenInfo('counter', counter)

    def _validateAuthenticationSignature(self,
                                         applicationParameter,
                                         userPresenceByte,
                                         counter,
                                         challengeParameter,
                                         publicKey,
                                         signature
                                         ):
        """
        Internal helper function to validate the authentication signature received after parsing
        the token authentication response according to the U2F specification

        :param applicationParameter: SHA-256 hash of the application identity.
        :param userPresenceByte:     The user presence byte as received in the authentication
                                     response
        :param challengeParameter:   SHA-256 hash of the Client Data, a stringified JSON data
                                     structure prepared by the FIDO Client.
        :param publicKey:            The user public key retrieved on parsing the registration data
        :param signature:            The signature to be verified as retrieved on parsing the
                                     authentication response
        """
        # add ASN1 prefix
        PUB_KEY_ASN1_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200".decode('hex')
        publicKey = PUB_KEY_ASN1_PREFIX + publicKey

        # Check for OpenSSL version 1.0.0 or higher
        if not self._is_supported_openssl_version():
            log.error("This version of OpenSSL is not supported! OpenSSL version 1.0.0 or higher "
                      "is required for the U2F token.")
            raise Exception("This version of OpenSSL is not supported! OpenSSL version 1.0.0 or "
                            "higher is required for the U2F token.")

        try:
            # The following command needs support for ECDSA in OpenSSL!
            # Since Red Hat systems (including Fedora) use an OpenSSL version without
            # support for the NIST P-256 curve (as of March 2015), this command will fail
            # with a NULL pointer exception on these systems
            ECPubKey = EC.pub_key_from_der(publicKey)
        except ValueError as ex:
            log.exception(
                "Could not get ECPubKey. Possibly missing ECDSA support for the NIST P-256 "
                "curve in OpenSSL? %r", ex)
            raise Exception(
                "Could not get ECPubKey. Possibly missing ECDSA support for the NIST P-256 "
                "curve in OpenSSL? %r" % ex)

        # According to the FIDO U2F specification the signature is a ECDSA signature on the
        # NIST P-256 curve over the SHA256 hash of the following byte string
        toBeVerified = sha256(
            applicationParameter + userPresenceByte + counter + challengeParameter).digest()
        if ECPubKey.verify_dsa_asn1(toBeVerified, signature) != 1:
            log.debug("Signature verification failed!")
            return False
        return True

    def checkResponse4Challenge(self, user, passw, options=None, challenges=None):
        """
        This method verifies if the given ``passw`` matches any existing ``challenge``
        of the token.

        It then returns the new otp_counter of the token and the
        list of the matching challenges.

        In case of success the otp_counter needs to be > 0.
        The matching_challenges is passed to the method
        :py:meth:`~linotp.lib.tokenclass.TokenClass.challenge_janitor`
        to clean up challenges.

        :param user: the requesting user
        :type user: User object
        :param passw: the password (pin+otp)
        :type passw: string
        :param options:  additional arguments from the request, which could be token specific
        :type options: dict
        :param challenges: A sorted list of valid challenges for this token.
        :type challenges: list
        :return: tuple of (otpcounter and the list of matching challenges)
        """
        otp_counter = -1
        transid = None
        matching = None
        matching_challenges = []

        # fetch the transactionid
        if 'transactionid' in options:
            transid = options.get('transactionid', None)

        # check if the transactionid is in the list of challenges
        if transid is not None:
            for challenge in challenges:
                if is_same_transaction(challenge, transid):
                    matching = challenge
                    break
            if matching is not None:
                # Split pin from otp and check the resulting pin and otpval
                (pin, otpval) = self.splitPinPass(passw)
                if not check_pin(self, pin, user=user, options=options):
                    otpval = passw
                # The U2F checkOtp functions needs to know the saved challenge
                # to compare the received challenge value to the saved one,
                # thus we add the transactionid to the options
                options['transactionid'] = transid
                options['challenges'] = challenges
                otp_counter = check_otp(self, otpval, options=options)
                if otp_counter >= 0:
                    matching_challenges.append(matching)

        return (otp_counter, matching_challenges)

    def checkOtp(self,
                 passw,
                 counter,
                 window,
                 options=None
                 ):
        """
        checkOtp - standard callback of linotp to verify the token

        :param passw:      the passw / otp, which has to be checked
        :type passw:       string
        :param counter:    the start counter
        :type counter:     int
        :param  window:    the window, in which the token is valid
        :type  window:     int
        :param options:    options
        :type options:     dict

        :return:           verification counter or -1
        :rtype:            int (-1)
        """
        log.debug('%r: %r: %r', passw, counter, window)
        ret = -1

        challenges = []
        serial = self.getSerial()
        transid = options.get('transactionid', None)
        if transid is None:
            log.error("Could not checkOtp due to missing transaction id")
            raise Exception("Could not checkOtp due to missing transaction id")

        # get all challenges with a matching trasactionid
        if 'challenges' in options:
            challs = options['challenges']
        else:
            challs = []
            log.debug('Could not find a challenge')

        for chall in challs:
            (rec_tan, rec_valid) = chall.getTanStatus()
            if rec_tan is False:
                # add all untouched challenges
                challenges.append(chall)
            elif rec_valid is False:
                # don't allow touched but failed challenges
                pass

        if len(challenges) == 0:
            err = 'No open transaction found for token %s and transactionid %s' % (serial, transid)
            log.error(err)
            raise Exception(err)

        # decode the retrieved passw object
        try:
            authResponse = json.loads(passw)
        except ValueError as ex:
            log.exception("Invalid JSON format - value error %r", (ex))
            raise Exception("Invalid JSON format")

        self._handle_client_errors(authResponse)

        try:
            signatureData = authResponse.get('signatureData', None)
            clientData = authResponse['clientData']
            keyHandle = authResponse['keyHandle']
        except AttributeError as ex:
            log.exception("Couldn't find keyword in JSON object - attribute error %r ", (ex))
            raise Exception("Couldn't find keyword in JSON object")

        # Does the keyHandle match the saved keyHandle created on registration?
        # Remove trailing '=' on the saved keyHandle
        savedKeyHandle = self.getFromTokenInfo('keyHandle', None)
        while savedKeyHandle.endswith('='):
            savedKeyHandle = savedKeyHandle[:-1]
        if keyHandle is None or keyHandle != savedKeyHandle:
            return -1

        # signatureData and clientData are urlsafe base64 encoded
        # correct padding errors (length should be multiples of 4)
        # fill up the signatureData and clientData with '=' to the correct padding
        signatureData = signatureData + ('=' * (4 - (len(signatureData) % 4)))
        clientData = clientData + ('=' * (4 - (len(clientData) % 4)))
        signatureData = base64.urlsafe_b64decode(signatureData.encode('ascii'))
        clientData = base64.urlsafe_b64decode(clientData.encode('ascii'))

        # now check the otp for each challenge
        for ch in challenges:
            challenge = {}

            # we saved the 'real' challenge in the data
            data = ch.get('data', None)
            if data is not None:
                challenge['challenge'] = data.get('challenge')

            if challenge.get('challenge') is None:
                log.debug('could not checkOtp due to missing challenge in request: %r', ch)
                continue

            # prepare the applicationParameter and challengeParameter needed for
            # verification of the registration signature

            appId = self._get_app_id()
            applicationParameter = sha256(appId).digest()
            challengeParameter = sha256(clientData).digest()
            publicKey = base64.urlsafe_b64decode(
                self.getFromTokenInfo('publicKey', None).encode('ascii'))

            # parse the received signatureData object
            (userPresenceByte, counter, signature) = self._parseSignatureData(signatureData)

            # verify the authentication signature
            if not self._validateAuthenticationSignature(applicationParameter,
                                                         userPresenceByte,
                                                         counter,
                                                         challengeParameter,
                                                         publicKey,
                                                         signature
                                                         ):
                continue

            # check the received clientData object and retrieve the appId
            if not self._checkClientData(
                clientData, 'authentication', challenge['challenge']):
                continue

            # the counter is interpreted as big-endian according to the U2F specification
            counterInt = struct.unpack('>I', counter)[0]

            # verify that the counter value increased - prevent token device cloning
            self._verifyCounterValue(counterInt)

            # U2F does not need an otp count
            ret = 0

        log.debug('%r', (ret))
        return ret

    def _parseRegistrationData(self, registrationData):
        """
        Internal helper function to parse the registrationData received on token registration
        according to the U2F specification

        :param registrationData: Raw urlsafe base64 encoded registration data as sent from
                                 the U2F token
        :return:                 Tuple of (userPublicKey, keyHandle, cert, signature)
        """
        USER_PUBLIC_KEY_LEN = 65

        # first byte has to be 0x05
        if ord(registrationData[:1]) is not 0x05:
            log.error("Wrong registration data format: Reserved byte does not match")
            raise ValueError("Wrong registration data format")
        registrationData = registrationData[1:]

        # next 65 bytes refer to the user public key
        userPublicKey = registrationData[:USER_PUBLIC_KEY_LEN]
        if len(userPublicKey) < USER_PUBLIC_KEY_LEN:
            log.error("Wrong registration data format: registration data is too short")
            raise ValueError("Wrong registration data format")
        registrationData = registrationData[USER_PUBLIC_KEY_LEN:]

        # next byte represents the length of the following key handle
        if len(registrationData) < 1:
            log.error("Wrong registration data format: registration data is too short")
            raise ValueError("Wrong registration data format")
        keyHandleLength = ord(registrationData[:1])
        registrationData = registrationData[1:]

        # key handle of length keyHandleLength
        keyHandle = registrationData[:keyHandleLength]
        if len(keyHandle) < keyHandleLength:
            log.error("Wrong registration data format: registration data is too short")
            raise ValueError("Wrong registration data format")
        registrationData = registrationData[keyHandleLength:]

        # load the X509 Certificate
        try:
            cert = X509.load_cert_der_string(registrationData)
            registrationData = registrationData[len(cert.as_der()):]
            # TODO: We could verify that the certificate was issued by a certification
            # authority we trust.
        except X509.X509Error as err:
            log.exception(
                "Wrong registration data format: could not interpret the X509 certificate")
            raise Exception(err)

        # The remaining registrationData is the ECDSA signature
        signature = registrationData

        return (userPublicKey, keyHandle, cert, signature)

    def _validateRegistrationSignature(self,
                                       applicationParameter,
                                       challengeParameter,
                                       keyHandle,
                                       userPublicKey,
                                       cert,
                                       signature
                                       ):
        """
        Internal helper function to validate the registration signature received after parsing the
        token registration data according to the U2F specification

        :param applicationParameter: SHA-256 hash of the application identity.
        :param challengeParameter:   SHA-256 hash of the Client Data, a stringified JSON data
                                     structure prepared by the FIDO Client.
        :param keyHandle:            The key handle retrieved on parsing the registration data
        :param userPublicKey:        The user public key retrieved on parsing the registration data
        :param cert:                 X.509 certificate retrieved on parsing the registration data
        :param signature:            The signature to be verified as retrieved on parsing the
                                     registration data
        """

        certPubKey = cert.get_pubkey()
        certPubKey.reset_context('sha256')
        certPubKey.verify_init()
        if certPubKey.verify_update(chr(0x00) +
                                    applicationParameter +
                                    challengeParameter +
                                    keyHandle +
                                    userPublicKey) != 1:
            log.error("Error on verify_update.")
            raise Exception("Error on verify_update.")

        # Check for OpenSSL version 1.0.0 or higher
        if not self._is_supported_openssl_version():
            log.error("This version of OpenSSL is not supported! OpenSSL version 1.0.0 or "
                      "higher is required for the U2F token.")
            raise Exception("This version of OpenSSL is not supported! OpenSSL version 1.0.0 "
                            "or higher is required for the U2F token.")

        if certPubKey.verify_final(signature) != 1:
            log.error("Signature verification failed! Maybe someone is doing something "
                      "nasty! However, this error could possibly also be related to missing "
                      "ECDSA support for the NIST P-256 curve in OpenSSL.")
            raise Exception("Signature verification failed! Maybe someone is doing "
                            "something nasty! However, this error could possibly also be "
                            "related to missing ECDSA support for the NIST P-256 curve in "
                            "OpenSSL.")

    def getInitDetail(self, params, user=None):
        """
        to complete the token normalisation, the response of the initialisation
        should be built by the token specific method, the getInitDetails
        """
        response_detail = {}

        info = self.getInfo()
        response_detail.update(info)
        response_detail['serial'] = self.getSerial()

        # get requested phase
        requested_phase = getParam(params, "phase", optional=False)

        if requested_phase == "registration1":
            # We are in registration phase 1
            # We create a 32 bytes otp key (from urandom)
            # which is used as the registration challenge
            challenge = base64.urlsafe_b64encode(binascii.unhexlify(self._genOtpKey_(32)))
            self.addToTokenInfo('challenge', challenge)

            # save the appId to the TokenInfo
            # An appId passed as parameter is preferred over an appId defined in a policy
            appId = ''
            if 'appid' in params:
                appId = params.get('appid')
            else:
                # No appId passed as parameter - fall back to the policy
                # Get the appId as specified in the enrollment policy 'u2f_app_id'
                # for the specific realm
                # If the token has multiple realms, the appIds are checked for conflicts.
                # It could be discussed whether the token should use the appId of the default
                # realm, when the token is not attached to any realms
                realms = self.token.getRealmNames()
                for realm in realms:
                    get_policy_params = {
                        'action': 'u2f_app_id',
                        'scope': 'enrollment',
                        'realm': realm
                        }
                    policy_value = getPolicyActionValue(getPolicy(get_policy_params),
                                                        'u2f_app_id',
                                                        is_string=True
                                                        )
                    # Check for appId conflicts
                    if appId and policy_value:
                        if appId != policy_value:
                            log.error("Conflicting appId values in u2f policies.")
                            raise Exception("Conflicting appId values in u2f policies.")
                    appId = policy_value

            if not appId:
                log.error("No appId defined.")
                raise Exception("No appId defined.")
            self.addToTokenInfo('appId', appId)

            # create U2F RegisterRequest object and append it to the response as 'message'
            appId = self._get_app_id()
            register_request = {'challenge': challenge,
                                'version': 'U2F_V2',
                                'appId': appId
                                }
            response_detail['registerrequest'] = register_request

        elif requested_phase == "registration2":
            # We are in registration phase 2
            # process the data generated by the u2f compatible token device
            registerResponse = ""

            otpkey = None
            if 'otpkey' in params:
                otpkey = params.get('otpkey')

            if otpkey is not None:
                # otpkey holds the JSON RegisterResponse object as specified by the FIDO Alliance
                try:
                    registerResponse = json.loads(otpkey)
                except ValueError as ex:
                    log.exception("Invalid JSON format - value error %r", (ex))
                    raise Exception('Invalid JSON format')

                self._handle_client_errors(registerResponse)

                try:
                    registrationData = registerResponse['registrationData']
                    clientData = registerResponse['clientData']
                except AttributeError as ex:
                    log.exception(
                        "Couldn't find keyword in JSON object - attribute error %r ", (ex))
                    raise Exception("Couldn't find keyword in JSON object")

                # registrationData and clientData are urlsafe base64 encoded
                # correct padding errors (length should be multiples of 4)
                # fill up the registrationData with '=' to the correct padding
                registrationData = registrationData + \
                    ('=' * (4 - (len(registrationData) % 4)))
                clientData = clientData + ('=' * (4 - (len(clientData) % 4)))
                registrationData = base64.urlsafe_b64decode(
                    registrationData.encode('ascii'))
                clientData = base64.urlsafe_b64decode(clientData.encode('ascii'))

                # parse the raw registrationData according to the specification
                (userPublicKey, keyHandle, X509cert, signature) = \
                    self._parseRegistrationData(registrationData)

                # check the received clientData object
                if not self._checkClientData(
                    clientData, 'registration', self.getFromTokenInfo('challenge', None)):
                    raise ValueError("Received invalid clientData object. Aborting...")

                # prepare the applicationParameter and challengeParameter needed for
                # verification of the registration signature
                appId = self._get_app_id()
                applicationParameter = sha256(appId).digest()
                challengeParameter = sha256(clientData).digest()

                # verify the registration signature
                self._validateRegistrationSignature(applicationParameter,
                                                    challengeParameter,
                                                    keyHandle,
                                                    userPublicKey,
                                                    X509cert,
                                                    signature
                                                    )

                # save the key handle and the user public key in the Tokeninfo field for
                # future use
                self.addToTokenInfo('keyHandle', base64.urlsafe_b64encode(keyHandle))
                self.addToTokenInfo('publicKey', base64.urlsafe_b64encode(userPublicKey))
                self.addToTokenInfo('counter', '0')
                self.addToTokenInfo('phase', 'authentication')
                # remove the registration challenge from the token info
                self.removeFromTokenInfo('challenge')
                # Activate the token
                self.token.LinOtpIsactive = True
            else:
                log.error("No otpkey set!")
                raise ValueError("No otpkey set")
        else:
            log.error("Unsupported phase: %s", requested_phase)
            raise Exception("Unsupported phase: %s", requested_phase)

        return response_detail

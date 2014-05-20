# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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
""" This file contains the Yubikey token class where the Yubikey is
    run in Yubico Mode"""

import logging

import traceback
from Crypto.Cipher import AES

import binascii

optional = True
required = False

from linotp.lib.validate import check_pin

from linotp.lib.tokenclass import TokenClass
from linotp.lib.util import modhex_decode
from linotp.lib.util import checksum

log = logging.getLogger(__name__)



###############################################
class YubikeyTokenClass(TokenClass):
    """
    The Yubikey Token in the Yubico AES mode
    """

    def __init__(self, aToken):
        TokenClass.__init__(self, aToken)
        self.setType(u"yubikey")

        self.hKeyRequired = True
        return


    @classmethod
    def getClassType(cls):
        return "yubikey"

    @classmethod
    def getClassPrefix(cls):
        return "UBAM"

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
        log.debug("[getClassInfo] begin. Get class render info for section: key %r, ret %r " %
                  (key, ret))

        res = {
            'type':          'yubikey',
            'title':         'Yubikey in Yubico Mode',
            'description':   ('Yubico token to run the AES OTP mode.'),
            'init':          {},
            'config':        {},
            'selfservice':   {},
            'policy':        {},
        }

        if key is not None and key in res:
            ret = res.get(key)
        else:
            if ret == 'all':
                ret = res
        log.debug("[getClassInfo] end. Returned the configuration section: ret %r " % (ret))
        return ret

    def check_otp_exist(self, otp, window=None):
        '''
        checks if the given OTP value is/are values of this very token.
        This is used to autoassign and to determine the serial number of
        a token.
        '''
        res = -1
        if window is None:
            window = self.getOtpCountWindow()
        counter = self.getOtpCount()

        res = self.checkOtp(otp, counter=counter, window=window, options=None)

        if res >= 0:
            # As usually the counter is increased in lib.token.checkUserPass, we
            # need to do this manually here:
            self.incOtpCounter(res)

        return res

    def is_challenge_request(self, passw, user, options=None):
        '''
        This method checks, if this is a request, that triggers a challenge.

        :param passw: password, which might be pin or pin+otp
        :type passw: string
        :param user: The user from the authentication request
        :type user: User object
        :param options: dictionary of additional request parameters
        :type options: dict

        :return: true or false
        '''

        request_is_valid = False

        pin_match = check_pin(self, passw, user=user, options=options)
        if pin_match is True:
            request_is_valid = True

        return request_is_valid


    def checkOtp(self, anOtpVal, counter=None, window=None, options=None):
        """
        checkOtp - validate the token otp against a given otpvalue

        :param anOtpVal: the to be verified otpvalue
        :type anOtpVal:  string

        :param counter: the counter state. It is not used by the Yubikey because the current counter value
        is sent encrypted inside the OTP value
        :type counter: int

        :param window: the counter +window, which is not used in the Yubikey because the current
        counter value is sent encrypted inside the OTP, allowing a simple comparison between the encrypted
        counter value and the stored counter value
        :type window: int

        :param options: the dict, which could contain token specific info
        :type options: dict

        :return: the counter state or an error code (< 0):
        -1 if the OTP is old (counter < stored counter)
        -2 if the private_uid sent in the OTP is wrong (different from the one stored with the token)
        -3 if the CRC verification fails
        :rtype: int

        """
        log.debug("[checkOtp] begin. Validate the token otp: anOtpVal: %r, counter: %r,  options: %r "
                  % (anOtpVal, counter, options))
        res = -1

        serial = self.token.getSerial()
        secret = self.token.getHOtpKey()

        # The prefix is the characters in front of the last 32 chars
        yubi_prefix = anOtpVal[:-32]
        # The variable otp val is the last 32 chars
        yubi_otp = anOtpVal[-32:]

        # TODO: We can also check the PREFIX! At the moment, we do not use it!

        otp_bin = modhex_decode(yubi_otp)
        msg_bin = secret.aes_decrypt(otp_bin)
        msg_hex = binascii.hexlify(msg_bin)

        # The checksum is a CRC-16 (16-bit ISO 13239 1st complement) that
        # occupies the last 2 bytes of the decrypted OTP value. Calculating the
        # CRC-16 checksum of the whole decrypted OTP should give a fixed residual
        # of 0xf0b8 (see Yubikey-Manual - Chapter 6: Implementation details).
        log.debug("[checkOtp] calculated checksum (61624): %r" % checksum(msg_hex))
        if checksum(msg_hex) != 0xf0b8:
            log.warning("[checkOtp] CRC checksum for token %r failed" % serial)
            return -3

        uid = msg_hex[0:12]
        log.debug("[checkOtp] uid: %r" % uid)
        log.debug("[checkOtp] prefix: %r" % binascii.hexlify(modhex_decode(yubi_prefix)))
        # usage_counter can go from 1 – 0x7fff
        usage_counter = msg_hex[12:16]
        timestamp = msg_hex[16:22]
        # session counter can go from 00 to 0xff
        session_counter = msg_hex[22:24]
        random = msg_hex[24:28]
        crc = msg_hex[28:]
        log.debug("[checkOtp] decrypted: usage_count: %r, session_count: %r" % (usage_counter, session_counter))

        # create the counter as integer
        # Note: The usage counter is stored LSB!

        count_hex = usage_counter[2:4] + usage_counter[0:2] + session_counter
        count_int = int(count_hex, 16)
        log.debug('[checkOtp] decrypted counter: %r' % count_int)

        tokenid = self.getFromTokenInfo("yubikey.tokenid")
        if not tokenid:
            log.debug("[checkOtp] Got no tokenid for %r. Setting to %r." % (serial, uid))
            tokenid = uid
            self.addToTokenInfo("yubikey.tokenid", tokenid)

        if tokenid != uid:
            # wrong token!
            log.warning("[checkOtp] The wrong token was presented for %r. Got %r, expected %r."
                        % (serial, uid, tokenid))
            return -2


        # TODO: We also could check the timestamp
        # - the timestamp. see http://www.yubico.com/wp-content/uploads/2013/04/YubiKey-Manual-v3_1.pdf
        log.debug('[checkOtp] compare counter to LinOtpCount: %r' % self.token.LinOtpCount)
        if count_int >= self.token.LinOtpCount:
            res = count_int

        return res

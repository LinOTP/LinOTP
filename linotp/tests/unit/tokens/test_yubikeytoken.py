# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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

import binascii
import json
import logging
import unittest

import pytest
from Cryptodome.Cipher import AES
from mock import MagicMock, patch


def _aes_decrypt_constructor(hex_key):
    """
    Returns a aes_decrypt function for the given hex key
    """
    binary_key = binascii.unhexlify(hex_key)

    def aes_decrypt(data_input):
        """
        support inplace aes decryption for the yubikey

        :param data_input: data, that should be decrypted
        :return: the decrypted data
        """
        aes = AES.new(binary_key, AES.MODE_ECB)
        msg_bin = aes.decrypt(data_input)
        return msg_bin

    return aes_decrypt


class YubikeyTokenClassTestCase(unittest.TestCase):
    """
    This class tests the YubikeyTokenClass in isolation by mocking out
    all dependencies on other classes. Therefore the tests can be run without
    requiring an installed server.
    """

    def setUp(self):
        import linotp.lib.crypto
        from linotp.tokens.yubikeytoken import YubikeyTokenClass

        # Without this logging in the tested class fails
        logging.basicConfig()

        # All these values were generated/tested with a real Yubikey
        # aes_key in hex format
        aes_key = "9163508031b20d2fbb1868954e041729"
        serial = "UBAM01382015_1"
        # private_uid in hex format
        self.private_uid = "adb0ee7dd24a"
        # public_uid in modhex format. In decimal: 01382015
        self.public_uid = "ecebeeejedecebeg"

        # Initialize mock objects
        secret_obj = MagicMock(spec=linotp.lib.crypto.SecretObj)
        secret_obj.aes_decrypt = _aes_decrypt_constructor(aes_key)

        # mock the linotp.model.Token
        model_token = MagicMock(
            spec=[
                "getSerial",
                "getHOtpKey",
                "getInfo",
                "setInfo",
                "setType",
                "LinOtpCountWindow",
            ]
        )
        model_token.getSerial.return_value = serial
        model_token.getInfo.return_value = json.dumps(
            {"yubikey.tokenid": self.private_uid}
        )

        # LinOtpCountWindow is not required in the Yubikey Token
        model_token.LinOtpCountWindow = None
        model_token.LinOtpCount = 0
        model_token.LinOtpOtpLen = 32

        self.model_token = model_token

        # create the yubike with the mocked model_token
        self.yubikey_token = YubikeyTokenClass(model_token)

        def _get_secret_object():
            return secret_obj

        setattr(self.yubikey_token, "_get_secret_object", _get_secret_object)
        model_token.setType.assert_called_once_with("yubikey")

    def test_checkotp_positive(self):
        """
        Verify that correct OTP values are decrypted and accepted
        """
        # The counter we use is calculated with the session_counter and usage_counter
        # contained in the OTP. counter = usage_counter*256 + session_counter
        # See the Yubikey documentation for an explanation of both counters.
        otp_counter_dict = {
            self.public_uid + "fcniufvgvjturjgvinhebbbertjnihit": 256,
            self.public_uid + "tbkfkdhnfjbjnkcbtbcckklhvgkljifu": 257,
            self.public_uid + "ktvkekfgufndgbfvctgfrrkinergbtdj": 258,
            self.public_uid + "jbefledlhkvjjcibvrdfcfetnjdjitrn": 259,
            self.public_uid + "druecevifbfufgdegglttghghhvhjcbh": 260,
            self.public_uid + "nvfnejvhkcililuvhntcrrulrfcrukll": 261,
            self.public_uid + "kttkktdergcenthdredlvbkiulrkftuk": 262,
            self.public_uid + "hutbgchjucnjnhlcnfijckbniegbglrt": 512,
            self.public_uid + "vneienejjnedbfnjnnrfhhjudjgghckl": 513,
            self.public_uid + "krgevltjnujcnuhtngjndbhbiiufbnki": 514,
            self.public_uid + "kehbefcrnlfejedfdulubuldfbhdlicc": 768,
            self.public_uid + "ljlhjbkejkctubnejrhuvljkvglvvlbk": 769,
            self.public_uid + "eihtnehtetluntirtirrvblfkttbjuih": 770,
        }

        # Test positive cases (otp_counter_dict)
        for otp in otp_counter_dict:
            counter_expected = otp_counter_dict[otp]
            counter_actual = self.yubikey_token.checkOtp(otp)
            assert counter_expected == counter_actual, (
                "Counter for OTP: "
                + otp
                + " is incorrect. Should be "
                + str(counter_expected)
                + " and is "
                + str(counter_actual)
            )

    def test_checkotp_old_otp(self):
        """
        Verify that an old OTP value (smaller the the stored counter) is not accepted.
        """
        self.model_token.LinOtpCount = 300
        otp = (
            self.public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
        )  # counter 256
        counter_expected = -1
        counter_actual = self.yubikey_token.checkOtp(otp)
        assert counter_expected == counter_actual, (
            "OTP: " + otp + " should no longer be accepted."
        )

    def test_checkotp_with_wrong_prefix(self):
        """
        check: if no prefix has been enrolled, the token will not complain about any prefix
        """

        # Passing bad prefix - xx is not decodeable
        otp = "xx" + "fcniufvgvjturjgvinhebbbertjnihit"
        counter_expected = 256

        # suppress the warning
        logger = logging.getLogger("linotp.tokens.yubikeytoken")
        logger.disabled = True

        counter_actual = self.yubikey_token.checkOtp(otp)

        assert counter_expected == counter_actual, (
            "verification for malicous prefix: %s should fail." % otp
        )

        logger.disabled = False

        # Passing a too short prefix
        otp = "iibb" + "fcniufvgvjturjgvinhebbbertjnihit"
        counter_expected = 256

        # suppress the warnings
        logger = logging.getLogger("linotp.tokens.yubikeytoken")
        logger.disabled = True

        counter_actual = self.yubikey_token.checkOtp(otp)

        assert counter_expected == counter_actual, (
            "verification for malicous prefix: %s should fail." % otp
        )

        logger.disabled = False

    def test_checkotp_with_wrong_prefix_fail(self):
        """
        check: if prefix has been enrolled, the token will complain about wrong prefix
        """

        # Passing not matching prefix
        token_info = {"public_uid": self.public_uid}
        self.model_token.getInfo.return_value = json.dumps(token_info)

        wrong_pub_id = self.public_uid.replace("e", "i")
        otp = wrong_pub_id + "fcniufvgvjturjgvinhebbbertjnihit"

        counter_expected = -1

        # suppress the warning
        logger = logging.getLogger("linotp.tokens.yubikeytoken")
        logger.disabled = True

        counter_actual = self.yubikey_token.checkOtp(otp)

        assert counter_expected == counter_actual, (
            "verification for malicous prefix: %s should fail." % otp
        )

        logger.disabled = False

        # Passing a too short prefix will complain as well
        otp = "iibb" + "fcniufvgvjturjgvinhebbbertjnihit"
        counter_expected = -1

        # suppress the warnings
        logger = logging.getLogger("linotp.tokens.yubikeytoken")
        logger.disabled = True

        counter_actual = self.yubikey_token.checkOtp(otp)

        assert counter_expected == counter_actual, (
            "verification for malicous prefix: %s should fail." % otp
        )

        logger.disabled = False

    def test_checkotp_wrong_crc(self):
        """
        Verify that an OTP with corrupt data is not accepted
        """
        # Passing in a random (wrong) OTP should fail because of the CRC
        otp = self.public_uid + "fcniufvgvjturjgvinhebbvvvvvvvvvv"
        counter_expected = -3
        # We want to suppress the warning generated because of the wrong CRC
        logger = logging.getLogger("linotp.tokens.yubikeytoken")
        logger.disabled = True
        counter_actual = self.yubikey_token.checkOtp(otp)
        logger.disabled = False
        assert counter_expected == counter_actual, (
            "CRC verification for OTP: " + otp + " should fail."
        )

    def test_checkotp_no_tokenid(self):
        """
        Verify that if the yubikey.tokenid is not set, then the corresponding function for
        setting it is called.
        """
        # yubikey.tokenid is not set
        self.model_token.getInfo.return_value = "{}"
        otp = self.public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
        self.yubikey_token.checkOtp(otp)
        # Verify that the tokenid is passed onto linotp.model.Token
        expected_tokeninfo = (
            "" + '{\n"yubikey.tokenid": "' + self.private_uid + '"\n}'
        )
        self.model_token.setInfo.assert_called_once_with(expected_tokeninfo)

    def test_checkotp_wrong_tokenid(self):
        """
        Verify that if the stored uid differs from the one contained in the OTP then an error
        is returned.
        """
        self.model_token.getInfo.return_value = (
            "" + '{\n"yubikey.tokenid": "wrong-value"\n}'
        )
        otp = self.public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
        counter_expected = -2
        # We want to suppress the warning generated because of the wrong CRC
        logger = logging.getLogger("linotp.tokens.yubikeytoken")
        logger.disabled = True
        counter_actual = self.yubikey_token.checkOtp(otp)
        logger.disabled = False
        assert counter_expected == counter_actual, (
            "(private) uid should not be accepted for OTP: " + otp
        )

    def test_class_type_and_prefix(self):
        """
        Verify the simple classmethods getClassType and getClassPrefix
        """
        from linotp.tokens.yubikeytoken import YubikeyTokenClass

        assert YubikeyTokenClass.getClassType() == "yubikey"
        assert YubikeyTokenClass.getClassPrefix() == "UBAM"

    def test_class_info(self):
        """
        Test the classmethod getClassInfo
        """
        from linotp.tokens.yubikeytoken import YubikeyTokenClass

        full_class_info = {
            "selfservice": {},
            "description": "Yubico token to run the AES OTP mode.",
            "title": "YubiKey in Yubico Mode",
            "type": "yubikey",
            "init": {},
            "policy": {},
            "config": {},
        }
        class_info = YubikeyTokenClass.getClassInfo()
        assert full_class_info == class_info
        assert "YubiKey in Yubico Mode" == YubikeyTokenClass.getClassInfo(
            key="title"
        )
        assert full_class_info == YubikeyTokenClass.getClassInfo(
            key="some_non_existent_key"
        )
        assert "some_random_value" == YubikeyTokenClass.getClassInfo(
            key="some_non_existent_key", ret="some_random_value"
        )

    def test_check_otp_exist(self):
        """
        Test method check_otp_exist()
        """
        otp = self.public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
        counter_expected = 256
        self.yubikey_token.incOtpCounter = MagicMock()
        counter_actual = self.yubikey_token.check_otp_exist(otp)
        self.yubikey_token.incOtpCounter.assert_called_once_with(
            counter_expected
        )
        assert counter_expected == counter_actual

        # invalid (old) value
        self.model_token.LinOtpCount = 300
        otp = (
            self.public_uid + "fcniufvgvjturjgvinhebbbertjnihit"
        )  # counter 256
        self.yubikey_token.incOtpCounter.reset_mock()
        counter_actual = self.yubikey_token.check_otp_exist(otp)
        assert 0 == self.yubikey_token.incOtpCounter.call_count
        assert -1 == counter_actual

    def test_is_challenge_request(self):
        """
        Test is_challenge_request() method
        """
        patcher = patch("linotp.tokens.yubikeytoken.check_pin", spec=True)
        check_pin_mock = patcher.start()
        check_pin_mock.return_value = True
        assert self.yubikey_token.is_challenge_request(
            "a-pin", user="someuser"
        )
        check_pin_mock.return_value = False
        assert not self.yubikey_token.is_challenge_request(
            "not-a-pin", user="someuser"
        )
        patcher.stop()


if __name__ == "__main__":
    unittest.main()

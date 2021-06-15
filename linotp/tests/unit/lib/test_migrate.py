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
"""
Tests a very small subset of linotp.lib.reply
"""
import os
import unittest

from Cryptodome.Cipher import AES

from linotp.lib.migrate import Crypter


def init_crypter(passphrase, salt=None):
    """
    setup the MigrationHandler - or more precise the crypto handler, which
    is a MigrationHandler member.

    :param passphrase: enc + decryption key is derived from the passphrase
    :param salt: optional - if not given, a new one is generated

    :return: the crypto handler
    """
    if not salt:
        salt = os.urandom(AES.block_size)

    crypter = Crypter(passphrase, salt)

    return crypter


class TestMigrate(unittest.TestCase):
    def test_decrypt_encrypt(self):

        config = {
            "SMSProviderTimeout": "300",
            "totp.timeShift": "0",
            "DefaultSyncWindow": "1000",
            "user_lookup_cache.enabled": "True",
            "totp.timeStep": "30",
            "Config": "2017-03-11 00:32:29.469277",
            "welcome_screen.opt_out": "false",
            "totp.timeWindow": "300",
            "DefaultResetFailCount": "True",
            "AutoResyncTimeout": "240",
            "certificates.use_system_certificates": "False",
            "DefaultBlockingTimeout": "0",
            "welcome_screen.version": "0",
            "resolver_lookup_cache.enabled": "True",
            "DefaultMaxFailCount": "10",
            "FailCounterIncOnFalsePin": "True",
            "PrependPin": "True",
            "SMSProvider": "smsprovider.HttpSMSProvider.HttpSMSProvider",
            "SecretKey.Partition.0": "YaGRQxVxn2Q45+TLhOUvNtDBr1AkPemgy4M7ddEEI8E7o94nXIHawsEkvdqaOl3h0w2PYsIl0OaZ8gIxY4PfJQ==",
            "PublicKey.Partition.0": "O6PeJ1yB2sLBJL3amjpd4dMNj2LCJdDmmfICMWOD3yU=",
            "DefaultChallengeValidityTime": "120",
            "EmailChallengeValidityTime": "600",
            "EmailBlockingTimeout": "120",
            "PushChallengeValidityTime": "150",
            "OATHTokenSupport": "False",
            "welcome_screen.last_shown": "0",
            "QRTokenOtpLen": "8",
            "EmailProvider": "linotp.provider.emailprovider.SMTPEmailProvider",
            "DefaultOtpLen": "6",
            "sql_data_model_version": "2.9.1.0",
            "DefaultRealm": "",
            "user_lookup_cache.expiration": "64800",
            "SMSBlockingTimeout": "30",
            "PushMaxChallenges": "4",
            "DefaultCountWindow": "10",
            "resolver_lookup_cache.expiration": "64800",
            "root": "/home/LinOTP/linotpd/src/linotp",
        }

        passphrase = "foobar"
        crypter = init_crypter(passphrase)

        for key, value in list(config.items()):

            # calculate encryption and add mac from mac_data
            enc_value = crypter.encrypt(input_data=value, just_mac=key + value)

            # decypt the real value

            out_value = crypter.decrypt(enc_value, just_mac=key + value)
            assert value == out_value

        return

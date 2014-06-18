#!/usr/bin/env python

import unittest
import yubico
import yubico.yubikey_config
from yubico.yubikey_config import YubiKeyConfigUSBHID
import yubico.yubico_util
import yubico.yubico_exception

class YubiKeyTests(unittest.TestCase):

    Config = ''

    def setUp(self):
        self.Config = YubiKeyConfigUSBHID()

    def test_static_ticket(self):
        """ Test static ticket """

        #fixed: m:
        #uid: h:000000000000
        #key: h:e2bee9a36568a00d026a02f85e61e6fb
        #acc_code: h:000000000000
        #ticket_flags: APPEND_CR
        #config_flags: STATIC_TICKET

        expected = ['\x00\x00\x00\x00\x00\x00\x00\x80',
                    '\x00\xe2\xbe\xe9\xa3\x65\x68\x83',
                    '\xa0\x0d\x02\x6a\x02\xf8\x5e\x84',
                    '\x61\xe6\xfb\x00\x00\x00\x00\x85',
                    '\x00\x00\x00\x00\x20\x20\x00\x86',
                    '\x00\x5a\x93\x00\x00\x00\x00\x87',
                    '\x00\x01\x95\x56\x00\x00\x00\x89'
                    ]

        Config = self.Config
        Config.aes_key('h:e2bee9a36568a00d026a02f85e61e6fb')
        Config.ticket_flag('APPEND_CR', True)
        Config.config_flag('STATIC_TICKET', True)

        data = Config.to_frame(slot=1).to_feature_reports()

        print "EXPECT:\n%s\nGOT:\n%s\n" % (yubico.yubico_util.hexdump(''.join(expected)),
                                           yubico.yubico_util.hexdump(''.join(data)))

        self.assertEqual(data, expected)


    def test_static_ticket_with_access_code(self):
        """ Test static ticket with unlock code """

        #fixed: m:
        #uid: h:000000000000
        #key: h:e2bee9a36568a00d026a02f85e61e6fb
        #acc_code: h:010203040506
        #ticket_flags: APPEND_CR
        #config_flags: STATIC_TICKET

        expected = ['\x00\x00\x00\x00\x00\x00\x00\x80',
                    '\x00\xe2\xbe\xe9\xa3\x65\x68\x83',
                    '\xa0\x0d\x02\x6a\x02\xf8\x5e\x84',
                    '\x61\xe6\xfb\x01\x02\x03\x04\x85',
                    '\x05\x06\x00\x00\x20\x20\x00\x86',
                    '\x00\x0d\x39\x01\x02\x03\x04\x87',
                    '\x05\x06\x00\x00\x00\x00\x00\x88',
                    '\x00\x01\xc2\xfc\x00\x00\x00\x89',
                    ]

        Config = self.Config
        Config.aes_key('h:e2bee9a36568a00d026a02f85e61e6fb')
        Config.ticket_flag('APPEND_CR', True)
        Config.config_flag('STATIC_TICKET', True)
        Config.unlock_key('h:010203040506')

        data = Config.to_frame(slot=1).to_feature_reports()

        print "EXPECT:\n%s\nGOT:\n%s\n" % (yubico.yubico_util.hexdump(''.join(expected)),
                                           yubico.yubico_util.hexdump(''.join(data)))

        self.assertEqual(data, expected)

    def test_fixed_and_oath_hotp(self):
        """ Test OATH HOTP with a fixed prefix-string """

        #fixed: m:ftftftft
        #uid: h:000000000000
        #key: h:523d7ce7e7b6ee853517a3e3cc1985c7
        #acc_code: h:000000000000
        #ticket_flags: APPEND_CR|OATH_HOTP
        #config_flags: OATH_FIXED_MODHEX1|OATH_FIXED_MODHEX2|STATIC_TICKET

        expected = ['\x4d\x4d\x4d\x4d\x00\x00\x00\x80',
                    '\x00\x52\x3d\x7c\xe7\xe7\xb6\x83',
                    '\xee\x85\x35\x17\xa3\xe3\xcc\x84',
                    '\x19\x85\xc7\x00\x00\x00\x00\x85',
                    '\x00\x00\x04\x00\x60\x70\x00\x86',
                    '\x00\x72\xad\xaa\xbb\xcc\xdd\x87',
                    '\xee\xff\x00\x00\x00\x00\x00\x88',
                    '\x00\x03\xfe\xc4\x00\x00\x00\x89',
                    ]

        Config = self.Config
        Config.aes_key('h:523d7ce7e7b6ee853517a3e3cc1985c7')
        Config.fixed_string('m:ftftftft')
        Config.ticket_flag('APPEND_CR', True)
        Config.ticket_flag('OATH_HOTP', True)
        Config.config_flag('OATH_FIXED_MODHEX1', True)
        Config.config_flag('OATH_FIXED_MODHEX2', True)
        Config.config_flag('STATIC_TICKET', True)
        Config.unlock_key('h:aabbccddeeff')
        Config.access_key('h:000000000000')

        data = Config.to_frame(slot=2).to_feature_reports()

        print "EXPECT:\n%s\nGOT:\n%s\n" % (yubico.yubico_util.hexdump(''.join(expected)),
                                           yubico.yubico_util.hexdump(''.join(data)))

        self.assertEqual(data, expected)

    def test_challenge_response_hmac_nist(self):
        """ Test HMAC challenge response with NIST test vector """

        expected = ['\x00\x00\x00\x00\x00\x00\x00\x80',
                    '\x00\x00\x40\x41\x42\x43\x00\x82',
                    '\x00\x30\x31\x32\x33\x34\x35\x83',
                    '\x36\x37\x38\x39\x3a\x3b\x3c\x84',
                    '\x3d\x3e\x3f\x00\x00\x00\x00\x85',
                    '\x00\x00\x00\x04\x40\x26\x00\x86',
                    '\x00\x98\x41\x00\x00\x00\x00\x87',
                    '\x00\x03\x95\x56\x00\x00\x00\x89',
                    ]

        Config = self.Config
        secret = 'h:303132333435363738393a3b3c3d3e3f40414243'
        Config.mode_challenge_response(secret, type='HMAC', variable=True)
        Config.extended_flag('SERIAL_API_VISIBLE', True)

        data = Config.to_frame(slot=2).to_feature_reports()

        print "EXPECT:\n%s\nGOT:\n%s\n" % (yubico.yubico_util.hexdump(''.join(expected)),
                                           yubico.yubico_util.hexdump(''.join(data)))

        self.assertEqual(data, expected)

    def test_unknown_ticket_flag(self):
        """ Test setting unknown ticket flag  """
        self.assertRaises(yubico.yubico_exception.InputError, self.Config.ticket_flag, 'YK_UNIT_TEST123', True)

    def test_unknown_ticket_flag_integer(self):
        """ Test setting unknown ticket flag as integer """
        future_flag = 0xff
        self.Config.ticket_flag(future_flag, True)
        self.assertEqual(future_flag, self.Config.ticket_flags.to_integer())

    def test_too_long_fixed_string(self):
        """ Test too long fixed string, and set as plain string """
        self.assertRaises(yubico.yubico_exception.InputError, self.Config.ticket_flag, 'YK_UNIT_TEST123', True)

    def test_default_flags(self):
        """ Test that no flags get set by default """
        self.assertEqual(0x0, self.Config.ticket_flags.to_integer())
        self.assertEqual(0x0, self.Config.config_flags.to_integer())
        self.assertEqual(0x0, self.Config.extended_flags.to_integer())

    def test_oath_hotp_like_windows(self):
        """ Test plain OATH-HOTP with NIST test vector """

        expected = ['\x00\x00\x00\x00\x00\x00\x00\x80',
                    '\x00\x00\x40\x41\x42\x43\x00\x82',
                    '\x00\x30\x31\x32\x33\x34\x35\x83',
                    '\x36\x37\x38\x39\x3a\x3b\x3c\x84',
                    '\x3d\x3e\x3f\x00\x00\x00\x00\x85',
                    '\x00\x00\x00\x00\x40\x00\x00\x86',
                    '\x00\x6a\xb9\x00\x00\x00\x00\x87',
                    '\x00\x03\x95\x56\x00\x00\x00\x89',
                    ]

        Config = self.Config
        secret = 'h:303132333435363738393a3b3c3d3e3f40414243'
        Config.mode_oath_hotp(secret)

        data = Config.to_frame(slot=2).to_feature_reports()

        print "EXPECT:\n%s\nGOT:\n%s\n" % (yubico.yubico_util.hexdump(''.join(expected)),
                                           yubico.yubico_util.hexdump(''.join(data)))

        self.assertEqual(data, expected)

    def test_oath_hotp_like_windows2(self):
        """ Test OATH-HOTP with NIST test vector and token identifier """

        expected = ['\x01\x02\x03\x04\x05\x06\x00\x80',
                    '\x00\x00\x40\x41\x42\x43\x00\x82',
                    '\x00\x30\x31\x32\x33\x34\x35\x83',
                    '\x36\x37\x38\x39\x3a\x3b\x3c\x84',
                    '\x3d\x3e\x3f\x00\x00\x00\x00\x85',
                    '\x00\x00\x06\x00\x40\x42\x00\x86',
                    '\x00\x0e\xec\x00\x00\x00\x00\x87',
                    '\x00\x03\x95\x56\x00\x00\x00\x89',
                    ]

        Config = self.Config
        secret = 'h:303132333435363738393a3b3c3d3e3f40414243'
        Config.mode_oath_hotp(secret, bytes=8, factor_seed='', omp=0x01, tt=0x02, mui='\x03\x04\x05\x06')
        Config.config_flag('OATH_FIXED_MODHEX2', True)

        data = Config.to_frame(slot=2).to_feature_reports()

        print "EXPECT:\n%s\nGOT:\n%s\n" % (yubico.yubico_util.hexdump(''.join(expected)),
                                           yubico.yubico_util.hexdump(''.join(data)))

        self.assertEqual(data, expected)

    def test_oath_hotp_like_windows_factory_seed(self):
        """ Test OATH-HOTP factor_seed """

        expected = ['\x01\x02\x03\x04\x05\x06\x00\x80',
                    '\x00\x00\x40\x41\x42\x43\x01\x82',
                    '\x21\x30\x31\x32\x33\x34\x35\x83',
                    '\x36\x37\x38\x39\x3a\x3b\x3c\x84',
                    '\x3d\x3e\x3f\x00\x00\x00\x00\x85',
                    '\x00\x00\x06\x00\x40\x42\x00\x86',
                    '\x00\x03\xea\x00\x00\x00\x00\x87',
                    '\x00\x03\x95\x56\x00\x00\x00\x89',
                    ]

        Config = self.Config
        secret = 'h:303132333435363738393a3b3c3d3e3f40414243'
        Config.mode_oath_hotp(secret, bytes=8, factor_seed=0x2101, omp=0x01, tt=0x02, mui='\x03\x04\x05\x06')
        Config.config_flag('OATH_FIXED_MODHEX2', True)

        data = Config.to_frame(slot=2).to_feature_reports()

        print "EXPECT:\n%s\nGOT:\n%s\n" % (yubico.yubico_util.hexdump(''.join(expected)),
                                           yubico.yubico_util.hexdump(''.join(data)))

        self.assertEqual(data, expected)

    def test_fixed_length_hmac_like_windows(self):
        """ Test fixed length HMAC SHA1 """

        expected = ['\x00\x00\x00\x00\x00\x00\x00\x80',
                    '\x00\x00\x40\x41\x42\x43\x00\x82',
                    '\x00\x30\x31\x32\x33\x34\x35\x83',
                    '\x36\x37\x38\x39\x3a\x3b\x3c\x84',
                    '\x3d\x3e\x3f\x00\x00\x00\x00\x85',
                    '\x00\x00\x00\x00\x40\x22\x00\x86',
                    '\x00\xe9\x0f\x00\x00\x00\x00\x87',
                    '\x00\x03\x95\x56\x00\x00\x00\x89',
                    ]

        Config = self.Config
        secret = 'h:303132333435363738393a3b3c3d3e3f40414243'
        Config.mode_challenge_response(secret, type='HMAC', variable=False)

        data = Config.to_frame(slot=2).to_feature_reports()

        print "EXPECT:\n%s\nGOT:\n%s\n" % (yubico.yubico_util.hexdump(''.join(expected)),
                                           yubico.yubico_util.hexdump(''.join(data)))

        self.assertEqual(data, expected)

    def test_version_required_1(self):
        """ Test YubiKey 1 with v2 option """

        Config = YubiKeyConfigUSBHID(ykver=(1, 3))
        self.assertRaises(yubico.yubikey_config.YubiKeyConfigError, Config.config_flag, 'SHORT_TICKET', True)

    def test_version_required_2(self):
        """ Test YubiKey 2 with v2 option """

        Config = YubiKeyConfigUSBHID(ykver=(2, 2))
        Config.config_flag('SHORT_TICKET', True)
        self.assertEqual((2, 0), Config.version_required())

    def test_version_required_3(self):
        """ Test YubiKey 2 with v1 option """

        Config = YubiKeyConfigUSBHID(ykver=(2, 2))
        self.assertRaises(yubico.yubikey_config.YubiKeyConfigError, Config.config_flag, 'TICKET_FIRST', True)

    def test_version_required_4(self):
        """ Test YubiKey 2.1 with v2.2 mode """

        Config = YubiKeyConfigUSBHID(ykver=(2, 1))
        secret = 'h:303132333435363738393a3b3c3d3e3f40414243'
        self.assertRaises(yubico.yubikey_config.YubiKeyConfigError, Config.mode_challenge_response, secret)

    def test_version_required_5(self):
        """ Test YubiKey 2.2 with v2.2 mode """

        Config = YubiKeyConfigUSBHID(ykver=(2, 2))
        secret = 'h:303132333435363738393a3b3c3d3e3f40414243'
        Config.mode_challenge_response(secret, type='yubico')
        self.assertEqual('CHAL_RESP', Config._mode)

if __name__ == '__main__':
    unittest.main()

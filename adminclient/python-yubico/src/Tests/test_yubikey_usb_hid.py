#!/usr/bin/env python
#
# Test cases for talking to a USB HID YubiKey.
#

import struct
import unittest
import yubico
import yubico.yubikey_usb_hid
from yubico.yubikey_usb_hid import *
import re

class TestYubiKeyUSBHID(unittest.TestCase):

    YK = None

    def setUp(self):
        """ Test connecting to the YubiKey """
        if self.YK is None:
            try:
                self.YK = YubiKeyUSBHID()
                return
            except YubiKeyUSBHIDError as  err:
                self.fail("No YubiKey connected (?) : %s" % str(err))

    #@unittest.skipIf(YK is None, "No USB HID YubiKey found")
    def test_status(self):
        """ Test the simplest form of communication : a status read request """
        status = self.YK.status()
        version = self.YK.version()
        print "Version returned: %s" % version
        re_match = re.match("\d+\.\d+\.\d+$", version)
        self.assertNotEqual(re_match, None)

    #@unittest.skipIf(self.YK is None, "No USB HID YubiKey found")
    def test_challenge_response(self):
        """ Test challenge-response, assumes a NIST PUB 198 A.2 20 bytes test vector in Slot 2 (variable input) """

        secret = struct.pack('64s', 'Sample #2')
        response = self.YK.challenge_response(secret, mode='HMAC', slot=2)
        self.assertEqual(response, '\x09\x22\xd3\x40\x5f\xaa\x3d\x19\x4f\x82\xa4\x58\x30\x73\x7d\x5c\xc6\xc7\x5d\x24')

    #@unittest.skipIf(self.YK is None, "No USB HID YubiKey found")
    def test_serial(self):
        """ Test serial number retrieval (requires YubiKey 2) """
        serial = self.YK.serial()
        print "Serial returned : %s" % serial
        self.assertEqual(type(serial), type(1))

if __name__ == '__main__':
    unittest.main()

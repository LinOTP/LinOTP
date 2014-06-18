#!/usr/bin/env python
#
# Simple test cases for a Python version of the yubikey_crc16() function in ykcrc.c.
#

import struct
import unittest
import yubico.yubico_util as yubico_util
from yubico.yubico_util import crc16

CRC_OK_RESIDUAL = 0xf0b8

class TestCRC(unittest.TestCase):

    def test_first(self):
        """ Test CRC16 trivial case """
        buffer = '\x01\x02\x03\x04'
        crc = crc16(buffer)
        self.assertEqual(crc, 0xc66e)
        return buffer, crc

    def test_second(self):
        """ Test CRC16 residual calculation """
        buffer, crc = self.test_first()
        # Append 1st complement for a "self-verifying" block -
        # from example in Yubikey low level interface
        crc_inv = 0xffff - crc
        buffer += struct.pack('<H', crc_inv)
        crc2 = crc16(buffer)
        self.assertEqual(crc2, CRC_OK_RESIDUAL)

    def test_hexdump(self):
        """ Test hexdump function, normal use """
        bytes = '\x01\x02\x03\x04\x05\x06\x07\x08'
        self.assertEqual(yubico_util.hexdump(bytes, length=4), \
                             '0000   01 02 03 04\n0004   05 06 07 08\n')

    def test_hexdump(self):
        """ Test hexdump function, with colors """
        bytes = '\x01\x02\x03\x04\x05\x06\x07\x08'
        self.assertEqual(yubico_util.hexdump(bytes, length=4, colorize=True), \
                             '0000   \x1b[0m01 02 03\x1b[0m 04\n0004   \x1b[0m05 06 07\x1b[0m 08\n')

    def test_modhex_decode(self):
        """ Test modhex decoding """
        self.assertEqual("0123456789abcdef", yubico_util.modhex_decode("cbdefghijklnrtuv"))

if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python

from yubico import *
from yubico.yubikey_frame import *
import yubico.yubico_exception
import unittest
import struct
import re

class YubiKeyTests(unittest.TestCase):

  def test_get_ykframe(self):
    """ Test normal use """
    buffer = YubiKeyFrame(command=0x01).to_string()

    # check number of bytes returned
    self.assertEqual(len(buffer), 70, "yubikey command buffer should always be 70 bytes")

    # check that empty payload works (64 * '\x00')
    all_zeros = '\x00' * 64

    self.assertTrue(buffer.startswith(all_zeros))


  def test_get_ykframe_feature_reports(self):
    """ Test normal use """
    res = YubiKeyFrame(command=0x32).to_feature_reports()

    self.assertEqual(res, ['\x00\x00\x00\x00\x00\x00\x00\x80',
                           '\x00\x32\x6b\x5b\x00\x00\x00\x89'
                           ])


  def test_get_ykframe_feature_reports2(self):
    """ Test one serie of non-zero bytes in the middle of the payload """
    payload = '\x00' * 38
    payload += '\x01\x02\x03'
    payload += '\x00' * 23
    res = YubiKeyFrame(command=0x32, payload=payload).to_feature_reports()

    self.assertEqual(res, ['\x00\x00\x00\x00\x00\x00\x00\x80',
                           '\x00\x00\x00\x01\x02\x03\x00\x85',
                           '\x002\x01s\x00\x00\x00\x89'])

  def test_bad_payload(self):
    """ Test that we get an exception for four bytes payload """
    self.assertRaises(yubico_exception.InputError, YubiKeyFrame, command=0x32, payload='test')

  def test_repr(self):
    """ Test string representation of object """
    # to achieve 100% test coverage ;)
    frame = YubiKeyFrame(command=0x4d)
    print "Frame is represented as %s" % frame
    re_match = re.search("YubiKeyFrame instance at .*: 77.$", str(frame))
    self.assertNotEqual(re_match, None)

if __name__ == '__main__':
    unittest.main()

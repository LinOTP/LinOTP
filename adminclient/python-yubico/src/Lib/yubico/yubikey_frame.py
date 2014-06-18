"""
module for creating frames of data that can be sent to a YubiKey
"""
# Copyright (c) 2010, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    # functions
    # classes
    'YubiKeyFrame',
]

import struct

import yubico_util
import yubikey_defs
import yubico_exception
from yubico import __version__

class YubiKeyFrame:
    """
    Class containing an YKFRAME (as defined in ykdef.h).

    A frame is basically 64 bytes of data. When this is to be sent
    to a YubiKey, it is put inside 10 USB HID feature reports. Each
    feature report is 7 bytes of data plus 1 byte of sequencing and
    flags.
    """

    def __init__(self, command, payload=''):
        if payload is '':
            payload = '\x00' * 64
        if len(payload) != 64:
            raise yubico_exception.InputError('payload must be empty or 64 bytes')
        self.payload = payload
        self.command = command
        self.crc = yubico_util.crc16(payload)

    def __repr__(self):
        return '<%s.%s instance at %s: %s>' % (
            self.__class__.__module__,
            self.__class__.__name__,
            hex(id(self)),
            self.command
            )

    def to_string(self):
        """
        Return the frame as a 70 byte string.
        """
        # From ykdef.h :
        #
        # // Frame structure
	# #define SLOT_DATA_SIZE  64
        # typedef struct {
        #     unsigned char payload[SLOT_DATA_SIZE];
        #     unsigned char slot;
        #     unsigned short crc;
        #     unsigned char filler[3];
        # } YKFRAME;
        filler = ''
        return struct.pack('<64sBH3s',
                           self.payload, self.command, self.crc, filler)

    def to_feature_reports(self):
        """
        Return the frame as an array of 8-byte parts, ready to be sent to a YubiKey.
        """
        rest = self.to_string()
        seq = 0
        out = []
        # When sending a frame to the YubiKey, we can (should) remove any
        # 7-byte serie that only consists of '\x00', besides the first
        # and last serie.
        while rest:
            this, rest = rest[:7], rest[7:]
            if seq > 0 and rest:
                # never skip first or last serie
                if this != '\x00\x00\x00\x00\x00\x00\x00':
                    this += chr(yubikey_defs.SLOT_WRITE_FLAG + seq)
                    out.append(this)
            else:
                this += chr(yubikey_defs.SLOT_WRITE_FLAG + seq)
                out.append(this)
            seq += 1
        return out

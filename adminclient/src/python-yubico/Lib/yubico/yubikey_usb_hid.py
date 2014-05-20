"""
module for accessing a USB HID YubiKey
"""

# Copyright (c) 2010, Yubico AB
# All rights reserved.

__all__ = [
  # constants
  # functions
  # classes
  'YubiKeyUSBHID',
  'YubiKeyUSBHIDError'
]

from yubico import __version__

import yubico_util
import yubico_exception
import yubikey_frame
import yubikey_config
import yubikey_defs
from yubikey import YubiKey
import struct
import time
import usb
import sys

# Various USB/HID parameters
_USB_TYPE_CLASS		 = (0x01 << 5)
_USB_RECIP_INTERFACE	 = 0x01
_USB_ENDPOINT_IN	 = 0x80
_USB_ENDPOINT_OUT	 = 0x00

_HID_GET_REPORT		 = 0x01
_HID_SET_REPORT		 = 0x09

_USB_TIMEOUT_MS		 = 100

# from ykcore_backend.h
_FEATURE_RPT_SIZE	 = 8
_REPORT_TYPE_FEATURE	 = 0x03
# from ykdef.h
_YUBICO_VID		 = 0x1050
_YUBIKEY_PID		 = 0x0010
# commands from ykdef.h
_SLOT_DEVICE_SERIAL	 = 0x10  # Device serial number
_SLOT_CHAL_OTP1		 = 0x20  # Write 6 byte challenge to slot 1, get Yubico OTP response
_SLOT_CHAL_OTP2		 = 0x28  # Write 6 byte challenge to slot 2, get Yubico OTP response
_SLOT_CHAL_HMAC1	 = 0x30  # Write 64 byte challenge to slot 1, get HMAC-SHA1 response
_SLOT_CHAL_HMAC2	 = 0x38  # Write 64 byte challenge to slot 2, get HMAC-SHA1 response

# dict used to select command for mode+slot in _challenge_response
_CMD_CHALLENGE = {'HMAC': {1: _SLOT_CHAL_HMAC1, 2: _SLOT_CHAL_HMAC2},
                  'OTP': {1: _SLOT_CHAL_OTP1, 2: _SLOT_CHAL_OTP2},
                  }

class YubiKeyUSBHIDError(yubico_exception.YubicoError):
    """ Exception raised for errors with the USB HID communication. """

class YubiKeyUSBHID(YubiKey):
    """
    Class for accessing a YubiKey over USB HID.

    This class is for communicating specifically with the YubiKeys
    presenting themselves as USB HID interfaces (the only ones available
    as of 2011).

    Tested with YubiKey versions 1.3 and 2.2.
    """

    def __init__(self, debug=False, skip=0):
        """
        Find and connect to a USB HIB YubiKey.

        Attributes :
            skip  -- number of YubiKeys to skip
            debug -- True or False
        """
        YubiKey.__init__(self, debug)
        self._usb_handle = None
        if not self._open(skip):
            raise YubiKeyUSBHIDError('YubiKey USB HID initialization failed')
        self.status()

    def __del__(self):
        YubiKey.__del__(self)
        try:
            if self._usb_handle:
                self._close()
        except usb.USBError:
            pass

    def __repr__(self):
        return '<%s instance at %s: YubiKey version %s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.version()
            )

    def status(self):
        """
        Poll YubiKey for status.

        Updates a bunch of attributes, such as the pgm_seq number, and returns
        the status byte, where you can check for yubikey_defs.SLOT_WRITE_FLAG etc.
        """
        data = self._read()
        # From ykdef.h :
        #
        # struct status_st {
        #        unsigned char versionMajor;     /* Firmware version information */
        #        unsigned char versionMinor;
        #        unsigned char versionBuild;
        #        unsigned char pgmSeq;           /* Programming sequence number. 0 if no valid configuration */
        #        unsigned short touchLevel;      /* Level from touch detector */
        # };
        version_major, \
            version_minor, \
            version_build, \
            self.pgm_seq, \
            self.touch_level, \
            flags = struct.unpack('<xBBBBHB', data)
        self.ykver = (version_major, version_minor, version_build)
        return flags

    def version_num(self):
        """ Get the YubiKey version as a tuple with integers. """
        return self.ykver

    def version(self):
        """ Get the YubiKey version. """
        version = "%d.%d.%d" % self.ykver
        return version

    def serial(self):
        """ Get the YubiKey serial number (requires YubiKey 2). """
        if self.version_num() < (2, 0, 0):
            raise YubiKeyUSBHIDError("Serial number unsupported in YubiKey %s" % self.version())
        return self._read_serial()

    def challenge_response(self, challenge, mode='HMAC', slot=1):
        """ Issue a challenge to the YubiKey and return the response (requires YubiKey 2). """
        if self.version_num() < (2, 0, 0):
            raise YubiKeyUSBHIDError("Challenge response unsupported in YubiKey %s" % self.version())
        return self._challenge_response(challenge, mode, slot)

    def init_config(self):
        """ Get a configuration object for this type of YubiKey. """
        return yubikey_config.YubiKeyConfigUSBHID(ykver=self.version_num())

    def write_config(self, cfg, slot=1):
        """ Write a configuration to the YubiKey. """
        cfg_req_ver = cfg.version_required()
        if cfg_req_ver > self.version_num():
            raise YubiKeyUSBHIDError('Configuration requires YubiKey version %i.%i (this is %s)' % \
                                         (cfg_major, cfg_minor, self.version()))
        return self._write_config(cfg, slot)

    def _read_serial(self):
        """ Read the serial number from a YubiKey > 2.0. """

        frame = yubikey_frame.YubiKeyFrame(command=_SLOT_DEVICE_SERIAL)
        self._write(frame)
        response = self._read_response()
        if not yubico_util.validate_crc16(response[:6]):
            raise YubiKeyUSBHIDError("Read from device failed CRC check")
        # the serial number is big-endian, although everything else is little-endian
        serial = struct.unpack('>lxxx', response)
        return serial[0]

    def _challenge_response(self, challenge, mode, slot):
        """ Do challenge-response with a YubiKey > 2.0. """
        try:
            command = _CMD_CHALLENGE[mode][slot]
        except:
            raise YubiKeyUSBHIDError('Invalid slot (%s) or mode (%s) specified' % (slot, mode))

        frame = yubikey_frame.YubiKeyFrame(command=command, payload=challenge)
        self._write(frame)
        response = self._read_response(may_block=True)
        if not yubico_util.validate_crc16(response[:22]):
            raise YubiKeyUSBHIDError("Read from device failed CRC check")
        return response[:20]

    def _write_config(self, cfg, slot):
        """ Write configuration to YubiKey. """
        old_pgm_seq = self.pgm_seq
        frame = cfg.to_frame(slot=slot)
        self._write(frame)
        self._waitfor_clear(yubikey_defs.SLOT_WRITE_FLAG)
        # make sure we have a fresh pgm_seq value
        self.status()
        if self.pgm_seq != old_pgm_seq + 1:
            raise YubiKeyUSBHIDError('YubiKey programming failed (seq %i not increased (%i))' % \
                                         (old_pgm_seq, self.pgm_seq))

    def _read_response(self, may_block=False):
        """ Wait for a response to become available, and read it. """
        # wait for response to become available
        res = self._waitfor_set(yubikey_defs.RESP_PENDING_FLAG, may_block)[:7]
        # continue reading while response pending is set
        while True:
            this = self._read()
            flags = ord(this[7])
            if flags & yubikey_defs.RESP_PENDING_FLAG:
                seq = flags & 0b00011111
                if res and (seq == 0):
                    break
                res += this[:7]
            else:
                break
        self._write_reset()
        return res

    def _read(self):
        """ Read a USB HID feature report from the YubiKey. """
        request_type = _USB_TYPE_CLASS | _USB_RECIP_INTERFACE | _USB_ENDPOINT_IN
        value = _REPORT_TYPE_FEATURE << 8  # apparently required for YubiKey 1.3.2, but not 2.2.x
        recv = self._usb_handle.controlMsg(request_type,
                                          _HID_GET_REPORT,
                                          _FEATURE_RPT_SIZE,
                                          value=value,
                                          timeout=_USB_TIMEOUT_MS)
        if len(recv) != _FEATURE_RPT_SIZE:
            if self.debug:
                sys.stderr.write("Failed reading %i bytes (got %i) from USB HID YubiKey.\n"
                                 % (_FEATURE_RPT_SIZE, recv))
            raise YubiKeyUSBHIDError('Failed reading from USB HID YubiKey')
        data = ''.join(chr(c) for c in recv)
        self._debug("YubiKey USB HID: READ  : %s" % yubico_util.hexdump(data, colorize=True))
        return data

    def _write(self, frame):
        """
        Write a YubiKeyFrame to the USB HID.

        Includes polling for YubiKey readiness before each write.
        """
        for data in frame.to_feature_reports():
            # first, we ensure the YubiKey will accept a write
            self._waitfor_clear(yubikey_defs.SLOT_WRITE_FLAG)
            self._raw_write(data)
        return True

    def _write_reset(self):
        """
        Reset read mode by issuing a dummy write.
        """
        data = '\x00\x00\x00\x00\x00\x00\x00\x8f'
        self._raw_write(data)
        self._waitfor_clear(yubikey_defs.SLOT_WRITE_FLAG)
        return True

    def _raw_write(self, data):
        """
        Write data to YubiKey.
        """
        self._debug("YubiKey USB HID: WRITE : %s" % yubico_util.hexdump(data, colorize=True))
        request_type = _USB_TYPE_CLASS | _USB_RECIP_INTERFACE | _USB_ENDPOINT_OUT
        value = _REPORT_TYPE_FEATURE << 8  # apparently required for YubiKey 1.3.2, but not 2.2.x
        sent = self._usb_handle.controlMsg(request_type,
                                          _HID_SET_REPORT,
                                          data,
                                          value=value,
                                          timeout=_USB_TIMEOUT_MS)
        if sent != _FEATURE_RPT_SIZE:
            self.debug("Failed writing %i bytes (wrote %i) to USB HID YubiKey.\n"
                       % (_FEATURE_RPT_SIZE, sent))
            raise YubiKeyUSBHIDError('Failed talking to USB HID YubiKey')
        return sent

    def _waitfor_clear(self, mask, may_block=False):
        """
        Wait for the YubiKey to turn OFF the bits in 'mask' in status responses.

        Returns the 8 bytes last read.
        """
        return self._waitfor('nand', mask, may_block)

    def _waitfor_set(self, mask, may_block=False):
        """
        Wait for the YubiKey to turn ON the bits in 'mask' in status responses.

        Returns the 8 bytes last read.
        """
        return self._waitfor('and', mask, may_block)

    def _waitfor(self, mode, mask, may_block, timeout=2):
        """
        Wait for the YubiKey to either turn ON or OFF certain bits in the status byte.

        mode is either 'and' or 'nand'
        timeout is a number of seconds (precision about ~0.5 seconds)
        """
        finished = False
        sleep = 0.01
        # After six sleeps, we've slept 0.64 seconds.
        wait_num = (timeout * 2) - 1 + 6
        resp_timeout = False  # YubiKey hasn't indicated RESP_TIMEOUT (yet)
        while not finished:
            this = self._read()
            flags = ord(this[7])

            if flags & yubikey_defs.RESP_TIMEOUT_WAIT_FLAG:
                if not resp_timeout:
                    resp_timeout = True
                    seconds_left = flags & yubikey_defs.RESP_TIMEOUT_WAIT_MASK
                    self._debug("YubiKey USB HID: Device indicates RESP_TIMEOUT (%i seconds left)\n"
                                % (seconds_left))
                    if may_block:
                        # calculate new wait_num - never more than 20 seconds
                        seconds_left = min(20, seconds_left)
                        wait_num = (seconds_left * 2) - 1 + 6

            if mode is 'nand':
                if not flags & mask == mask:
                    finished = True
                else:
                    self._debug("YubiKey USB HID: Status %s (0x%x) fails NAND %s (0x%x)\n"
                                % (bin(flags), flags, bin(mask), mask))
            elif mode is 'and':
                if flags & mask == mask:
                    finished = True
                else:
                    self._debug("YubiKey USB HID: Status %s (0x%x) fails AND %s (0x%x)\n"
                                % (bin(flags), flags, bin(mask), mask))
            else:
                assert()

            if not finished:
                wait_num -= 1
                if wait_num == 0:
                    if mode is 'nand':
                        reason = 'Timed out waiting for YubiKey to clear status 0x%x' % mask
                    else:
                        reason = 'Timed out waiting for YubiKey to set status 0x%x' % mask
                    raise yubikey.YubiKeyTimeout(reason)
                time.sleep(sleep)
                sleep = min(sleep + sleep, 0.5)
            else:
                return this

    def _open(self, skip=0):
        """ Perform HID initialization """
        usb_device = self._get_usb_device(skip)

        if usb_device:
            usb_conf = usb_device.configurations[0]
            usb_int = usb_conf.interfaces[0][0]
        else:
            raise YubiKeyUSBHIDError('No USB YubiKey found')

        try:
            self._usb_handle = usb_device.open()
            self._usb_handle.detachKernelDriver(0)
        except usb.USBError as  error:
            if 'could not detach kernel driver from interface' in str(error):
                self._debug('The in-kernel-HID driver has already been detached\n')
            else:
                raise

        self._usb_handle.setConfiguration(1)
        self._usb_handle.claimInterface(usb_int)
        return True

    def _get_usb_device(self, skip=0):
        """
        Get YubiKey USB device.

        Optionally allows you to skip n devices, to support multiple attached YubiKeys.
        """
        for bus in usb.busses():
            for device in bus.devices:
                if device.idVendor == _YUBICO_VID and device.idProduct == _YUBIKEY_PID:
                    if skip == 0:
                        return device
                    skip -= 1
        return None

    def _close(self):
        """ Perform HID cleanup """
        self._usb_handle.releaseInterface()

    def _debug(self, out):
        """ Print out to stderr, if debugging is enabled. """
        if self.debug:
            sys.stderr.write(out)

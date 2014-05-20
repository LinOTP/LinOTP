"""
module for configuring YubiKeys
"""
# Copyright (c) 2010, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    'TTicketFlags',
    # functions
    # classes
    'YubiKeyConfigUSBHID',
]

from yubico import __version__

import struct
import binascii
import yubico_util
import yubikey_frame
import yubico_exception
import yubikey_config_util
from yubikey_config_util import YubiKeyConfigBits, YubiKeyConfigFlag, YubiKeyExtendedFlag, YubiKeyTicketFlag

TicketFlags = [
    YubiKeyTicketFlag('TAB_FIRST', 		0x01, min_ykver=(1, 0), doc='Send TAB before first part'),
    YubiKeyTicketFlag('APPEND_TAB1', 		0x02, min_ykver=(1, 0), doc='Send TAB after first part'),
    YubiKeyTicketFlag('APPEND_TAB2', 		0x04, min_ykver=(1, 0), doc='Send TAB after second part'),
    YubiKeyTicketFlag('APPEND_DELAY1', 		0x08, min_ykver=(1, 0), doc='Add 0.5s delay after first part'),
    YubiKeyTicketFlag('APPEND_DELAY2', 		0x10, min_ykver=(1, 0), doc='Add 0.5s delay after second part'),
    YubiKeyTicketFlag('APPEND_CR', 		0x20, min_ykver=(1, 0), doc='Append CR as final character'),
    YubiKeyTicketFlag('OATH_HOTP', 		0x40, min_ykver=(2, 1), doc='Choose OATH-HOTP mode'),
    YubiKeyTicketFlag('CHAL_RESP', 		0x40, min_ykver=(2, 2), doc='Choose Challenge-Response mode'),
    YubiKeyTicketFlag('PROTECT_CFG2', 		0x80, min_ykver=(2, 0), doc='Protect configuration in slot 2'),
    ]

ConfigFlags = [
    YubiKeyConfigFlag('SEND_REF', 		0x01, min_ykver=(1, 0), doc='Send reference string (0..F) before data'),
    YubiKeyConfigFlag('TICKET_FIRST', 		0x02, min_ykver=(1, 0), doc='Send ticket first (default is fixed part)', max_ykver=(1, 9)),
    YubiKeyConfigFlag('PACING_10MS', 		0x04, min_ykver=(1, 0), doc='Add 10ms intra-key pacing'),
    YubiKeyConfigFlag('PACING_20MS', 		0x08, min_ykver=(1, 0), doc='Add 20ms intra-key pacing'),
    #YubiKeyConfigFlag('ALLOW_HIDTRIG',		0x10, min_ykver=(1, 0), doc='DONT USE: Allow trigger through HID/keyboard', max_ykver=(1, 9)),
    YubiKeyConfigFlag('STATIC_TICKET', 		0x20, min_ykver=(1, 0), doc='Static ticket generation'),

    # YubiKey 2.0 and above
    YubiKeyConfigFlag('SHORT_TICKET', 		0x02, min_ykver=(2, 0), doc='Send truncated ticket (half length)'),
    YubiKeyConfigFlag('STRONG_PW1', 		0x10, min_ykver=(2, 0), doc='Strong password policy flag #1 (mixed case)'),
    YubiKeyConfigFlag('STRONG_PW2', 		0x40, min_ykver=(2, 0), doc='Strong password policy flag #2 (subtitute 0..7 to digits)'),
    YubiKeyConfigFlag('MAN_UPDATE', 		0x80, min_ykver=(2, 0), doc='Allow manual (local) update of static OTP'),

    # YubiKey 2.1 and above
    YubiKeyConfigFlag('OATH_HOTP8', 		0x02, min_ykver=(2, 1), mode='OATH', doc='Generate 8 digits HOTP rather than 6 digits'),
    YubiKeyConfigFlag('OATH_FIXED_MODHEX1', 	0x10, min_ykver=(2, 1), mode='OATH', doc='First byte in fixed part sent as modhex'),
    YubiKeyConfigFlag('OATH_FIXED_MODHEX2', 	0x40, min_ykver=(2, 1), mode='OATH', doc='First two bytes in fixed part sent as modhex'),
    YubiKeyConfigFlag('OATH_FIXED_MODHEX', 	0x50, min_ykver=(2, 1), mode='OATH', doc='Fixed part sent as modhex'),
    YubiKeyConfigFlag('OATH_FIXED_MASK', 	0x50, min_ykver=(2, 1), mode='OATH', doc='Mask to get out fixed flags'),

    # YubiKey 2.2 and above
    YubiKeyConfigFlag('CHAL_YUBICO', 		0x20, min_ykver=(2, 2), mode='CHAL', doc='Challenge-response enabled - Yubico OTP mode'),
    YubiKeyConfigFlag('CHAL_HMAC', 		0x22, min_ykver=(2, 2), mode='CHAL', doc='Challenge-response enabled - HMAC-SHA1'),
    YubiKeyConfigFlag('HMAC_LT64', 		0x04, min_ykver=(2, 2), mode='CHAL', doc='Set when HMAC message is less than 64 bytes'),
    YubiKeyConfigFlag('CHAL_BTN_TRIG', 		0x08, min_ykver=(2, 2), mode='CHAL', doc='Challenge-respoonse operation requires button press'),
    ]

ExtendedFlags = [
    YubiKeyExtendedFlag('SERIAL_BTN_VISIBLE', 	0x01, min_ykver=(2, 2), doc='Serial number visible at startup (button press)'),
    YubiKeyExtendedFlag('SERIAL_USB_VISIBLE', 	0x02, min_ykver=(2, 2), doc='Serial number visible in USB iSerial field'),
    YubiKeyExtendedFlag('SERIAL_API_VISIBLE', 	0x04, min_ykver=(2, 2), doc='Serial number visible via API call'),
    ]

SLOT_CONFIG			 = 0x01  # First (default / V1) configuration
SLOT_CONFIG2			 = 0x03  # Second (V2) configuration

class YubiKeyConfigError(yubico_exception.YubicoError):
    """
    Exception raised for YubiKey configuration errors.
    """

class YubiKeyConfig():
    """
    Base class for configuration of all types of YubiKeys, present and future.
    """

    def __init__(self, ykver=None):
        # Minimum version of YubiKey this configuration will require
        self.yk_req_version = (1, 3)
        self.ykver = ykver

        self.fixed = ''
        self.uid = ''
        self.key = ''
        self.access_code = ''
        self.ticket_flags = YubiKeyConfigBits(0x0)
        self.config_flags = YubiKeyConfigBits(0x0)
        self.extended_flags = YubiKeyConfigBits(0x0)

        self.unlock_code = ''
        self._mode = ''

        return None

    def version_required(self):
        """
        Return the (major, minor) versions of YubiKey required for this configuration.
        """
        return self.yk_req_version

    def fixed_string(self, data=None):
        """
        The fixed string is used to identify a particular Yubikey device.

        The fixed string is referred to as the 'Token Identifier' in OATH-HOTP mode.

        The length of the fixed string can be set between 0 and 16 bytes.

        Tip: This can also be used to extend the length of a static password.
        """
        old = self.fixed
        if data != None:
            new = self._decode_input_string(data)
            if len(new) <= 16:
                self.fixed = new
            else:
                raise yubico_exception.InputError('The "fixed" string must be 0..16 bytes')
        return old

    def enable_extended_scan_code_mode(self):
        """
        Extended scan code mode means the Yubikey will output the bytes in
        the 'fixed string' as scan codes, without modhex encoding the data.

        Because of the way this is stored in the config flags, it is not
        possible to disable this option once it is enabled (of course, you
        can abort config update or reprogram the YubiKey again).

        Requires YubiKey 2.x.
        """
        self._require_version(major=2)
        self.config_flag('SHORT_TICKET', True)
        self.config_flag('STATIC_TICKET', False)

    def enable_shifted_1(self):
        """
        This will cause a shifted character 1 (typically '!') to be sent before
        anything else. This can be used to make the YubiKey output qualify as a
        password with 'special characters', if such is required.

        Because of the way this is stored in the config flags, it is not
        possible to disable this option once it is enabled (of course, you
        can abort config update or reprogram the YubiKey again).

        Requires YubiKey 2.x.
        """
        self._require_version(major=2)
        self.config_flag('STRONG_PW2', True)
        self.config_flag('SEND_REF', True)

    def aes_key(self, data):
        """
        AES128 key to program into YubiKey.

        Supply data as either a raw string, or a hexlified string prefixed by 'h:'.
        The result, after any hex decoding, must be 16 bytes.
        """
        old = self.key
        if data:
            new = self._decode_input_string(data)
            if len(new) == 16:
                self.key = new
            else:
                raise yubico_exception.InputError('AES128 key must be exactly 16 bytes')

        return old

    def unlock_key(self, data):
        """
        Access code to allow re-program your YubiKey.

        Supply data as either a raw string, or a hexlified string prefixed by 'h:'.
        The result, after any hex decoding, must be 6 bytes.
        """
        if data.startswith('h:'):
            new = binascii.unhexlify(data[2:])
        else:
            new = data
        if len(new) == 6:
            self.unlock_code = new
            if not self.access_code:
                # Don't reset the access code when programming, unless that seems
                # to be the intent of the calling program.
                self.access_code = new
        else:
            raise yubico_exception.InputError('Unlock key must be exactly 6 bytes')

    def access_key(self, data):
        """
        Set a new access code which will be required for future re-programmings of your YubiKey.

        Supply data as either a raw string, or a hexlified string prefixed by 'h:'.
        The result, after any hex decoding, must be 6 bytes.
        """
        if data.startswith('h:'):
            new = binascii.unhexlify(data[2:])
        else:
            new = data
        if len(new) == 6:
            self.access_code = new
        else:
            raise yubico_exception.InputError('Access key must be exactly 6 bytes')

    def mode_oath_hotp(self, secret, bytes=6, factor_seed=None, omp=0x0, tt=0x0, mui=''):
        """
        Set the YubiKey up for OATH-HOTP operation.

        Requires YubiKey 2.1.
        """
        if bytes != 6 and bytes != 8:
            raise InputError('OATH-HOTP bytes must be 6 or 8')

        self._change_mode('OATH_HOTP', major=2, minor=1)
        self._set_20_bytes_key(secret)
        if bytes == 8:
            self.config_flag('OATH_HOTP8', True)
        if omp or tt or mui:
            decoded_mui = self._decode_input_string(mui)
            fixed = chr(omp) + chr(tt) + decoded_mui
            self.fixed_string(fixed)
        if factor_seed:
            self.uid = self.uid + struct.pack('<H', factor_seed)

    def mode_challenge_response(self, secret, type='HMAC', variable=True, require_button=False):
        """
        Set the YubiKey up for challenge-response operation.

        type can be 'HMAC' or 'Yubico'.

        variable is only applicable to type 'HMAC'.

        Requires YubiKey 2.2.
        """
        self._change_mode('CHAL_RESP', major=2, minor=2)
        if type.upper() == 'HMAC':
            self.config_flag('CHAL_HMAC', True)
            self.config_flag('HMAC_LT64', variable)
        elif type.lower() == 'yubico':
            self.config_flag('CHAL_YUBICO', True)
        else:
            raise yubico_exception.InputError('Invalid \'type\' (%s)' % type)
        self.config_flag('CHAL_BTN_TRIG', require_button)
        self._set_20_bytes_key(secret)

    def ticket_flag(self, which, new=None):
        """
        Get or set a ticket flag.

        'which' can be either a string ('APPEND_CR' etc.), or an integer.
        You should ALWAYS use a string, unless you really know what you are doing.
        """
        flag = _get_flag(which, TicketFlags)
        if flag:
            req_major, req_minor = flag.req_version()
            if self.ykver and not flag.is_compatible_ver(self.ykver):
                raise YubiKeyConfigError('Ticket flag %s requires YubiKey %d.%d, and this is %d.%d'
                                         % (which, req_major, req_minor, self.ykver[0], self.ykver[1]))
            self._require_version(major=req_major, minor=req_minor)
            value = flag.to_integer()
        else:
            if type(which) is not int:
                raise yubico_exception.InputError('Unknown non-integer TicketFlag (%s)' % which)
            value = which

        return self.ticket_flags.get_set(value, new)

    def config_flag(self, which, new=None):
        """
        Get or set a config flag.

        'which' can be either a string ('APPEND_CR' etc.), or an integer.
        You should ALWAYS use a string, unless you really know what you are doing.
        """
        flag = _get_flag(which, ConfigFlags)
        if flag:
            req_major, req_minor = flag.req_version()
            if self.ykver and not flag.is_compatible_ver(self.ykver):
                raise YubiKeyConfigError('Config flag %s requires YubiKey %d.%d, and this is %d.%d'
                                         % (which, req_major, req_minor, self.ykver[0], self.ykver[1]))
            self._require_version(major=req_major, minor=req_minor)
            value = flag.to_integer()
        else:
            if type(which) is not int:
                raise yubico_exception.InputError('Unknown non-integer ConfigFlag (%s)' % which)
            value = which

        return self.config_flags.get_set(value, new)

    def extended_flag(self, which, new=None):
        """
        Get or set a extended flag.

        'which' can be either a string ('APPEND_CR' etc.), or an integer.
        You should ALWAYS use a string, unless you really know what you are doing.
        """
        flag = _get_flag(which, ExtendedFlags)
        if flag:
            req_major, req_minor = flag.req_version()
            if self.ykver and not flag.is_compatible_ver(self.ykver):
                raise YubiKeyConfigError('Config flag %s requires YubiKey %d.%d, and this is %d.%d'
                                         % (which, req_major, req_minor, self.ykver[0], self.ykver[1]))
            self._require_version(major=req_major, minor=req_minor)
            value = flag.to_integer()
        else:
            if type(which) is not int:
                raise yubico_exception.InputError('Unknown non-integer ExtendedFlag (%s)' % which)
            value = which

        return self.extended_flags.get_set(value, new)

    def to_string(self):
        """
        Return the current configuration as a string (always 64 bytes).
        """
        #define UID_SIZE		6	/* Size of secret ID field */
        #define FIXED_SIZE              16      /* Max size of fixed field */
        #define KEY_SIZE                16      /* Size of AES key */
        #define KEY_SIZE_OATH           20      /* Size of OATH-HOTP key (key field + first 4 of UID field) */
        #define ACC_CODE_SIZE           6       /* Size of access code to re-program device */
        #
        #struct config_st {
        #    unsigned char fixed[FIXED_SIZE];/* Fixed data in binary format */
        #    unsigned char uid[UID_SIZE];    /* Fixed UID part of ticket */
        #    unsigned char key[KEY_SIZE];    /* AES key */
        #    unsigned char accCode[ACC_CODE_SIZE]; /* Access code to re-program device */
        #    unsigned char fixedSize;        /* Number of bytes in fixed field (0 if not used) */
        #    unsigned char extFlags;         /* Extended flags */
        #    unsigned char tktFlags;         /* Ticket configuration flags */
        #    unsigned char cfgFlags;         /* General configuration flags */
        #    unsigned char rfu[2];           /* Reserved for future use */
        #    unsigned short crc;             /* CRC16 value of all fields */
        #};
        t_rfu = 0

        first = struct.pack('<16s6s16s6sBBBBH',
                            self.fixed,
                            self.uid,
                            self.key,
                            self.access_code,
                            len(self.fixed),
                            self.extended_flags.to_integer(),
                            self.ticket_flags.to_integer(),
                            self.config_flags.to_integer(),
                            t_rfu
                            )

        crc = 0xffff - yubico_util.crc16(first)

        second = first + struct.pack('<H', crc) + self.unlock_code
        return second

    def to_frame(self, slot=1):
        """
        Return the current configuration as a YubiKeyFrame object.
        """
        data = self.to_string()
        payload = data.ljust(64, chr(0x0))
        if slot is 1:
            command = SLOT_CONFIG
        elif slot is 2:
            command = SLOT_CONFIG2
        else:
            assert()
        return yubikey_frame.YubiKeyFrame(command=command, payload=payload)

    def _require_version(self, major, minor=0):
        """ Update the minimum version of YubiKey this configuration can be applied to. """
        new_ver = (major, minor)
        if self.ykver and new_ver > self.ykver:
            raise YubiKeyConfigError('Configuration requires YubiKey %d.%d, and this is %d.%d'
                                     % (major, minor, self.ykver[0], self.ykver[1]))
        if new_ver > self.yk_req_version:
            self.yk_req_version = new_ver

    def _decode_input_string(self, data):
        if data.startswith('m:'):
            data = 'h:' + yubico_util.modhex_decode(data[2:])
        if data.startswith('h:'):
            return(binascii.unhexlify(data[2:]))
        else:
            return(data)

    def _change_mode(self, mode, major, minor):
        """ Change mode of operation, with some sanity checks. """
        if self._mode:
            if self._mode != mode:
                raise RuntimeError('Can\'t change mode (from %s to %s)' % (self._mode, this_mode))
        self._require_version(major=major, minor=minor)
        self._mode = mode
        # when setting mode, we reset all flags
        self.ticket_flags = YubiKeyConfigBits(0x0)
        self.config_flags = YubiKeyConfigBits(0x0)
        self.extended_flags = YubiKeyConfigBits(0x0)
        self.ticket_flag(mode, True)

    def _set_20_bytes_key(self, data):
        """
        Set a 20 bytes key. This is used in CHAL_HMAC and OATH_HOTP mode.

        Supply data as either a raw string, or a hexlified string prefixed by 'h:'.
        The result, after any hex decoding, must be 20 bytes.
        """
        if data.startswith('h:'):
            new = binascii.unhexlify(data[2:])
        else:
            new = data
        if len(new) == 20:
            self.key = new[:16]
            self.uid = new[16:]
        else:
            raise yubico_exception.InputError('HMAC key must be exactly 20 bytes')

class YubiKeyConfigUSBHID(YubiKeyConfig):
    """
    Configuration class for USB HID YubiKeys.
    """
    def __init__(self, ykver=None):
        YubiKeyConfig.__init__(self, ykver)
        return None

def _get_flag(which, flags):
    """ Find 'which' entry in 'flags'. """
    res = [this for this in flags if this.is_equal(which)]
    if len(res) == 0:
        return None
    if len(res) == 1:
        return res[0]
    assert()

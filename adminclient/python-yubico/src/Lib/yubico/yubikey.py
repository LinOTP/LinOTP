"""
module for accessing a YubiKey

In an attempt to support any future versions of the YubiKey which
might not be USB HID devices, you should always use the yubikey.find_key()
function to initialize communication with YubiKeys.

Example usage :

    import yubico.yubikey

    try:
        YK = yubico.yubikey.find_key()
        print "Version : %s " % YK.version()
    except yubico.yubico_exception.YubicoError as inst:
        print "ERROR: %s" % inst.reason
"""
# Copyright (c) 2010, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    'RESP_TIMEOUT_WAIT_FLAG',
    'RESP_PENDING_FLAG',
    'SLOT_WRITE_FLAG',
    # functions
    'find_key',
    # classes
    'YubiKey',
    'YubiKeyTimeout',
]

from yubico  import __version__
import yubico_exception

class YubiKeyError(yubico_exception.YubicoError):
    """
    Exception raised concerning YubiKey operations.

    Attributes:
        reason -- explanation of the error
    """
    def __init__(self, reason='no details'):
        yubico_exception.YubicoError.__init__(self, reason)

class YubiKeyTimeout(YubiKeyError):
    """
    Exception raised when a YubiKey operation timed out.

    Attributes:
        reason -- explanation of the error
    """
    def __init__(self, value='no details'):
        YubiKeyError.__init__(self, reason)


class YubiKey():
    """
    Base class for accessing YubiKeys
    """

    def __init__(self, debug):
        self.debug = debug
        return None

    def __del__(self):
        return None

    def version(self):
        """ Get the connected YubiKey's version as a string. """
        pass

    def serial(self):
        """ Get the connected YubiKey's serial number. """
        pass

    def challenge(self, challenge, mode='HMAC', slot=1):
        """ Get the response to a challenge from a connected YubiKey's. """
        pass

    def init_config(self):
        """
        Return a YubiKey configuration object for this type of YubiKey.
        """
        pass

    def write_config(self, cfg, slot):
        """
        Configure a YubiKey using a configuration object.
        """
        pass

# Since YubiKeyUSBHID is a subclass of YubiKey (defined here above),
# the import must be after the declaration of YubiKey. We also carefully
# import only what we need to not get a circular import of modules.
from yubikey_usb_hid import YubiKeyUSBHID, YubiKeyUSBHIDError

def find_key(debug=False, skip=0):
    """
    Locate a connected YubiKey. Throws an exception if none is found.

    This function is supposed to be possible to extend if any other YubiKeys
    appear in the future.

    Attributes :
        skip  -- number of YubiKeys to skip
        debug -- True or False
    """
    try:
        return YubiKeyUSBHID(debug=debug, skip=skip)
    except YubiKeyUSBHIDError as inst:
        if 'No USB YubiKey found' in str(inst):
            # generalize this error
            raise YubiKeyError('No YubiKey found')
        else:
            raise

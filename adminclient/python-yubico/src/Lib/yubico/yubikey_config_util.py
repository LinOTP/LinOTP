"""
utility functions used in yubikey_config.
"""
# Copyright (c) 2010, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    # functions
    # classes
    'YubiKeyConfigBits',
    'YubiKeyConfigFlag',
    'YubiKeyExtendedFlag',
    'YubiKeyTicketFlag',
]

class YubiKeyFlag():
    """
    A flag value, and associated metadata.
    """

    def __init__(self, key, value, doc=None, min_ykver=(0, 0), max_ykver=None):
        if type(key) is not str:
            assert()
        if type(value) is not int:
            assert()
        if type(min_ykver) is not tuple:
            assert()

        self.key = key
        self.value = value
        self.doc = doc
        self.min_ykver = min_ykver
        self.max_ykver = max_ykver

        return None

    def __repr__(self):
        return '<%s instance at %s: %s (0x%x)>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.key,
            self.value
            )

    def is_equal(self, key):
        """ Check if key is equal to that of this instance """
        return self.key == key

    def to_integer(self):
        """ Return flag value """
        return self.value

    def req_version(self):
        """ Return the minimum required version """
        return self.min_ykver

    def is_compatible_ver(self, ver):
        """ Check if this flag is compatible with a YubiKey of version 'ver'. """
        if self.max_ykver:
            return (ver >= self.min_ykver and
                    ver <= self.max_ykver)
        else:
            return ver >= self.min_ykver

class YubiKeyTicketFlag(YubiKeyFlag):
    """
    A ticket flag value, and associated metadata.
    """

class YubiKeyConfigFlag(YubiKeyFlag):
    """
    A config flag value, and associated metadata.
    """

    def __init__(self, key, value, mode='', doc=None, min_ykver=(0, 0), max_ykver=None):
        if type(mode) is not str:
            assert()
        self.mode = mode

        return YubiKeyFlag.__init__(self, key, value, doc=doc, min_ykver=min_ykver, max_ykver=max_ykver)

class YubiKeyExtendedFlag(YubiKeyFlag):
    """
    An extended flag value, and associated metadata.
    """

    def __init__(self, key, value, mode='', doc=None, min_ykver=(2, 2), max_ykver=None):
        if type(mode) is not str:
            assert()
        self.mode = mode

        return YubiKeyFlag.__init__(self, key, value, doc=doc, min_ykver=min_ykver, max_ykver=max_ykver)

class YubiKeyConfigBits():
    """
    Class to hold bit values for configuration.
    """
    def __init__(self, default=0x0):
        self.value = default
        return None

    def __repr__(self):
        return '<%s instance at %s: value 0x%x>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.key
            )

    def get_set(self, flag, new):
        """
        Return the boolean value of 'flag'. If 'new' is set,
        the flag is updated, and the value before update is
        returned.
        """
        old = self._is_set(flag)
        if new is True:
            self._set(flag)
        elif new is False:
            self._clear(flag)
        return old

    def to_integer(self):
        """ Return the sum of all flags as an integer. """
        return self.value

    def _is_set(self, flag):
        """ Check if flag is set. Returns True or False. """
        return self.value & flag == flag

    def _set(self, flag):
        """ Set flag. """
        self.value |= flag

    def _clear(self, flag):
        """ Clear flag. """
        self.value &= (0xff - flag)

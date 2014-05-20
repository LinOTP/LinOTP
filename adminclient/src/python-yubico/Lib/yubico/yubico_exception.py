"""
class for exceptions used in the other Yubico modules

All exceptions raised by the different Yubico modules are inherited
from the base class YubicoError. That means you can trap them all,
without knowing the details, with code like this :

    try:
        # something Yubico related
    except yubico.yubico_exception.YubicoError as inst:
        print "ERROR: %s" % inst.reason
"""
# Copyright (c) 2010, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    # functions
    # classes
    'YubicoError',
    'InputError',
    'YubiKeyTimeout',
]

from yubico import __version__

class YubicoError(Exception):
    """
    Base class for Yubico exceptions in this module.

    Attributes:
        reason -- explanation of the error
    """

    def __init__(self, reason):
        self.reason = reason

    def __str__(self):
        return '<%s instance at %s: %s>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.reason
            )

    pass

class InputError(YubicoError):
    """
    Exception raised for errors in an input to some function.
    """
    def __init__(self, reason='input validation error'):
        YubicoError.__init__(self, reason)

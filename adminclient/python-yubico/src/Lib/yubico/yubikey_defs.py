"""
Module with constants. Many of them from ykdefs.h.
"""
# Copyright (c) 2010, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    'RESP_TIMEOUT_WAIT_MASK',
    'RESP_TIMEOUT_WAIT_FLAG',
    'RESP_PENDING_FLAG',
    'SLOT_WRITE_FLAG',
    # functions
    # classes
]

from yubico import __version__

# Yubikey Low level interface #2.3
RESP_TIMEOUT_WAIT_MASK	 = 0x1f  # Mask to get timeout value
RESP_TIMEOUT_WAIT_FLAG	 = 0x20  # Waiting for timeout operation - seconds left in lower 5 bits
RESP_PENDING_FLAG	 = 0x40  # Response pending flag
SLOT_WRITE_FLAG		 = 0x80  # Write flag - set by app - cleared by device

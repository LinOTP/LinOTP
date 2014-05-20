# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
"""prototype of the yubico hsm - should be moved into the lib/security!!"""

import pyhsm
import logging

log = logging.getLogger(__name__)

class YubiHSM(object):

    def __init__(self, key_handle, device="/dev/ttyACM0", debug=False, password=""):
        log.debug("initialize YubiHSM object with key handle %s on device %s" %
                    (key_handle, device))
        self.key_handle = key_handle
        self.device = device
        self.debug = debug
        self.password = ""
        self.hsm = pyhsm.base.YHSM(device=self.device, debug=self.debug)
        if "" != password:
            self.unlock(password)

    def unlock(self, password=""):
        try:
            if "" == password:
                password = raw_input('Enter HSM password (will be echoed) : ')

            if len(password) == 32:
                password = password.decode('hex')

            self.hsm.key_storage_unlock(password)
            log.debug("key store unlocked")
        except pyhsm.exception.YHSM_Error as  e:
            log.error("Failed to unlock key store: %s" % e)


    def decrypt(self, data):
        d = ""
        try:
            d = self.hsm.aes_ecb_decrypt(self.key_handle, data)
        except pyhsm.exception.YHSM_Error as  e:
            log.error("Failed to decrypt data: %s" % e)
        return d

    def encrypt(self, data):
        d = ""
        try:
            d = self.hsm.aes_ecb_encrypt(self.key_handle, data)
        except pyhsm.exception.YHSM_Error as  e:
            print str(e)
            log.error("Failed to encrypt data: %s" % e)
        return d


def main():
    y = YubiHSM(0x1111, device="/dev/ttyACM3", debug=False, password="14fda9321ae820aa34e57852a31b10d0")

    e = y.encrypt("Das ist ein Test1234567890123456")
    print e
    d = y.decrypt(e)
    print d

if __name__ == "__main__":
    main()

#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP admin clients.
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
"""This module is used for enrolling yubikey
"""


try:
    import yubico
    import yubico.yubikey
    import yubico.yubikey_defs
    from yubico.yubikey import YubiKeyError
except ImportError as  e:
    print "python yubikey module not available."
    print "please get it from https://github.com/Yubico/python-yubico if you want to enroll yubikeys"
    print str(e)

from time import sleep
from usb import USBError
import sys
import re, os, binascii
try:
    from Crypto.Cipher import AES
    CRYPTO_AVAILABLE = True
except:
    CRYPTO_AVAILABLE = False
    print "No pycrypto available. You can not enroll yubikeys with static password."

MODE_YUBICO = 1
MODE_OATH = 2
MODE_STATIC = 3

hexHexChars = '0123456789abcdef'
modHexChars = 'cbdefghijklnrtuv'

hex2ModDict = dict(zip(hexHexChars, modHexChars))
mod2HexDict = dict(zip(modHexChars, hexHexChars))

def modhex_encode(s):
    return ''.join(
        [ hex2ModDict[c] for c in s.encode('hex') ]
    )

class YubiError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


def create_static_password(key_hex):
    '''
    According to yubikey manual 5.5.5 the static-ticket is the same algorith with no moving factors.
    The msg_hex that is encoded with the aes key is '000000000000ffffffffffffffff0f2e'
    '''
    if not CRYPTO_AVAILABLE:
        raise Exception("No pycrypto available. You can not enroll Yubikey with static password!")

    msg_hex = "000000000000ffffffffffffffff0f2e"
    msg_bin = binascii.unhexlify(msg_hex)
    aes = AES.new(binascii.unhexlify(key_hex), AES.MODE_ECB)
    password_bin = aes.encrypt(msg_bin)
    password = modhex_encode(password_bin)

    return password

def enrollYubikey(digits=6, APPEND_CR=True, debug=False, unlock_key=None, access_key=None, slot=1,
                  mode=MODE_OATH,
                  fixed_string=None,
                  len_fixed_string=0,
                  prefix_serial=False,
                  challenge_response=False):
    '''
    :param mode: Defines if the yubikey should be enrolled in OATH mode (1) or Yubico Mode (2)
    :type mode: integer

    :param fixed_string: A fixed string can be added in front of the output. If set to None, a random string will be generated
    :type fixed_string: string

    :param len_fixed_string: This specified the length of the random fixed string.
    :type len_fixed_string: integer


    '''
    YK = yubico.yubikey.find_key(debug=debug)
    firmware_version = YK.version()
    serial = "%08d" % YK.serial()

    v1 = re.match('1.', firmware_version)
    v2 = re.match('2.0.', firmware_version)

    if (v1 or v2):
        raise YubiError("Your Yubikey is too old. You need Firmware 2.1 or above. You are running %s"
            % firmware_version)

    Cfg = YK.init_config()

    # handle unlock_key and access_key
    if unlock_key:
        Cfg.unlock_key(unlock_key)
    if access_key:
        Cfg.access_key(access_key)

    if mode == MODE_YUBICO:
        key = binascii.hexlify(os.urandom(16))
        uid = os.urandom(yubico.yubikey_defs.UID_SIZE)
        if challenge_response:
            #Cfg.mode_challenge_response('h:' + key, type="OTP")
            raise YubiError("LinOTP only supports the OATH challenge Response mode at the moment!")
        else:
            Cfg.mode_yubikey_otp(uid, 'h:' + key)

    elif mode == MODE_OATH:
        key = binascii.hexlify(os.urandom(20))
        if challenge_response:
            Cfg.mode_challenge_response('h:' + key, type="HMAC")
        else:
            try:
                # set hmac mode with key and 6 digits
                # Try if we got 0.0.5
                Cfg.mode_oath_hotp('h:' + key, digits=digits)
            except TypeError:
                # We seem to have 0.0.4
                Cfg.mode_oath_hotp('h:' + key, bytes=digits)


    elif mode == MODE_STATIC:
        key = binascii.hexlify(os.urandom(16))
        Cfg.aes_key('h:' + key)
        Cfg.config_flag('STATIC_TICKET', True)

    else:
        YubiError("Unknown OTP mode specified.")

    # Do the fixed string:
    if prefix_serial:
        Cfg.fixed_string(serial)
    if fixed_string:
        Cfg.fixed_string(fixed_string)
    elif len_fixed_string:
        fs = os.urandom(len_fixed_string)
        Cfg.fixed_string(fs)

    # set CR behind OTP value
    Cfg.ticket_flag('APPEND_CR', APPEND_CR)
    Cfg.extended_flag('SERIAL_API_VISIBLE', True)

    YK.write_config(Cfg, slot=slot)

    return (key, serial)


def main():
    file_template = """<Tokens>
<Token serial="%s">
    <CaseModel>5</CaseModel>
    <Model>yubikey</Model>
    <ProductionDate>%s</ProductionDate>
    <ProductName>Yubikey 2.2</ProductName>
    <Applications>
        <Application ConnectorID="{a61c4073-2fc8-4170-99d1-9f5b70a2cec6}">
        <Seed>%s</Seed>
        <MovingFactor>1</MovingFactor>
        </Application>
    </Applications>
</Token>
</Tokens>"""

    import datetime
    from getopt import getopt, GetoptError

    OUTFILE = ""
    today = datetime.date.today().strftime("%m/%d/%Y")

    try:
        opts, args = getopt(sys.argv[1:], "o:",
                ['outfile='])

    except GetoptError:
        print "There is an error in your parameter syntax:"
        print "o, outfile=    the name of the output file"
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('o', '--outfile'):
            print "setting output file : ", arg
            OUTFILE = arg

    #
    # example of usage
    #
    try:
        #otpkey, serial = enrollYubikey( debug= False ,
        #                                access_key = binascii.unhexlify('121212121212'),
        #                                unlock_key = binascii.unhexlify('121212121212'))
        otpkey, serial = enrollYubikey(debug=False)
        print "Success: serial: %s, otpkey: %s." % (serial, otpkey)
        #
        # Now we write to a file
        #
        if "" == OUTFILE:
            OUTFILE = "yubikey-%s.xml" % serial
        f = open(OUTFILE, 'w')
        f.write(file_template % ("YUBI%s" % serial, today, otpkey))
        f.close()

    except yubico.yubico_exception.YubicoError as  e:
        print "ERROR: %s" % str(e)
        sys.exit(1)
    except YubiError as  e:
        print "Error: %s" % e.value


class YubikeyPlug(object):

    def __init__(self):
        self.last_serial = None

    def wait_for_new_yubikey(self, timeout=None):
        '''
        This functions waits for a new yubikey to be inserted
        '''
        found = False
        while 1:
            try:
                sleep(1)
                YK = yubico.yubikey.find_key()
                #firmware_version = YK.version()
                serial = "%08d" % YK.serial()

                if serial != self.last_serial:
                    self.last_serial = serial
                    print "\nFound Yubikey with serial %r\n" % serial
                    found = True
                    break;
            except USBError:
                sys.stdout.write('u')
                sys.stdout.flush()
            except YubiKeyError:
                sys.stdout.write('.')
                sys.stdout.flush()

        return found




if __name__ == "__main__":
    main()


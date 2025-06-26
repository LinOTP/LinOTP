# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""
read the CSV data as created by the Yubico personalization GUI.
"""

import binascii
import logging
import os

from Cryptodome.Cipher import AES

from linotp.lib.util import modhex_decode, modhex_encode

log = logging.getLogger(__name__)


def create_static_password(key_hex):
    """
    According to yubikey manual 5.5.5 the static-ticket is the same algorith
    with no moving factors. The msg_hex that is encoded with the aes key is
       '000000000000ffffffffffffffff0f2e'
    """
    msg_hex = "000000000000ffffffffffffffff0f2e"
    msg_bin = binascii.unhexlify(msg_hex)
    aes = AES.new(binascii.unhexlify(key_hex), AES.MODE_ECB)
    password_bin = aes.encrypt(msg_bin)
    password = modhex_encode(password_bin)

    return password


def parseYubicoCSV(csv):
    """
    This function reads the CSV data as created by the Yubico personalization GUI.

    Traditional Format:
    Yubico OTP,12/11/2013 11:10,1,vvgutbiedkvi,ab86c04de6a3,d26a7c0f85fdda28bd816e406342b214,,,0,0,0,0,0,0,0,0,0,0
    OATH-HOTP,11.12.13 18:55,1,cccccccccccc,,916821d3a138bf855e70069605559a206ba854cd,,,0,0,0,6,0,0,0,0,0,0
    Static Password,11.12.13 19:08,1,,d5a3d50327dc,0e8e37b0e38b314a56748c030f58d21d,,,0,0,0,0,0,0,0,0,0,0

    Yubico Format:
    # OATH mode
    508326,,0,69cfb9202438ca68964ec3244bfa4843d073a43b,,2013-12-12T08:41:07,
    1382042,,0,bf7efc1c8b6f23604930a9ce693bdd6c3265be00,,2013-12-12T08:41:17,
    # Yubico mode
    508326,cccccccccccc,83cebdfb7b93,a47c5bf9c152202f577be6721c0113af,,2013-12-12T08:43:17,
    # static mode
    508326,,,9e2fd386224a7f77e9b5aee775464033,,2013-12-12T08:44:34,

    column 0: serial
    column 1: public ID in yubico mode
    column 2: private ID in yubico mode, 0 in OATH mode, blank in static mode
    column 3: AES key

    BUMMER: The Yubico Format does not contain the information, which slot of
    the token was written.

    If now public ID or serial is given, we can not import the token, as the
    returned dictionary needs the token serial as a key.

    It returns a dictionary with the new tokens to be created:

        {
            serial: {   'type' : yubico,
                        'hmac_key' : xxxx,
                        'otplen' : xxx,
                        'description' : xxx
                         }
        }
    """
    TOKENS = {}
    log.debug("[parseYubicoCSV] starting to parse an yubico csv file.")

    csv_array = csv.split("\n")

    log.debug("[parseYubicoCSV] the file contains %i tokens.", len(csv_array))
    for line in csv_array:
        cells = line.split(",")
        serial = ""
        key = ""
        otplen = 32
        public_id = ""
        slot = ""
        if len(cells) >= 6:
            first_column = cells[0].strip()
            if first_column.lower() in [
                "yubico otp",
                "oath-hotp",
                "static password",
            ]:
                # traditional format
                typ = cells[0].strip()
                slot = cells[2].strip()
                public_id = cells[3].strip()
                key = cells[5].strip()

                if public_id == "":
                    log.warning("No public ID in line %r", line)
                    serial_int = int(binascii.hexlify(os.urandom(4)), 16)
                else:
                    mh = modhex_decode(public_id).encode("utf-8")[:8]
                    serial_int = int(mh, 16)

                if typ.lower() == "yubico otp":
                    ttype = "yubikey"
                    otplen = 32 + len(public_id)
                    serial = "UBAM%08d_%s" % (serial_int, slot)
                    TOKENS[serial] = {
                        "type": ttype,
                        "hmac_key": key,
                        "otplen": otplen,
                        "description": public_id,
                    }
                elif typ.lower() == "oath-hotp":
                    """
                    TODO: this does not work out at the moment, since the GUI either
                    1. creates a serial in the CSV, but then the serial is always prefixed! We can not authenticate with this!
                    2. if it does not prefix the serial there is no serial in the CSV! We can not import and assign the token!
                    """
                    ttype = "hmac"
                    otplen = 6
                    if cells and len(cells) > 11 and cells[11] and cells[11].strip():
                        otplen = int(cells[11])

                    serial = "UBOM%08d_%s" % (serial_int, slot)
                    TOKENS[serial] = {
                        "type": ttype,
                        "hmac_key": key,
                        "otplen": otplen,
                        "description": public_id,
                    }
                else:
                    log.warning(
                        "[parseYubicoCSV] at the moment we do only"
                        " support Yubico OTP and HOTP: %r",
                        line,
                    )
                    continue
            elif first_column.isdigit():
                # first column is a number, (serial number), so we are in the
                # yubico format
                serial = first_column
                # the yubico format does not specify a slot
                slot = "X"
                key = cells[3].strip()
                if cells[2].strip() == "0":
                    # HOTP
                    typ = "hmac"
                    serial = "UBOM%s_%s" % (serial, slot)
                    otplen = 6
                elif cells[2].strip() == "":
                    # Static
                    typ = "pw"
                    serial = "UBSM%s_%s" % (serial, slot)
                    key = create_static_password(key)
                    otplen = len(key)
                    log.warning(
                        "[parseYubcoCSV] We can not enroll a static mode, since we do not know"
                        " the private identify and so we do not know the static password."
                    )
                    continue
                else:
                    # Yubico
                    typ = "yubikey"
                    serial = "UBAM%s_%s" % (serial, slot)
                    public_id = cells[1].strip()
                    otplen = 32 + len(public_id)
                TOKENS[serial] = {
                    "type": typ,
                    "hmac_key": key,
                    "otplen": otplen,
                    "description": public_id,
                }
        else:
            log.warning(
                "[parseYubicoCSV] the line %r did not contain a enough values",
                line,
            )
            continue

    log.debug("[parseOATHcsv] read the following values: %r", TOKENS)

    return TOKENS

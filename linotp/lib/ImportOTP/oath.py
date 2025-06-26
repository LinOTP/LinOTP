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
parses CSV data for oath token
"""

import logging

log = logging.getLogger(__name__)


def parseOATHcsv(csv):
    """

    This function parses CSV data for oath token.
    The file format is

        serial, key, [hotp,totp], [6,8], [30|60], [sha1|sha256|sha512],
        serial, key, ocra, [ocra-suite]

    It imports standard hmac algorithm based tokens

    If the seed is 32 bytes long or at the end of the row the hashlib is
       defined the tokens hashlib changes to sha265. For seeds with 64 bytes
       the hashlib is determined as sha512 if not other specified.

    It can also import ocra2 token.

    * The default is hotp
    * if totp is set, the default seconds are 30

    * if ocra is set, an ocra-suite is required

    It returns a dictionary:
        {
            serial: {   'type' : xxxx,
                        'hmac_key' : xxxx,
                        'hashlib' : 'sha1|sha256|sha512'
                        'timeStep' : xxxx,
                        'otplen' : xxx,
                        'ocrasuite' : xxx  }
        }
    """
    TOKENS = {}

    # we cant use the csv parser here as we have variable length data. So
    # we do the split into lines manualy

    csv_array = csv.split("\n")

    log.debug("[parseOATHcsv] starting to parse an oath csv file.")
    log.debug("[parseOATHcsv] the file contains %i lines.", len(csv_array))

    for csv_line in csv_array:
        token = {}

        # we extend the line to contain always 8 columns

        line = [x.strip() for x in csv_line.split(",")]
        line += [""] * (8 - len(line))

        # ------------------------------------------------------------------ --

        # 1. column: serial

        serial = line[0]
        if not serial:
            log.error(
                "[parseOATHcsv] the line %s did not contain a serial number",
                csv_line,
            )
            continue

        if serial == "#":
            continue

        token["serial"] = serial

        # ------------------------------------------------------------------ --

        # 2 column: seed

        key = line[1]
        if not key:
            log.error(
                "[parseOATHcsv] the line %s did not contain a hmac key",
                csv_line,
            )
            continue

        token["hmac_key"] = key

        # ------------------------------------------------------------------ --

        # 3 column: token type

        ttype = line[2].lower()
        if ttype == "hotp":
            ttype = "hmac"

        if not ttype:
            ttype = "hmac"

        token["type"] = ttype

        # ------------------------------------------------------------------ --

        # 4 column: otplen or ocrasuite

        if ttype in ["ocra2"]:
            ocrasuite = line[3]

            if not ocrasuite:
                log.error(
                    "[parseOATHcsv] the line %s did not contain"
                    " the ocrasuite for the ocra2 token!",
                    csv_line,
                )
                continue

            token["ocrasuite"] = ocrasuite

        else:
            otplen = line[3]
            otplen = int(otplen) if otplen else 6

            token["otplen"] = otplen

        # ------------------------------------------------------------------ --

        # 5 column: timeStep

        if ttype in ["totp"]:
            try:
                seconds = int(line[4])
            except ValueError:
                seconds = 30

            token["timeStep"] = seconds

        # ------------------------------------------------------------------ --

        # 6 column: hash lib

        hash_hint = line[5].lower()
        if hash_hint and hash_hint in ["sha1", "sha256", "sha512"]:
            hashlib = hash_hint
        else:
            if len(key) == 2 * 64:
                hashlib = "sha512"
            elif len(key) == 2 * 32:
                hashlib = "sha256"
            else:
                hashlib = "sha1"

        if ttype not in ["ocra", "ocra2"]:
            token["hashlib"] = hashlib

        # ------------------------------------------------------------------ --

        log.debug(
            "[parseOATHcsv] read the line >%s< into token: >%r<",
            csv_line,
            token,
        )

        TOKENS[serial] = token

    log.debug("[parseOATHcsv] read the following values: %r", TOKENS)

    return TOKENS

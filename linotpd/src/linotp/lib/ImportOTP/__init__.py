# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""
This file is used used for importing SafeNet (former Aladdin)
XML files, that hold the OTP secrets for eToken PASS.
"""

import xml.etree.ElementTree as etree
import re
import os
import binascii
from linotp.lib.util import modhex_decode
from linotp.lib.util import modhex_encode
from Cryptodome.Cipher import AES

import logging
log = logging.getLogger(__name__)


def getKnownTypes():
    return ["feitian", "pskc", "dpw", 'dat', "vasco"]

def getImportText():
    return { 'feitian' : 'Feitian XML',
        'pskc' : 'OATH compliant PSKC',
        'dpw' : 'Tagespasswort Token File',
        'dat' : 'eToken DAT File',
        'vasco' : 'Vasco DPX' }

def create_static_password(key_hex):
    '''
    According to yubikey manual 5.5.5 the static-ticket is the same algorith with no moving factors.
    The msg_hex that is encoded with the aes key is '000000000000ffffffffffffffff0f2e'
    '''
    msg_hex = "000000000000ffffffffffffffff0f2e"
    msg_bin = binascii.unhexlify(msg_hex)
    aes = AES.new(binascii.unhexlify(key_hex), AES.MODE_ECB)
    password_bin = aes.encrypt(msg_bin)
    password = modhex_encode(password_bin)

    return password

class ImportException(Exception):
    def __init__(self, description):
        #self.auth_scope = scope
        #self.auth_action = action
        #self.auth_action_desc = action_desc
        self.description = description

    def __str__(self):
        return ('%s' % self.description)

def getTagName(elem):
    match = re.match("^({.*?})(.*)$", elem.tag)
    if match:
        return match.group(2)
    else:
        return elem.tag


def parseOATHcsv(csv):
    '''

    This function parses CSV data for oath token.
    The file format is

        serial, key, [hotp,totp], [6,8], [30|60], [sha1|sha256|sha512],
        serial, key, ocra, [ocra-suite]

    It imports standard hmac algorithm based tokens

    If the seed is 32 bytes long or at the end of the row the hashlib is
       defined the tokens hashlib changes to sha265. For seeds with 64 bytes
       the hashlib is determined as sha512 if not other specified.

    It can also import ocra token.

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
    '''
    TOKENS = {}

    # we cant use the csv parser here as we have variable length data. So
    # we do the split into lines manualy

    csv_array = csv.split('\n')

    log.debug("[parseOATHcsv] starting to parse an oath csv file.")
    log.debug("[parseOATHcsv] the file contains %i lines.", len(csv_array))

    for csv_line in csv_array:

        token = {}

        # we extend the line to contain always 8 columns

        line = [x.strip() for x in csv_line.split(',')]
        line += [''] * (8 - len(line))

        # ------------------------------------------------------------------ --

        # 1. column: serial

        serial = line[0]
        if not serial:
            log.error("[parseOATHcsv] the line %s did not contain"
                      " a serial number", csv_line)
            continue

        if serial == '#':
            continue

        token['serial'] = serial

        # ------------------------------------------------------------------ --

        # 2 column: seed

        key = line[1]
        if not key:
            log.error("[parseOATHcsv] the line %s did not contain"
                      " a hmac key" % csv_line)
            continue

        token['hmac_key'] = key

        # ------------------------------------------------------------------ --

        # 3 column: token type

        ttype = line[2].lower()
        if ttype == "hotp":
            ttype = "hmac"

        if not ttype:
            ttype = "hmac"

        token['type'] = ttype

        # ------------------------------------------------------------------ --

        # 4 column: otplen or ocrasuite

        if ttype in ["ocra", "ocra2"]:

            ocrasuite = line[3]

            if not ocrasuite:
                log.error("[parseOATHcsv] the line %s did not contain"
                          " the ocrasuite for the ocra token!" % csv_line)
                continue

            token['ocrasuite'] = ocrasuite

        else:

            otplen = line[3]
            if otplen:
                otplen = int(otplen)
            else:
                otplen = 6

            token['otplen'] = otplen

        # ------------------------------------------------------------------ --

        # 5 column: timeStep

        if ttype in ['totp']:
            try:
                seconds = int(line[4])
            except ValueError:
                seconds = 30

            token['timeStep'] = seconds

        # ------------------------------------------------------------------ --

        # 6 column: hash lib

        hash_hint = line[5].lower()
        if hash_hint and hash_hint in ['sha1', 'sha256', 'sha512']:
            hashlib = hash_hint
        else:
            if len(key) == 2 * 64:
                hashlib = "sha512"
            elif len(key) == 2 * 32:
                hashlib = "sha256"
            else:
                hashlib = 'sha1'

        if ttype not in ["ocra", "ocra2"]:
            token['hashlib'] = hashlib

        # ------------------------------------------------------------------ --

        log.debug("[parseOATHcsv] read the line >%s< into token: >%r<",
                  csv_line, token)

        TOKENS[serial] = token

    log.debug("[parseOATHcsv] read the following values: %r", TOKENS)

    return TOKENS

def parseYubicoCSV(csv):
    '''
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

    BUMMER: The Yubico Format does not contain the information, which slot of the token was written.

    If now public ID or serial is given, we can not import the token, as the returned dictionary needs
    the token serial as a key.

    It returns a dictionary with the new tokens to be created:

        {
            serial: {   'type' : yubico,
                        'hmac_key' : xxxx,
                        'otplen' : xxx,
                        'description' : xxx
                         }
        }
    '''
    TOKENS = {}
    log.debug("[parseYubicoCSV] starting to parse an yubico csv file.")

    csv_array = csv.split('\n')

    log.debug("[parseYubicoCSV] the file contains %i tokens." % len(csv_array))
    for line in csv_array:
        l = line.split(',')
        serial = ""
        key = ""
        otplen = 32
        public_id = ""
        slot = ""
        if len(l) >= 6:
            first_column = l[0].strip()
            if first_column.lower() in ["yubico otp", "oath-hotp", "static password"]:
                # traditional format
                typ = l[0].strip()
                slot = l[2].strip()
                public_id = l[3].strip()
                key = l[5].strip()

                if public_id == "":
                    log.warning("No public ID in line %r" % line)
                    serial_int = int(binascii.hexlify(os.urandom(4)), 16)
                else:
                    serial_int = int(binascii.hexlify(modhex_decode(public_id)), 16)

                if typ.lower() == "yubico otp":
                    ttype = "yubikey"
                    otplen = 32 + len(public_id)
                    serial = "UBAM%08d_%s" % (serial_int, slot)
                    TOKENS[serial] = { 'type' : ttype,
                               'hmac_key' : key,
                               'otplen' : otplen,
                               'description': public_id
                              }
                elif typ.lower() == "oath-hotp":
                    '''
                    TODO: this does not work out at the moment, since the GUI either
                    1. creates a serial in the CSV, but then the serial is always prefixed! We can not authenticate with this!
                    2. if it does not prefix the serial there is no serial in the CSV! We can not import and assign the token!
                    '''
                    ttype = "hmac"
                    otplen = 6
                    serial = "UBOM%08d_%s" % (serial_int, slot)
                    TOKENS[serial] = { 'type' : ttype,
                               'hmac_key' : key,
                               'otplen' : otplen,
                               'description': public_id
                              }
                else:
                    log.warning("[parseYubicoCSV] at the moment we do only support Yubico OTP and HOTP: %r" % line)
                    continue
            elif first_column.isdigit():
                # first column is a number, (serial number), so we are in the yubico format
                serial = first_column
                # the yubico format does not specify a slot
                slot = "X"
                key = l[3].strip()
                if l[2].strip() == "0":
                    # HOTP
                    typ = "hmac"
                    serial = "UBOM%s_%s" % (serial, slot)
                    otplen = 6
                elif l[2].strip() == "":
                    # Static
                    typ = "pw"
                    serial = "UBSM%s_%s" % (serial, slot)
                    key = create_static_password(key)
                    otplen = len(key)
                    log.warning("[parseYubcoCSV] We can not enroll a static mode, since we do not know"
                                " the private identify and so we do not know the static password.")
                    continue
                else:
                    # Yubico
                    typ = "yubikey"
                    serial = "UBAM%s_%s" % (serial, slot)
                    public_id = l[1].strip()
                    otplen = 32 + len(public_id)
                TOKENS[serial] = { 'type' : typ,
                               'hmac_key' : key,
                               'otplen' : otplen,
                               'description': public_id
                              }
        else:
            log.warning("[parseYubicoCSV] the line %r did not contain a enough values" % line)
            continue


    log.debug("[parseOATHcsv] read the following values: %s" % str(TOKENS))

    return TOKENS


def parseSafeNetXML(xml):
    '''
    This function parses XML data of a Aladdin/SafeNet XML
    file for eToken PASS

    It returns a dictionary of
        serial : { hmac_key , counter, type }
    '''

    TOKENS = {}
    elem_tokencontainer = etree.fromstring(xml)

    if getTagName(elem_tokencontainer) != "Tokens":
        raise ImportException("No toplevel element Tokens")


    for elem_token in list(elem_tokencontainer):
        SERIAL = None
        COUNTER = None
        HMAC = None
        DESCRIPTION = None
        if getTagName(elem_token) == "Token":
            SERIAL = elem_token.get("serial")
            log.debug("Found token with serial %s" % SERIAL)
            for elem_tdata in list(elem_token):
                tag = getTagName(elem_tdata)
                if "ProductName" == tag:
                    DESCRIPTION = elem_tdata.text
                    log.debug("The Token with the serial %s has the productname %s" % (SERIAL, DESCRIPTION))
                if "Applications" == tag:
                    for elem_apps in elem_tdata:
                        if getTagName(elem_apps) == "Application":
                            for elem_app in elem_apps:
                                tag = getTagName(elem_app)
                                if "Seed" == tag:
                                    HMAC = elem_app.text
                                if "MovingFactor" == tag:
                                    COUNTER = elem_app.text
            if not SERIAL:
                log.error("Found token without a serial")
            else:
                if HMAC:
                    hashlib = "sha1"
                    if len(HMAC) == 64:
                        hashlib = "sha256"

                    TOKENS[SERIAL] = {
                        'hmac_key' : HMAC,
                        'counter' : COUNTER,
                        'type' : 'HMAC',
                        'hashlib' : hashlib
                    }
                else:
                    log.error("Found token %s without a element 'Seed'" % SERIAL)

    return TOKENS

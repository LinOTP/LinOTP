# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
parses XML data of a Aladdin/SafeNet XML
"""

import logging
import re

import xml.etree.ElementTree as etree


log = logging.getLogger(__name__)


def getKnownTypes():
    return ["feitian", "pskc", "dpw", 'dat', "vasco"]


def getImportText():
    return {'feitian': 'Feitian XML',
            'pskc': 'OATH compliant PSKC',
            'dpw': 'Tagespasswort Token File',
            'dat': 'eToken DAT File',
            'vasco': 'Vasco DPX'}


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
                    log.debug("The Token with the serial %s has the productname %s" % (
                        SERIAL, DESCRIPTION))
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
                        'hmac_key': HMAC,
                        'counter': COUNTER,
                        'type': 'HMAC',
                        'hashlib': hashlib
                    }
                else:
                    log.error(
                        "Found token %s without a element 'Seed'" % SERIAL)

    return TOKENS

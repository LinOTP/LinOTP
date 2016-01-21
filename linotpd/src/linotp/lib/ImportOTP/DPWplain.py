# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
""" Tages Password importer"""

import re

import logging
log = logging.getLogger(__name__)


from linotp.lib.ImportOTP  import ImportException


def checkserial(serial):
    '''
    TODO: What should the serials look like?
    '''
    return True

def parseDPWdata(data):
    '''
    This function parses data of a file containing the secrets for Tagespasswort-Tokens

    each line in the file has the format
    serial <whitespace> secret

    the serial is checked for matching. If the serial does not match,
    the line is not imported

    It returns a dictionary of
        serial : { hmac_key , type }
    '''

    TOKENS = {}
    TOKEN_TYPE = "dpw"

    for line in data.splitlines():
        log.debug("[parseDPWdata] checking line: %s" % line)
        m = re.match("(\S.*?)\s.*?(\S.*)", line)
        if m:
            serial = m.groups()[0]
            key = m.groups()[1]
            if checkserial(serial):
                log.debug("import tagespasswort token with serial %s" % serial)
                TOKENS[serial] = { 'hmac_key' : key, 'type' : TOKEN_TYPE }
            else:
                log.warning("Found a non-matching line: %s" % line)

    return TOKENS

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
""" Tages Password importer"""

import logging
import re

from linotp.lib.ImportOTP import ImportException

log = logging.getLogger(__name__)


def checkserial(serial):
    """
    TODO: What should the serials look like?
    """
    return True


def parseDPWdata(data):
    """
    This function parses data of a file containing the secrets for Tagespasswort-Tokens

    each line in the file has the format
    serial <whitespace> secret

    the serial is checked for matching. If the serial does not match,
    the line is not imported

    It returns a dictionary of
        serial : { hmac_key , type }
    """

    TOKENS = {}
    TOKEN_TYPE = "dpw"

    for line in data.splitlines():
        log.debug("[parseDPWdata] checking line: %r", line)
        m = re.match(r"(\S.*?)\s.*?(\S.*)", line)
        if m:
            serial = m.groups()[0]
            key = m.groups()[1]
            if checkserial(serial):
                log.debug("import tagespasswort token with serial %r", serial)
                TOKENS[serial] = {"hmac_key": key, "type": TOKEN_TYPE}
            else:
                log.warning("Found a non-matching line: %r", line)

    return TOKENS

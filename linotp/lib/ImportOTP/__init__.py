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
import tokens module
"""

import re


class ImportException(Exception):
    def __init__(self, description):
        # self.auth_scope = scope
        # self.auth_action = action
        # self.auth_action_desc = action_desc
        self.description = description

    def __str__(self):
        return f"{self.description}"


def getTagName(elem):
    match = re.match("^({.*?})(.*)$", elem.tag)
    if match:
        return match.group(2)
    else:
        return elem.tag


def getKnownTypes():
    return ["feitian", "pskc", "dpw", "dat"]


def getImportText():
    return {
        "feitian": "Feitian XML",
        "pskc": "OATH compliant PSKC",
        "dpw": "Tagespasswort Token File",
        "dat": "eToken DAT File",
    }


# eof

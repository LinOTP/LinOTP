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
"""logic for the selfservice processing"""

import logging

from linotp.flap import config

log = logging.getLogger(__name__)


def get_imprint(realm):
    """
    This function returns the imprint for a certain realm.
    This is just the contents of the file <realm>.imprint in the directory
    <imprint_directory>
    """
    res = ""
    realm = realm.lower()
    directory = config.get("linotp.imprint_directory", "/etc/linotp/imprint")
    filename = f"{directory}/{realm}.imprint"
    try:
        with open(filename) as f:
            res = f.read()
    except Exception as e:
        log.info("[get_imprint] can not read imprint file: %s. (%r)", filename, e)

    return res

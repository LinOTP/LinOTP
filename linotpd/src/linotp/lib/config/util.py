# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
    some config helper utilities
    - located here as required in certain places
"""

from linotp.config import environment as env
from linotp.lib.crypto.encrypted_data import EncryptedData

linotp_root = env.config.get("linotp.root")


def expand_here(value):
    """
    expand the %(here)s string with the linotp root location

    :param value: the input value
    :return: the expanded value
    """

    if not linotp_root:
        return value

    if not (isinstance(value, unicode) or isinstance(value, str)):
        return value

    if isinstance(value, EncryptedData):
        return value

    if "%(here)s" in value:
        return value.replace("%(here)s", linotp_root)

    return value

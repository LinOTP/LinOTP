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
    base for a typing system:

        association of linotp system config entries with its types
"""


from linotp.lib.type_utils import (
    check_networks_expression,
    check_time_format_string,
    encrypted_data,
    is_duration,
)

Config_Types = {
    "linotp.user_lookup_cache.expiration": ("duration", is_duration),
    "linotp.resolver_lookup_cache.expiration": ("duration", is_duration),
    "linotp.client.FORWARDED_PROXY": ("network", check_networks_expression),
    "linotp.token.last_access": (
        "time_format_string",
        check_time_format_string,
    ),
}


type_definitions = {
    # legacy provider defintion require an extra conversion step
    "linotp.EmailProviderConfig": ("encrypted_data", encrypted_data),
    "linotp.SMSProviderConfig": ("encrypted_data", encrypted_data),
}

# EOF #

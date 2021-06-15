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

import io
from configparser import ConfigParser


def create_provider_config():
    """
    not used but implemented to generate templates of provider configs
    'contents' contains the ini file
    """
    from linotp.provider import Provider_types
    from linotp.provider import get_all_new_providers

    provider_config = {}
    for provider_type in list(Provider_types.keys()):

        providers = get_all_new_providers(
            provider_type, show_managed_config=True
        )

        provider_config[provider_type] = providers

    ini = ConfigParser()

    for provider_type, providers in list(provider_config.items()):
        for provider in list(providers.keys()):
            section = "%s:%s" % (provider_type, provider)
            ini.add_section(section)

            provider_config = providers.get(provider)
            for key, value in list(provider_config.items()):
                ini.set(section, key, value)

    output = io.StringIO()
    ini.write(output)
    contents = output.getvalue()
    output.close()
    return contents

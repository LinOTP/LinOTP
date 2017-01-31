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
'''
* interface of the PushProvider
'''

from linotp.provider import provider_registry

import logging

log = logging.getLogger(__name__)


class IPushProvider(object):
    """
    An abstract class that has to be implemented by ever e-mail provider class
    """

    provider_type = 'push'

    def __init__(self):
        pass

    @staticmethod
    def getConfigMapping():
        """
        for dynamic, adaptive config entries we provide the abilty to
        have dedicated config entries

        entries should look like:
        {
          key: (ConfigName, ConfigType)
        }
        """
        config_mapping = {
                'timeout': ('Timeout', None),
                'config': ('Config', 'password')}

        return config_mapping

    def push_notification(self, message, token_info=None, gda=None):
        """
        Sends out the push notification message.

        :param message: The push notification message / challenge
        :param token_info: the token info, which contains target token
                           descriptor
        :param gda: alternative to the token_info, the gda could be provided
                    directly
        :return: A tuple of success and result message
        """
        raise NotImplementedError("Every subclass of IPushProvider has to "
                                  "implement this method.")

    def loadConfig(self, configDict):
        """
        Loads the configuration for this push notification provider

        :param configDict: A dictionary that contains all configuration entries
                          you defined (e.g. in the linotp.ini file)
        """
        pass

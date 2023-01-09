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
    manager for the app global linotp config dict.

    using rwlocks to synchronize the access to a linotp config dict for
    the global app context.

    the purpose of this class is the speedup, so that a linotp config
    dict in the request context is instantiated via a deep copy from
    the flask app global linotp config dict instead of a database read.
"""

import copy

from linotp.lib.rw_lock import RWLock


class LinotpAppConfig:

    """Globals acts as a container for objects available throughout the
    life of the application

    """

    def __init__(self):
        """One app global instance of LinotpAppConfig is created during
        application initialization and is available during requests via the
        'current_app.linotp_app_config' variable

        """

        self.config = {}
        self.config_incomplete = False
        self.configLock = RWLock()

    def getConfig(self):
        """
        retrieve (the deep copy of) the actual config
        """
        self.configLock.acquire_read()
        try:
            config = copy.deepcopy(self.config)
        finally:
            self.configLock.release()
        return config

    def setConfig(self, config, replace=False):
        """
        set the app global config for linotp
        """
        self.configLock.acquire_write()
        try:
            if not isinstance(config, dict):
                raise Exception(
                    "cannot set global config from object %r" % config
                )

            conf = copy.deepcopy(config)
            if replace is True:
                self.config = conf
            else:
                self.config.update(conf)

        finally:
            self.configLock.release()

    def isConfigComplete(self):
        """check if the linotp config read is completed.

        purpose of this flag is that the configuration might be read
        but when the security module was not loaded, the config entry
        was not de-crypted. this has become obsolete by introducing the
        CryptedData objects which allows a lazy read.
        """
        self.configLock.acquire_read()
        try:
            return self.config_incomplete
        finally:
            self.configLock.release()
        return False

    def setConfigIncomplete(self, val=False):
        """set the status that the config reading is completed"""
        self.configLock.acquire_write()
        try:
            self.config_incomplete = val
        finally:
            self.configLock.release()

    def delConfig(self, conf):
        """
        delete one entry in the appl_globals
        """
        self.configLock.acquire_write()

        try:
            if isinstance(conf, (list, dict)):
                for k in conf:
                    if k in self.config:
                        del self.config[k]

            elif isinstance(conf, str):
                if conf in self.config:
                    del self.config[conf]

        finally:
            self.configLock.release()


# eof #

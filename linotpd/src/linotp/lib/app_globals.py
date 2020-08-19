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

"""The application's Globals object"""
import copy
import logging


from linotp.lib.rw_lock import RWLock

log = logging.getLogger(__name__)

class Globals(object):

    """Globals acts as a container for objects available throughout the
    life of the application

    """

    def __init__(self):
        """One instance of Globals is created during application
        initialization and is available during requests via the
        'app_globals' variable

        """
        self.rwl2 = RWLock()
        self.rcount = 0

        self.config = {}
        self.config_incomplete = False
        self.configLock = RWLock()

        self.cache_manager = None

    def getConfig(self):
        '''
            retrieve (the deep copy of) the actual config
        '''
        self.configLock.acquire_read()
        try:
            config = copy.deepcopy(self.config)
        finally:
            self.configLock.release()
        return config

    def setConfig(self, config, replace=False):
        '''
            set the app global config for linotp
        '''
        err = None
        self.configLock.acquire_write()
        try:
            ty = type(config).__name__
            if ty != 'dict':
                self.configLock.release()
                err = 'cannot set global config from object ' + ty

            else:
                conf = copy.deepcopy(config)
                if replace is True:
                    self.config = conf
                else:
                    self.config.update(conf)
        finally:
            self.configLock.release()
            if err is not None:
                raise Exception(err)
        return

    def isConfigComplet(self):
        ret = True
        self.configLock.acquire_read()
        try:
            ret = self.config_incomplete
        finally:
            self.configLock.release()
        return  ret

    def setConfigIncomplete(self, val=False):
        '''
            set the app global config for linotp
        '''
        self.configLock.acquire_write()
        try:
            self.config_incomplete = val
        finally:
            self.configLock.release()
        return


    def delConfig(self, conf):
        '''
            delete one entry in the appl_globals
        '''
        self.configLock.acquire_write()
        try:
            ty = type(conf).__name__

            if ty == 'list' or ty == 'dict':
                for k in conf:
                    if k in self.config:
                        del self.config[k]
            elif ty == 'str' or ty == 'unicode':
                if conf in self.config:
                    del self.config[conf]
        finally:
            self.configLock.release()
        return

    def setConfigReadLock(self):
        self.rcount = self.rcount + 1
        self.rwl2.acquire_read()
        return self.rcount

    def setConfigWriteLock(self):
        self.rcount = self.rcount + 1
        self.rwl2.acquire_write()
        return self.rcount

    def releaseConfigLock(self):
        self.rcount = self.rcount - 1
        self.rwl2.release()
        return self.rcount


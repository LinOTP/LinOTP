# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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
import threading
import copy
import logging

from linotp.lib.security.provider import SecurityProvider


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
        secLock = RWLock()

        self.security_provider = SecurityProvider(secLock)

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
                    if self.config.has_key(k):
                        del self.config[k]
            elif ty == 'str' or ty == 'unicode':
                if self.config.has_key(conf):
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


###
#Python offers a number of useful synchronization primitives in the threading and Queue modules.
#One that is missing, however, is a simple reader-writer lock (RWLock). A RWLock allows improved
#concurrency over a simple mutex, and is useful for objects that have high read-to-write ratios
#like database caches.
#
#Surprisingly, I haven t been able to find any implementation of these semantics, so I rolled my
#own in a module rwlock.py to implement a RWLock class, along with lock promotion/demotion. Hopefully
#it can be added to the standard library threading module.
#This code is hereby placed in the public domain.
#
#    from
#    http://majid.info/blog/a-reader-writer-lock-for-python/
#
#
#   Simple reader-writer locks in Python
#    Many readers can hold the lock XOR one and only one writer
#
#
###
#
#version = """$Id: 04-1.html,v 1.3 2006/12/05 17:45:12 majid Exp $"""

class RWLock:
    """
    A simple reader-writer lock Several readers can hold the lock
    simultaneously, XOR one writer. Write locks have priority over reads to
    prevent write starvation.
    """
    def __init__(self):
        self.rwlock = 0
        self.writers_waiting = 0
        self.monitor = threading.Lock()
        self.readers_ok = threading.Condition(self.monitor)
        self.writers_ok = threading.Condition(self.monitor)
    def acquire_read(self):
        """Acquire a read lock. Several threads can hold this typeof lock.
        It is exclusive with write locks.
        """
        self.monitor.acquire()
        while self.rwlock < 0 or self.writers_waiting:
            self.readers_ok.wait()
        self.rwlock += 1
        self.monitor.release()
    def acquire_write(self):
        """Acquire a write lock. Only one thread can hold this lock, and
            only when no read locks are also held.
        """
        self.monitor.acquire()
        while self.rwlock != 0:
            self.writers_waiting += 1
            self.writers_ok.wait()
            self.writers_waiting -= 1
        self.rwlock = -1
        self.monitor.release()
    def promote(self):
        """Promote an already-acquired read lock to a write lock
        WARNING: it is very easy to deadlock with this method"""
        self.monitor.acquire()
        self.rwlock -= 1
        while self.rwlock != 0:
            self.writers_waiting += 1
            self.writers_ok.wait()
            self.writers_waiting -= 1
        self.rwlock = -1
        self.monitor.release()
    def demote(self):
        """Demote an already-acquired write lock to a read lock"""
        self.monitor.acquire()
        self.rwlock = 1
        self.readers_ok.notifyAll()
        self.monitor.release()
    def release(self):
        """Release a lock, whether read or write."""
        self.monitor.acquire()
        if self.rwlock < 0:
            self.rwlock = 0
        else:
            self.rwlock -= 1
        wake_writers = self.writers_waiting and self.rwlock == 0
        wake_readers = self.writers_waiting == 0
        self.monitor.release()
        if wake_writers:
            self.writers_ok.acquire()
            self.writers_ok.notify()
            self.writers_ok.release()
        elif wake_readers:
            self.readers_ok.acquire()
            self.readers_ok.notifyAll()
            self.readers_ok.release()

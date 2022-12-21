# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
    handle all configuration items with aspekts like persitance and
       syncronysation and provides this to all requests
"""

import logging
import os
import time

from datetime import datetime

from linotp.config import environment as env
from linotp.lib.config.util import expand_here

from linotp.lib.config.db_api import _removeConfigDB
from linotp.lib.config.db_api import _retrieveAllConfigDB
from linotp.lib.config.db_api import _storeConfigDB
from linotp.lib.config.db_api import _retrieveConfigDB

from linotp.lib.config.global_api import getGlobalObject
from linotp.lib.config.global_api import _getConfigReadLock
from linotp.lib.config.global_api import _releaseConfigLock

from linotp.lib.config.type_definition import Config_Types

"""
    LinOTP Config class
    - a dictionary to hold the config entries with a backend database
"""

log = logging.getLogger(__name__)


class LinOtpConfig(dict):
    """
    This class should be a request singleton.

    In case of a change, it must cover the different aspects like

    - env config entry
    - and app_globals
    - and finally sync this to disc

    """

    def __init__(self, *args, **kw):
        self.parent = super(LinOtpConfig, self)
        self.parent.__init__(*args, **kw)

        self.delay = False
        self.realms = None
        self.glo = getGlobalObject()
        conf = self.glo.getConfig()

        do_reload = False

        # do the bootstrap if no entry in the app_globals
        if len(conf.keys()) == 0:
            do_reload = True

        if self.glo.isConfigComplet() is False:
            do_reload = True
            self.delay = True

        if 'linotp.enableReplication' in conf:
            val = conf.get('linotp.enableReplication')
            if val.lower() == 'true':

                # look for the timestamp when config was created
                e_conf_date = conf.get('linotp.Config')

                # in case of replication, we always have to look if the
                # config data in the database changed
                db_conf_date = _retrieveConfigDB('linotp.Config')

                if str(db_conf_date) != str(e_conf_date):
                    do_reload = True

        self.refreshConfig(do_reload=do_reload)

        return

    def refreshConfig(self, do_reload=False):

        conf = self.glo.getConfig()

        if do_reload is True:
            # in case there is no entry in the dbconf or
            # the config file is newer, we write the config back to the db
            entries = conf.keys()
            for entry in entries:
                del conf[entry]

            writeback = False
            # get all conf entries from the config file
            fileconf = _getConfigFromEnv()

            # get all configs from the DB
            (dbconf, delay) = _retrieveAllConfigDB()
            self.glo.setConfigIncomplete(not delay)

            # we only merge the config file once as a removed entry
            #  might reappear otherwise
            if 'linotp.Config' not in dbconf:
                conf.update(fileconf)
                writeback = True

            conf.update(dbconf)
            # check, if there is a selfTest in the DB and delete it
            if 'linotp.selfTest' in dbconf:
                _removeConfigDB('linotp.selfTest')
                _storeConfigDB('linotp.Config', datetime.now())

            # the only thing we take from the fileconf is the selftest
            if 'linotp.selfTest' in fileconf:
                conf['linotp.selfTest'] = 'True'

            if writeback is True:
                for con in conf:
                    if con != 'linotp.selfTest':
                        _storeConfigDB(con, conf.get(con))
                _storeConfigDB(u'linotp.Config', datetime.now())

            self.glo.setConfig(conf, replace=True)

        self.parent.update(conf)
        return

    def setRealms(self, realmDict):
        self.realms = realmDict
        return

    def getRealms(self):
        return self.realms

    def addEntry(self, key, val, typ=None, des=None):
        '''
        small wrapper, as the assignement opperator has only one value argument

        :param key: key of the dict
        :type  key: string
        :param val: any value, which is put in the dict
        :type  val: any type
        :param typ: used in the database to control if the data is encrypted
        :type  typ: None,string,password
        :param des: literal, which describes the data
        :type  des: string
        '''
        if not key.startswith('linotp.'):
            key = 'linotp.' + key

        return self.__setitem__(key, val, typ, des)

    def __setitem__(self, key, val, typ=None, des=None):
        '''
        implemtation of the assignement operator == internal function

        :param key: key of the dict
        :type  key: string
        :param val: any value, which is put in the dict
        :type  val: any type
        :param typ: used in the database to control if the data is encrypted
        :type  typ: None,string,password
        :param des: literal, which describes the data
        :type  des: string
        '''

        # do some simple typing for known config entries
        self._check_type(key, val)

        nVal = expand_here(val)

        # update this config and sync with global dict and db

        res = self.parent.__setitem__(key, nVal)
        self.glo.setConfig({key: nVal})

        # ----------------------------------------------------------------- --

        # finally store the entry in the database and
        # syncronize as well the global timestamp

        now = datetime.now()

        self.glo.setConfig({'linotp.Config': unicode(now)})

        _storeConfigDB(key, val, typ, des)
        _storeConfigDB('linotp.Config', now)

        return res

    def _check_type(self, key, value):
        """
        check if we have a type description for this entry:
        - if so, we take the tuple of type 'as literal' and
          the type check function, we are running against the given value

        :param key: the to be stored key
        :param value: the to be stored value

        :return: - nothing -
        :raises: ValueError - if value is not type compliant

        """

        if key in Config_Types:

            #
            # get the tuple of type as literal and type checking function
            #

            typ, check_type_function = Config_Types[key]

            if not check_type_function(value):
                raise ValueError("Config Error: %s must be of type %r" %
                                 (key, typ))

    def get(self, key, default=None):
        '''
            check for a key in the linotp config

            remark: the config entries all start with linotp.
            if a key is not found, we do a check if there is
            a linotp. prefix set in the key and potetialy prepend it

            :param key: search value
            :type  key: string
            :param default: default value, which is returned,
                            if the value is not found
            :type  default: any type

            :return: value or None
            :rtype:  any type
        '''
        # has_key is required here, as we operate on the dict class

        if not self.parent.has_key(key) and not key.startswith('linotp.'):
            key = 'linotp.' + key

        # return default only if key does not exist
        res = self.parent.get(key, default)
        return res

    def has_key(self, key):
        res = self.parent.has_key(key)
        if res is False and key.startswith('linotp.') is False:
            key = 'linotp.' + key

        res = self.parent.has_key(key)

        if res is False and key.startswith('enclinotp.') is False:
            key = 'enclinotp.' + key

        res = self.parent.has_key(key)

        return res

    def __delitem__(self, key):
        '''
        remove an item from the config

        :param key: the name of the ocnfig entry
        :type  key: string

        :return : return the std value like the std dict does, whatever this is
        :rtype  : any value a dict update will return
        '''
        Key = key

        if self.parent.has_key(key):
            Key = key

        elif self.parent.has_key('linotp.' + key):
            Key = 'linotp.' + key

        res = self.parent.__delitem__(Key)

        # sync with global dict

        self.glo.delConfig(Key)

        # sync with db
        if key.startswith('linotp.'):
            Key = key
        else:
            Key = 'linotp.' + key

        _removeConfigDB(Key)
        _storeConfigDB('linotp.Config', datetime.now())

        return res

    def __contains__(self, key):
        """
        support for 'in' operator of the Config dict
        """
        res = (self.parent.__contains__(key) or
               self.parent.__contains__('linotp.' + key))
        return res

    def update(self, dic):
        '''
        update the config dict with multiple items in a dict

        :param dic: dictionary of multiple items
        :type  dic: dict

        :return : return the std value like the std dict does, whatever this is
        :rtype  : any value a dict update will return
        '''

        #
        # first check if all data is type compliant
        #

        for key, val in dic.items():
            self._check_type(key, val)

        #
        # put the data in the parent dictionary
        #

        res = self.parent.update(dic)

        #
        # and sync the data with the global config dict
        #

        self.glo.setConfig(dic)

        #
        # finally sync the entries to the database
        #

        for key in dic:
            if key != 'linotp.Config':
                _storeConfigDB(key, dic.get(key))

        _storeConfigDB('linotp.Config', datetime.now())
        return res


###############################################################################
#  helper class from here
###############################################################################

def _getConfigFromEnv():

    linotpConfig = {}

    try:
        _getConfigReadLock()
        for entry in env.config:
            # we check for the modification time of the config file
            if entry == '__file__':
                fname = env.config.get('__file__')
                mTime = time.localtime(os.path.getmtime(fname))
                modTime = datetime(*mTime[:6])
                linotpConfig['linotp.Config'] = modTime

            if entry.startswith("linotp."):
                linotpConfig[entry] = expand_here(env.config[entry])
            if entry.startswith("enclinotp."):
                linotpConfig[entry] = env.config[entry]
        _releaseConfigLock()
    except Exception as e:
        log.exception('Error while reading config: %r' % e)
        _releaseConfigLock()
    return linotpConfig


# eof #

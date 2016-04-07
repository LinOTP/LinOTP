# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
'''handle all configuration items with aspekts like persitance and
   syncronysation and provides this to all requests
'''

import logging
import time
import os
import copy

from pylons import tmpl_context as c
from linotp.config import environment as env

from linotp.lib.error import ConfigAdminError

from linotp.model import Config
from linotp.model.meta import Session

from linotp.lib.crypt import encryptPassword
from linotp.lib.crypt import decryptPassword

from datetime import datetime



log = logging.getLogger(__name__)

ENCODING = 'utf-8'


###############################################################################
# #     public interface
###############################################################################

def initLinotpConfig():
    '''
    return the linotpConfig class, which is integrated
    in the local thread context

    :return: thread local LinOtpConfig
    :rtype:  LinOtpConfig Class
    '''
    log.debug("[getLinotpConfig]")

    ret = getLinotpConfig()

    log.debug("[/getLinotpConfig]")
    return ret


def getLinotpConfig():
    '''
    return the thread local dict with all entries

    :return: local config dict
    :rtype: dict
    '''

    ret = {}
    try:
        if False == hasattr(c, 'linotpConfig'):
            c.linotpConfig = LinOtpConfig()

        ty = type(c.linotpConfig).__name__
        if ty != 'LinOtpConfig':
            try:
                c.linotpConfig = LinOtpConfig()
            except Exception as e:
                log.exception("Linotp Definition Error")
                raise Exception(e)
        ret = c.linotpConfig

        if ret.delay == True:
            if hasattr(c, 'hsm') == True and isinstance(c.hsm, dict):
                hsm = c.hsm.get('obj')
                if hsm is not None and hsm.isReady() == True:
                    ret = LinOtpConfig()
                    c.linotpConfig = ret


    except Exception as e:
        log.debug("Bad Hack: LinotpConfig called out of controller context")
        ret = LinOtpConfig()

        if ret.delay == True:
            if hasattr(c, 'hsm') == True and isinstance(c.hsm, dict):
                hsm = c.hsm.get('obj')
                if hsm is not None and hsm.isReady() == True:
                    ret = LinOtpConfig()

    finally:
        log.debug("[getLinotpConfig]")

    return ret

###############################################################################
# #     implementation class
###############################################################################
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

        if self.glo.isConfigComplet() == False:
            do_reload = True
            self.delay = True

        if 'linotp.enableReplication' in conf:
            val = conf.get('linotp.enableReplication')
            if val.lower() == 'true':

                # # look for the timestamp when config was created
                e_conf_date = conf.get('linotp.Config')

                # # in case of replication, we always have to look if the
                # # config data in the database changed
                db_conf_date = _retrieveConfigDB('linotp.Config')

                if str(db_conf_date) != str(e_conf_date):
                    do_reload = True

        return self.refreshConfig(do_reload=do_reload)

    def refreshConfig(self, do_reload=False):

        conf = self.glo.getConfig()

        if do_reload == True:
            # # in case there is no entry in the dbconf or
            # # the config file is newer, we write the config back to the db
            entries = conf.keys()
            for entry in entries:
                del conf[entry]

            writeback = False
            # # get all conf entries from the config file
            fileconf = _getConfigFromEnv()

            # #  get all configs from the DB
            (dbconf, delay) = _retrieveAllConfigDB()
            self.glo.setConfigIncomplete(not delay)

            # # we only merge the config file once as a removed entry
            # #  might reappear otherwise
            if dbconf.has_key('linotp.Config') == False:
                conf.update(fileconf)
                writeback = True
            # #
            # #else:
            # #    modCFFileDatum = fileconf.get('linotp.Config')
            # #    dbTimeStr = dbconf.get('linotp.Config')
            # #    dbTimeStr = dbTimeStr.split('.')[0]
            # #    modDBFileDatum =
            # #           datetime.strptime(dbTimeStr,'%Y-%m-%d %H:%M:%S')
            # #    # if configFile timestamp is newer than last update:
            # #    #             reincorporate conf
            # #    #if modCFFileDatum > modDBFileDatum:
            # #    #    conf.update(fileconf)
            # #    #    writeback = True
            # #

            conf.update(dbconf)
            # # chck, if there is a selfTest in the DB and delete it
            if dbconf.has_key('linotp.selfTest'):
                _removeConfigDB('linotp.selfTest')
                _storeConfigDB('linotp.Config', datetime.now())

            # # the only thing we take from the fileconf is the selftest
            if fileconf.has_key('linotp.selfTest'):
                conf['linotp.selfTest'] = 'True'

            if writeback == True:
                for con in conf:
                    if con != 'linotp.selfTest':
                        _storeConfigDB(con, conf.get(con))
                _storeConfigDB('linotp.Config', datetime.now())

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
        if key.startswith('linotp.') == False:
            key = 'linotp.' + key

        if type(val) in [str, unicode] and "%(here)s" in val:
            val = _expandHere(val)

        res = self.__setitem__(key, val, typ, des)
        return res

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

        if typ == 'password':

            # # in case we have a password type, we have to put
            # #- in the config only the encrypted pass and
            # #- add the config enclinotp.* with the clear password

            res = self.parent.__setitem__(key, encryptPassword(val))
            res = self.parent.__setitem__('enc' + key, val)
            self.glo.setConfig({key :encryptPassword(val)})
            self.glo.setConfig({'enc' + key : val})

        else:
            # # update this config and sync with global dict and db
            nVal = _expandHere(val)
            res = self.parent.__setitem__(key, nVal)
            self.glo.setConfig({key:nVal})

        _storeConfigDB(key, val, typ, des)
        _storeConfigDB('linotp.Config', datetime.now())
        return res

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
        if (self.parent.has_key(key) == False
                and key.startswith('linotp.') == False):
            key = 'linotp.' + key

        # return default only if key does not exist
        res = self.parent.get(key, default)
        return res

    def has_key(self, key):
        res = self.parent.has_key(key)
        if res == False and key.startswith('linotp.') == False:
            key = 'linotp.' + key

        res = self.parent.has_key(key)

        if res == False and key.startswith('enclinotp.') == False:
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
        encKey = None
        if self.parent.has_key(key):
            Key = key
        elif self.parent.has_key('linotp.' + key):
            Key = 'linotp.' + key

        if self.parent.has_key('enclinotp.' + key):
            encKey = 'enclinotp.' + key
        elif self.parent.has_key('enc' + key):
            encKey = 'enc' + key

        res = self.parent.__delitem__(Key)
        # # sync with global dict
        self.glo.delConfig(Key)

        # # do we have an decrypted in local or global dict??
        if encKey is not None:
            res = self.parent.__delitem__(encKey)
            # # sync with global dict
            self.glo.delConfig(encKey)

        # # sync with db
        if key.startswith('linotp.'):
            Key = key
        else:
            Key = 'linotp.' + key

        _removeConfigDB(Key)
        _storeConfigDB('linotp.Config', datetime.now())
        return res

    def update(self, dic):
        '''
        update the config dict with multiple items in a dict

        :param dic: dictionary of multiple items
        :type  dic: dict

        :return : return the std value like the std dict does, whatever this is
        :rtype  : any value a dict update will return
        '''
        res = self.parent.update(dic)
        # # sync the lobal dict
        self.glo.setConfig(dic)
        # # sync to disc
        for key in dic:
            if key != 'linotp.Config':
                _storeConfigDB(key, dic.get(key))

        _storeConfigDB('linotp.Config', datetime.now())
        return res


###############################################################################
# #  helper class from here
###############################################################################
def getGlobalObject():
    glo = None

    try:
        if env.config.has_key('pylons.app_globals'):
            glo = env.config['pylons.app_globals']
        elif env.config.has_key('pylons.g'):
            glo = env.config['pylons.g']
    except:
        glo = None
    return glo

def _getConfigReadLock():
    glo = getGlobalObject()
    rcount = glo.setConfigReadLock()
    log.debug(" --------------------------------------- Read Lock %s" % rcount)

def _getConfigWriteLock():
    glo = getGlobalObject()
    rcount = glo.setConfigWriteLock()
    log.debug(" ------------------- ------------------ Write Lock %s" % rcount)

def _releaseConfigLock():
    glo = getGlobalObject()
    rcount = glo.releaseConfigLock()
    log.debug(" ------------------------------------ release Lock %s" % rcount)



def _expandHere(value):
    log.debug('[_expandHere] value: %r' % value)

    Value = unicode(value)
    if env.config.has_key("linotp.root"):
        root = env.config["linotp.root"]
        Value = Value.replace("%(here)s", root)
    return Value


def _getConfigFromEnv():
    log.debug('[getLinotpConfig]')
    linotpConfig = {}

    try:
        _getConfigReadLock()
        for entry in env.config:
            # # we check for the modification time of the config file
            if entry == '__file__':
                fname = env.config.get('__file__')
                mTime = time.localtime(os.path.getmtime(fname))
                modTime = datetime(*mTime[:6])
                linotpConfig['linotp.Config'] = modTime

            if entry.startswith("linotp."):
                linotpConfig[entry] = _expandHere(env.config[entry])
            if entry.startswith("enclinotp."):
                linotpConfig[entry] = env.config[entry]
        _releaseConfigLock()
    except Exception as e:
        log.exception('Error while reading Config: %r' % e)
        _releaseConfigLock()
    return linotpConfig


# we insert or update the key / value the config DB
def _storeConfigDB(key, val, typ=None, desc=None):
    value = val
    log.debug('storeConfigDB: key %r : value %r' % (key, value))

    if (not key.startswith("linotp.")):
        key = "linotp." + key

    confEntries = Session.query(Config).filter(Config.Key == unicode(key))
    theConf = None

    if typ is not None and typ == 'password':
        value = encryptPassword(val)
        en = decryptPassword(value)
        if (en != val):
            raise Exception("StoreConfig: Error during encoding password type!")

    # # update
    if confEntries.count() == 1:
        theConf = confEntries[0]
        theConf.Value = unicode(value)
        if (typ is not None):
            theConf.Type = unicode(typ)
        if (desc is not None):
            theConf.Description = unicode(desc)

    # # insert
    elif confEntries.count() == 0:
        theConf = Config(
                        Key=unicode(key),
                        Value=unicode(value),
                        Type=unicode(typ),
                        Description=unicode(desc)
                        )
    if theConf is not None:
        Session.add(theConf)

    return 101

def _removeConfigDB(key):
    log.debug('removeConfigDB %r' % key)
    num = 0

    if (not key.startswith("linotp.")):
        if not key.startswith('enclinotp.'):
            key = u"linotp." + key

    confEntries = Session.query(Config).filter(Config.Key == unicode(key))

    num = confEntries.count()
    if num == 1:
        theConf = confEntries[0]

        try:
            # Session.add(theConf)
            Session.delete(theConf)

        except Exception as e:
            log.exception('[removeConfigDB] failed')
            raise ConfigAdminError("remove Config failed for %r: %r"
                                   % (key, e), id=1133)

    return num

def _retrieveConfigDB(Key):
    log.debug('[retrieveConfigDB] key: %r' % Key)

    # # prepend "lonotp." if required
    key = Key
    if (not key.startswith("linotp.")):
        if (not key.startswith("enclinotp.")):
            key = "linotp." + Key

    myVal = None
    key = u'' + key
    for theConf in Session.query(Config).filter(Config.Key == key):
        myVal = theConf.Value
        myVal = _expandHere(myVal)
    return myVal

def _retrieveAllConfigDB():

    config = {}
    delay = False
    for conf in Session.query(Config).all():
        log.debug("[retrieveAllConfigDB] key %r:%r" % (conf.Key, conf.Value))
        key = conf.Key
        if (not key.startswith("linotp.")):
            key = "linotp." + conf.Key
        nVal = _expandHere(conf.Value)
        config[key] = nVal
        myTyp = conf.Type
        if myTyp is not None:
            if myTyp == 'password':
                if hasattr(c, 'hsm') == True and isinstance(c.hsm, dict):
                    hsm = c.hsm.get('obj')
                    if hsm is not None and hsm.isReady() == True:
                        config['enc' + key] = decryptPassword(conf.Value)
                else:
                    delay = True

    return (config, delay)

########### external interfaces ###############
def storeConfig(key, val, typ=None, desc=None):
    log.debug('[storeConfig] %r:%r' % (key, val))
    conf = getLinotpConfig()
    conf.addEntry(key, val, typ, desc)
    log.debug('[/storeConfig]')
    return True

def updateConfig(confi):
    '''
    update the server config entries incl. syncing it to disc
    '''
    log.debug('[updateConfig]')
    conf = getLinotpConfig()


    # # remember all key, which should be processed
    p_keys = copy.deepcopy(confi)

    typing = False

    for entry in confi:
        typ = confi.get(entry + ".type", None)
        des = confi.get(entry + ".desc", None)
        # # check if we have a descriptive entry
        if typ is not None or des is not None:
            typing = True
            if typ is not None:
                del p_keys[entry + ".type"]
            if des is not None:
                del p_keys[entry + ".desc"]

    if typing == True:
        # # tupple dict containing the additional info
        t_dict = {}
        for entry in p_keys:
            val = confi.get(entry)
            typ = confi.get(entry + ".type", None)
            des = confi.get(entry + ".desc", None)
            t_dict[entry] = (val, typ or "string", des)

        for key in t_dict:
            (val, typ, desc) = t_dict.get(key)
            if val in [str, unicode] and "%(here)s" in val:
                val = _expandHere(val)
            conf.addEntry(key, val, typ, desc)

    else:
        conf_clean = {}
        for key, val in confi.iteritems():
            if "%(here)s" in val:
                val = _expandHere(val)
            conf_clean[key] = val

        conf.update(conf_clean)

    log.debug('[/updateConfig]')
    return True

def getFromConfig(key, defVal=None):
    log.debug('[getFromConfig] key:  %s' % key)
    conf = getLinotpConfig()
    value = conf.get(key, defVal)
    return value

def refreshConfig():
    log.debug('[refreshConfig]')
    conf = getLinotpConfig()
    conf.refreshConfig(do_reload=True)
    return

def removeFromConfig(key, iCase=False):
    log.debug('[removeFromConfig] key:  %r' % key)
    conf = getLinotpConfig()

    if iCase == False:
        if conf.has_key(key):
            del conf[key]
    else:
        # # case insensitive delete
        # #- might have multiple hits
        fConf = []
        for k in conf:
            if (k.lower() == key.lower() or
                  k.lower() == 'linotp.' + key.lower()):
                fConf.append(k)

        if len(fConf) > 0:
            for k in fConf:
                if conf.has_key(k) or conf.has_key('linotp.' + k):
                    del conf[k]

    log.debug('[/removeFromConfig]')
    return True


#### several config functions to follow
def setDefaultMaxFailCount(maxFailCount):
    return storeConfig(u"DefaultMaxFailCount", maxFailCount)

def setDefaultSyncWindow(syncWindowSize):
    return storeConfig(u"DefaultSyncWindow", syncWindowSize)

def setDefaultCountWindow(countWindowSize):
    return storeConfig(u"DefaultCountWindow", countWindowSize)

def setDefaultOtpLen(otpLen):
    return storeConfig(u"DefaultOtpLen", otpLen)

def setDefaultResetFailCount(resetFailCount):
    return storeConfig(u"DefaultResetFailCount", resetFailCount)


#eof###########################################################################


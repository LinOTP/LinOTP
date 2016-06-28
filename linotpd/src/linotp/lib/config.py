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

import copy
from datetime import datetime
from linotp.config import environment as env
from linotp.lib.crypt import decryptPassword
from linotp.lib.crypt import encryptPassword
from linotp.lib.error import ConfigAdminError
from linotp.model import Config
from linotp.model.meta import Session
import logging
import os
import time

from pylons import tmpl_context as c


ENCODING = 'utf-8'
MAX_VALUE_LEN = 2000

log = logging.getLogger(__name__)

###############################################################################
#     public interface
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

        if ret.delay is True:
            if hasattr(c, 'hsm') is True and isinstance(c.hsm, dict):
                hsm = c.hsm.get('obj')
                if hsm is not None and hsm.isReady() is True:
                    ret = LinOtpConfig()
                    c.linotpConfig = ret

    except Exception as e:
        log.debug("Bad Hack: LinotpConfig called out of controller context")
        ret = LinOtpConfig()

        if ret.delay is True:
            if hasattr(c, 'hsm') is True and isinstance(c.hsm, dict):
                hsm = c.hsm.get('obj')
                if hsm is not None and hsm.isReady() is True:
                    ret = LinOtpConfig()

    finally:
        log.debug("[getLinotpConfig]")

    return ret


###############################################################################
#      implementation class
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

        return self.refreshConfig(do_reload=do_reload)

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
        if key.startswith('linotp.') is False:
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

        now = datetime.now()

        if typ == 'password':

            # in case we have a password type, we have to put
            # #- in the config only the encrypted pass and
            # #- add the config enclinotp.* with the clear password

            res = self.parent.__setitem__(key, encryptPassword(val))
            res = self.parent.__setitem__('enc' + key, val)
            self.glo.setConfig({key: encryptPassword(val)})
            self.glo.setConfig({'enc' + key: val})

        else:
            # update this config and sync with global dict and db
            nVal = _expandHere(val)
            res = self.parent.__setitem__(key, nVal)
            self.glo.setConfig({key: nVal})

        # syncronize as well the global timestamp
        self.glo.setConfig({'linotp.Config': unicode(now)})

        _storeConfigDB(key, val, typ, des)
        _storeConfigDB('linotp.Config', now)

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
        if (self.parent.has_key(key) is False
                and key.startswith('linotp.') is False):
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
        # sync with global dict
        self.glo.delConfig(Key)

        # do we have an decrypted in local or global dict??
        if encKey is not None:
            res = self.parent.__delitem__(encKey)
            # sync with global dict
            self.glo.delConfig(encKey)

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
        res = self.parent.update(dic)
        # sync the lobal dict
        self.glo.setConfig(dic)
        # sync to disc
        for key in dic:
            if key != 'linotp.Config':
                _storeConfigDB(key, dic.get(key))

        _storeConfigDB('linotp.Config', datetime.now())
        return res


###############################################################################
#  helper class from here
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
            # we check for the modification time of the config file
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


def _storeConfigDB(key, val, typ=None, desc=None):
    """
    insert or update the entry with  key, value, type and
    description in the config DB

    """
    value = val

    log_value = val
    if typ == 'password':
        log_value = "XXXXXXX"
    log.debug('key %r : value %r', key, log_value)

    if (not key.startswith("linotp.")):
        key = "linotp." + key

    if typ and typ == 'password':
        value = encryptPassword(val)
        en = decryptPassword(value)
        if (en != val):
            raise Exception("Error during encoding password type!")

    if type(value) not in [str, unicode]:
        return _storeConfigEntryDB(key, value, typ=typ, desc=desc)

    # for strings or unicode, we support continued entries
    # check if we have to split the value
    number_of_chunks = (len(value) / MAX_VALUE_LEN)
    if number_of_chunks == 0:
        return _storeConfigEntryDB(key, value, typ=typ, desc=desc)

    # the continuous type is a split over multiple entries:
    # * every entry will have an enumerated key but the first one which has the
    #   original one.
    # * For all the type is 'C', but the last one which contains the original
    #   type.
    # * For description all entries contains the enumeration, but the last the
    #   original description

    for i in range(number_of_chunks + 1):
        # iterate through the chunks, the last one might be empty though
        cont_value = value[i * MAX_VALUE_LEN: (i + 1) * MAX_VALUE_LEN]

        cont_typ = "C"
        cont_desc = "%d:%d" % (i, number_of_chunks)
        cont_key = "%s__[%d:%d]" % (key, i, number_of_chunks)

        if i == 0:
            # first one will contain the correct key, but type is continuous
            cont_key = key
        elif i == number_of_chunks:
            # the last one will contain the type and the description
            cont_typ = typ
            cont_desc = desc

        res = _storeConfigEntryDB(cont_key, cont_value,
                                  typ=cont_typ,
                                  desc=cont_desc)

    return res


def _storeConfigEntryDB(key, value, typ=None, desc=None):
    """
    lowest level for storing database entries in the config table
    """

    confEntries = Session.query(Config).filter(Config.Key == unicode(key))
    theConf = None

    # update
    if confEntries.count() == 1:
        theConf = confEntries[0]
        theConf.Value = unicode(value)
        if (typ is not None):
            theConf.Type = unicode(typ)
        if (desc is not None):
            theConf.Description = unicode(desc)

    # insert
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
    """
    remove entry from config table

    :param key: the name of the entry
    :return: number of deleted entries
    """
    log.debug('removeConfigDB %r' % key)

    if (not key.startswith("linotp.")):
        if not key.startswith('enclinotp.'):
            key = u"linotp." + key

    confEntries = Session.query(Config).filter(Config.Key == unicode(key)).all()

    if not confEntries:
        return 0

    theConf = confEntries[0]

    to_be_deleted = []
    to_be_deleted.append(theConf)

    # if entry is a contious type, delete all of this kind
    if theConf.Type == 'C' and theConf.Description[:len('0:')] == '0:':
        _start, end = theConf.Description.split(':')
        search_key = "%s__[%%:%s]" % (key, end)
        cont_entries = Session.query(Config).filter(Config.Key.like(search_key)).all()
        to_be_deleted.extend(cont_entries)

    try:
        for entry in to_be_deleted:
            # Session.add(theConf)
            Session.delete(entry)

    except Exception as e:
        log.exception('[removeConfigDB] failed')
        raise ConfigAdminError("remove Config failed for %r: %r"
                               % (key, e), id=1133)

    return len(to_be_deleted)


def _retrieveConfigDB(Key):
    log.debug('[retrieveConfigDB] key: %r' % Key)

    # prepend "lonotp." if required
    key = Key
    if (not key.startswith("linotp.")):
        if (not key.startswith("enclinotp.")):
            key = "linotp." + Key

    myVal = None
    key = u'' + key
    entries = Session.query(Config).filter(Config.Key == key).all()

    if not entries:
        return None

    theConf = entries[0]

    # other types than continous: we are done
    if theConf.Type != 'C':
        myVal = theConf.Value
        myVal = _expandHere(myVal)
        return myVal

    # else we have the continue type: we iterate over all entries where the
    # number of entries is stored in the description as range end
    _start, end = theConf.Description.split(':')

    # start accumulating the value
    value = theConf.Value

    for i in range(int(end)):
        search_key = "%s__[%d:%d]" % (key, i, int(end))
        cont_entries = Session.query(Config).filter(Config.Key == search_key).all()
        if cont_entries:
            value = value + cont_entries[0].Value

    return value


def _retrieveAllConfigDB():
    """
    get the server config from database with one call

    remark: for support for continous entries dedicated dicts for
            description and type are used for interim processing

    :return: config dict
    """

    config = {}
    delay = False

    conf_dict = {}
    type_dict = {}
    desc_dict = {}
    cont_dict = {}

    # put all information in the dicts for later processing
    for conf in Session.query(Config).all():
        log.debug("[retrieveAllConfigDB] key %r:%r" % (conf.Key, conf.Value))
        conf_dict[conf.Key] = conf.Value
        type_dict[conf.Key] = conf.Type
        desc_dict[conf.Key] = conf.Description

        # a continous entry is indicated by the type 'C' and the description
        # starting with '0:'
        if conf.Type == 'C' and conf.Description[:len('0:')] == '0:':
            _start, num = conf.Description.split(':')
            cont_dict[conf.Key] = int(num)

    # cleanup the config from contious entries
    for key, number in cont_dict.items():
        value = conf_dict[key]
        for i in range(number + 1):
            search_key = "%s__[%d:%d]" % (key, i, number)
            if search_key in conf_dict:
                value = value + conf_dict[search_key]
                del conf_dict[search_key]
        conf_dict[key] = value
        search_key = "%s__[%d:%d]" % (key, number, number)
        type_dict[key] = type_dict[search_key]
        desc_dict[key] = desc_dict[search_key]

    # normal processing as before continous here
    for key, value in conf_dict.items():
        if key.startswith("linotp.") is False:
            key = "linotp." + key
        nVal = _expandHere(value)
        config[key] = nVal

    for key, value in config.items():
        myTyp = type_dict.get(key)
        if myTyp is not None:
            if myTyp == 'password':
                if hasattr(c, 'hsm') is True and isinstance(c.hsm, dict):
                    hsm = c.hsm.get('obj')
                    if hsm is not None and hsm.isReady() is True:
                        config['enc' + key] = decryptPassword(value)
                else:
                    delay = True

    return (config, delay)


# ########## external interfaces ###############
def storeConfig(key, val, typ=None, desc=None):

    log_val = val
    if type and typ == 'password':
        log_val = "XXXXXXX"
    log.debug('[storeConfig] %r:%r' % (key, log_val))

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

    # remember all key, which should be processed
    p_keys = copy.deepcopy(confi)

    typing = False

    for entry in confi:
        typ = confi.get(entry + ".type", None)
        des = confi.get(entry + ".desc", None)
        # check if we have a descriptive entry
        if typ is not None or des is not None:
            typing = True
            if typ is not None:
                del p_keys[entry + ".type"]
            if des is not None:
                del p_keys[entry + ".desc"]

    if typing is True:
        # tupple dict containing the additional info
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

    if iCase is False:
        if key in conf:
            del conf[key]
    else:
        # case insensitive delete
        # #- might have multiple hits
        fConf = []
        for k in conf:
            if (k.lower() == key.lower() or
               k.lower() == 'linotp.' + key.lower()):
                fConf.append(k)

        if len(fConf) > 0:
            for k in fConf:
                if k in conf or 'linotp.' + k in conf:
                    del conf[k]

    log.debug('[/removeFromConfig]')
    return True


# several config functions to follow
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

# eof #########################################################################

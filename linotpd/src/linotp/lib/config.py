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
'''handle all configuration items with aspekts like persitance and
   syncronysation and provides this to all requests
'''

import copy
from datetime import datetime
from linotp.config import environment as env
from linotp.lib.crypto import decryptPassword
from linotp.lib.crypto import encryptPassword
from linotp.lib.error import ConfigAdminError
from linotp.model import Config
from linotp.model.meta import Session


from linotp.lib.text_utils import UTF8_MAX_BYTES
from linotp.lib.text_utils import simple_slice
from linotp.lib.text_utils import utf8_slice

from linotp.lib.type_utils import is_duration

import logging
import os
import time

from pylons import tmpl_context as c

import linotp.model.meta


Config_Types = {
    'linotp.user_lookup_cache.expiration':  ('duration', is_duration),
    'linotp.resolver_lookup_cache.expiration': ('duration', is_duration),
    }


Session = linotp.model.meta.Session


ENCODING = 'utf-8'

#
# MAX_VALUE_LEN defines the max len before we split the config entries into
#  continuous config entries blocks.
#


MAX_VALUE_LEN = 2000 - UTF8_MAX_BYTES


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
    ret = getLinotpConfig()
    return ret


def getLinotpConfig():
    '''
    return the thread local dict with all entries

    :return: local config dict
    :rtype: dict
    '''

    ret = {}
    try:
        if not hasattr(c, 'linotpConfig'):
            c.linotpConfig = LinOtpConfig()

        ty = type(c.linotpConfig).__name__
        if ty != 'LinOtpConfig':
            try:
                c.linotpConfig = LinOtpConfig()
            except Exception as exx:
                log.exception("Could not add LinOTP configuration to pylons "
                              "tmpl_context. Exception was: %r", exx)
                raise exx
        ret = c.linotpConfig

        if ret.delay is True:
            if hasattr(c, 'hsm') is True and isinstance(c.hsm, dict):
                hsm = c.hsm.get('obj')
                if hsm is not None and hsm.isReady() is True:
                    ret = LinOtpConfig()
                    c.linotpConfig = ret

    except Exception as e:
        log.debug("Bad Hack: Retrieving LinotpConfig without "
                  "controller context")
        ret = LinOtpConfig()

        if ret.delay is True:
            if hasattr(c, 'hsm') is True and isinstance(c.hsm, dict):
                hsm = c.hsm.get('obj')
                if hsm is not None and hsm.isReady() is True:
                    ret = LinOtpConfig()

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

        self._check_type(key, val)

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

        self._check_type(key, val)

        if typ == 'password':

            # in case we have a password type, we have to put
            # - in the config only the encrypted pass and
            # - add the config enclinotp.* with the clear password

            utf_val = val.encode('utf-8')

            # store in request local config dict

            res = self.parent.__setitem__(key, encryptPassword(utf_val))
            res = self.parent.__setitem__('enc' + key, val)

            # store in global config

            self.glo.setConfig({key: encryptPassword(utf_val)})
            self.glo.setConfig({'enc' + key: val})

        else:

            # update this config and sync with global dict and db

            nVal = _expandHere(val)
            res = self.parent.__setitem__(key, nVal)
            self.glo.setConfig({key: nVal})

        # ----------------------------------------------------------------- --

        # finally store the entry in the database and
        # syncronize as well the global timestamp

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


def _getConfigWriteLock():
    glo = getGlobalObject()
    rcount = glo.setConfigWriteLock()


def _releaseConfigLock():
    glo = getGlobalObject()
    rcount = glo.releaseConfigLock()


def _expandHere(value):
    Value = unicode(value)
    if env.config.has_key("linotp.root"):
        root = env.config["linotp.root"]
        Value = Value.replace("%(here)s", root)
    return Value


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
                linotpConfig[entry] = _expandHere(env.config[entry])
            if entry.startswith("enclinotp."):
                linotpConfig[entry] = env.config[entry]
        _releaseConfigLock()
    except Exception as e:
        log.exception('Error while reading config: %r' % e)
        _releaseConfigLock()
    return linotpConfig


def _storeConfigDB(key, val, typ=None, desc=None):
    """
    insert or update the entry with  key, value, type and
    description in the config DB

    :param key: the config entry key, should start with 'linotp.'
    :param val: the value
    :param typ: the linotp typ, which could be text, int or password
    :param desc: the description which comes along with the key
    """

    value = val
    if (not key.startswith("linotp.")):
        key = "linotp." + key
    log_value = 'XXXXXX' if typ == 'password' else value
    log.debug('Changing config entry %r in database: New value is %r',
              key, log_value)

    # ---------------------------------------------------------------------- --

    # in case of an encrypted entry where the typ is 'password', we store
    # only the encrypted value

    # ---------------------------------------------------------------------- --

    # passwords are encrypted from here

    if typ and typ == 'password':
        value = encryptPassword(val.encode('utf-8'))

    # ---------------------------------------------------------------------- --

    # for types other than string such int, float or datetime, we do a simple
    # storeing

    if not (isinstance(value, str) or isinstance(value, unicode)):
        return _storeConfigEntryDB(key, value, typ=typ, desc=desc)

    # ---------------------------------------------------------------------- --

    # if there are chunked entries for this key we delete them to prevent
    # dangling, not updated entries

    _delete_continous_entry_db(key)

    # ---------------------------------------------------------------------- --

    # the split algorithm depends on the value data -
    # in case of only ascii, we can use the much faster simple algorithm
    # in case of unicode characters we have to take the much slower one

    # for 'utf8_slice' the number of chunks is oriented toward the max length
    # defined by utf8 in bytes + the clipping of 6 bytes each. But as this
    # could vary, we could not calculate the number of chunks and thus use
    # an iterator to split the value into chunks

    chunks = []
    if len(value) < len(value.encode('utf-8')):
        text_slice = utf8_slice
    else:
        text_slice = simple_slice

    for cont_value in text_slice(value, MAX_VALUE_LEN):
        chunks.append(cont_value)

    # ---------------------------------------------------------------------- --

    # finally store either single entry or multiple chunks

    if len(chunks) == 1:
        return _storeConfigEntryDB(key, value, typ=typ, desc=desc)

    return _store_continous_entry_db(chunks, key, val, typ, desc)


def _delete_continous_entry_db(key):
    """
    delete all chunk entries of a key

    in case of an update of an continous entry, the new set of entries might
    be smaller than the old one. So if we try to store the continous entry, we
    first have to remove all chunks

    :param key: the key prefix of the chunks
    """

    search_key = "%s__[%%:%%]" % (key)
    continous_entries = Session.query(Config).filter(
                                      Config.Key.like(search_key))

    for continous_entry in continous_entries:
        Session.delete(continous_entry)


def _store_continous_entry_db(chunks, key, val, typ, desc):
    """
    store continous entries -
    for strings or unicode, we support continued entries

    the continuous type is a split over multiple entries:

    normal Config Entry:
    +-----------------+---------------------------+-------+-------------+
    | key             | value                     |  type | description |
    +-----------------+---------------------------+-------+-------------+
    | small_val       | <small chunk of data>     | 'text' | 'my cert'  |
    +-----------------+---------------------------+-------+-------------+

    continous Config Entry:
    +-------------------+---------------------------+--------+-------------+
    | key               | value                     |  type  | description |
    +-------------------+---------------------------+--------+-------------+
    | long_value        | <big chunk > part 0       | 'C'    | '0:3'       |
    +-------------------+---------------------------+--------+-------------+
    | long_value__[1:3] | <big chunk > part 1       | 'C'    | '1:3'       |
    +----------------..-+---------------------------+--------+-------------+
    | long_value__[2:3] | <big chunk > part 2       | 'C'    | '2:3'       |
    +-------------------+---------------------------+--------+-------------+
    | long_value__[3:3] | <big chunk > part 3       | 'text' | 'my cert'   |
    +-------------------+---------------------------+--------+-------------+

    handling of key, type and description in chunked entries:

    key: every entry will have an enumerated key but the first one which
         has the original one.

    type: for all the entries the type is 'C', but the last one which
          contains the original type.

    descr: for all entries the description contains the enumeration like 0:3,
           which to be read as 'this is part 0 of 3 chunks'. the last entry
           contains the the original description

    :params key: the key
    :params val: the value
    :params val: the value
    :params desc: the desctiption
    :params chunks: the array of the split up entries
    """

    number_of_chunks = len(chunks)

    for i, cont_value in enumerate(chunks):

        cont_typ = "C"
        cont_desc = "%d:%d" % (i, number_of_chunks - 1)
        cont_key = "%s__[%d:%d]" % (key, i, number_of_chunks - 1)

        # first one will contain the correct key with type 'C' continuous
        if i == 0:
            cont_key = key

        # the last one will contain the correct type and description
        elif i == number_of_chunks - 1:
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
        theConf.Type = typ
        theConf.Description = desc

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
    log.debug('removing config entry %r from database table' % key)

    if (not key.startswith("linotp.")):
        if not key.startswith('enclinotp.'):
            key = u"linotp." + key

    confEntries = Session.query(Config).filter(
                                        Config.Key == unicode(key)).all()

    if not confEntries:
        return 0

    theConf = confEntries[0]

    to_be_deleted = []
    to_be_deleted.append(theConf)

    # if entry is a contious type, delete all of this kind
    if theConf.Type == 'C' and theConf.Description[:len('0:')] == '0:':
        _start, end = theConf.Description.split(':')
        search_key = "%s__[%%:%s]" % (key, end)
        cont_entries = Session.query(Config).filter(
                                     Config.Key.like(search_key)).all()
        to_be_deleted.extend(cont_entries)

    try:
        for entry in to_be_deleted:
            # Session.add(theConf)
            Session.delete(entry)

    except Exception as e:
        raise ConfigAdminError("remove Config failed for %r: %r"
                               % (key, e), id=1133)

    return len(to_be_deleted)


def _retrieveConfigDB(Key):

    # prepend "linotp." if required
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
        cont_entries = Session.query(Config).filter(
                                            Config.Key == search_key).all()
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

    db_config = Session.query(Config).all()

    # put all information in the dicts for later processing

    for conf in db_config:
        log.debug("[retrieveAllConfigDB] key %r:%r" % (conf.Key, conf.Value))

        conf_dict[conf.Key] = conf.Value
        type_dict[conf.Key] = conf.Type
        desc_dict[conf.Key] = conf.Description

        # a continuous entry is indicated by the type 'C' and the description
        # search for the entry which starts with '0:' as it will provide the
        # number of continuous entries

        if conf.Type == 'C' and conf.Description[:len('0:')] == '0:':
            _start, num = conf.Description.split(':')
            cont_dict[conf.Key] = int(num)

    # cleanup the config from continous entries

    for key, number in cont_dict.items():

        value = conf_dict[key]

        for i in range(number + 1):

            search_key = "%s__[%d:%d]" % (key, i, number)

            if search_key in conf_dict:
                value = value + conf_dict[search_key]
                del conf_dict[search_key]

        conf_dict[key] = value

        search_key = "%s__[%d:%d]" % (key, number, number)

        # allow the reading of none existing entries

        type_dict[key] = type_dict.get(search_key)
        desc_dict[key] = desc_dict.get(search_key)

    # normal processing as before continous here

    for key, value in conf_dict.items():

        if key.startswith("linotp.") is False:
            key = "linotp." + key

        nVal = _expandHere(value)
        config[key] = nVal

    # ---------------------------------------------------------------------- --

    # special treatment of passwords, which are provided decrypted as
    # 'enclinotp.' linotp-config entries
    #
    # TODO: here will be the hook for the replacement of decrpyted values
    #       with a password object in the linotp_config

    for key, value in config.items():

        myTyp = type_dict.get(key)
        if not myTyp or myTyp != 'password':
            continue

        # ------------------------------------------------------------------ --

        # for password decryption we require an working hsm or we
        # will delay the decoding of the config entries

        if not hasattr(c, 'hsm') or not isinstance(c.hsm, dict):
            delay = True
            continue

        hsm = c.hsm.get('obj')
        if not hsm or not hsm.isReady():
            delay = True
            continue

        #
        # !!! dont try to utf-8 decode the passwords as they
        #     are already "magically" correct:
        # - when retrieved from DB, they are already in unicode format,
        #   which is sufficient for further processing :)
        #

        config['enc' + key] = decryptPassword(value)

    return (config, delay)


# ########## external interfaces ###############
def storeConfig(key, val, typ=None, desc=None):

    log_val = val
    if typ and typ == 'password':
        log_val = "X" * len(val)
    log.debug('Changing config entry %r: New value is %r', key, log_val)

    conf = getLinotpConfig()
    conf.addEntry(key, val, typ, desc)
    return True


def updateConfig(confi):
    '''
    update the server config entries incl. syncing it to disc
    '''
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

    return True


def getFromConfig(key, defVal=None):
    conf = getLinotpConfig()
    value = conf.get(key, defVal)
    return value


def refreshConfig():
    conf = getLinotpConfig()
    conf.refreshConfig(do_reload=True)
    return


def removeFromConfig(key, iCase=False):
    log.debug('Removing config entry %r' % key)
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

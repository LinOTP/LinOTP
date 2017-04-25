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


import logging

from linotp.lib.crypto import decryptPassword
from linotp.lib.crypto import encryptPassword
from linotp.lib.error import ConfigAdminError
from linotp.model import Config

from pylons import tmpl_context as c

from linotp.lib.text_utils import UTF8_MAX_BYTES
from linotp.lib.text_utils import simple_slice
from linotp.lib.text_utils import utf8_slice

from linotp.lib.config.util import expand_here

import linotp.model.meta

Session = linotp.model.meta.Session


#
# MAX_VALUE_LEN defines the max len before we split the config entries into
#  continuous config entries blocks.
#

MAX_VALUE_LEN = 2000 - UTF8_MAX_BYTES


log = logging.getLogger(__name__)

###############################################################################
#     private interface
###############################################################################


def _storeConfigDB(key, val, typ=None, desc=None):
    """
    insert or update the entry with  key, value, type and
    description in the config DB

    """
    value = val

    log_value = 'XXXXXX' if typ == 'password' else value
    log.debug('Changing config entry %r in database: New value is %r',
              key, log_value)

    if (not key.startswith("linotp.")):
        key = "linotp." + key

    # ---------------------------------------------------------------------- --

    # passwords are encrypted from here

    if typ and typ == 'password':

        value = encryptPassword(val.encode('utf-8'))

        # we just check if the encryption went good

        en = decryptPassword(value).decode('utf-8')
        if (en != val):
            raise Exception("Error during encoding password type!")

    # ---------------------------------------------------------------------- --

    # other types like datetime or int are simply stored

    if type(value) not in [str, unicode]:
        return _storeConfigEntryDB(key, value, typ=typ, desc=desc)

    # ---------------------------------------------------------------------- --

    # for strings or unicode, we support continued entries
    # check if we have to split the value

    # the continuous type is a split over multiple entries:
    # * every entry will have an enumerated key but the first one which has the
    #   original one.
    # * For all the type is 'C', but the last one which contains the original
    #   type.
    # * For description all entries contains the enumeration, but the last the
    #   original description

    #
    # we check the split algorithm depending on the value data -
    # in case of only ascii, we can use the much faster simple algorithm
    # in case of unicode characters we have to take the much slower one
    #

    chunks = []
    if len(value) < len(value.encode('utf-8')):
        text_slice = utf8_slice
    else:
        text_slice = simple_slice

    # the number of chunks is oriented toward the max length defined
    # by utf8 in bytes + the clipping of 6 bytes each. But as this could
    # vary, we could not calculate the number of chunks and thus benefit
    # from the iterator

    for cont_value in text_slice(value, MAX_VALUE_LEN):
        chunks.append(cont_value)

    number_of_chunks = len(chunks)

    # special simple case: either empty value or single entry
    if number_of_chunks == 1:
        return _storeConfigEntryDB(key, value, typ=typ, desc=desc)

    for i, cont_value in enumerate(chunks):

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
        myVal = expand_here(myVal)
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

    # ---------------------------------------------------------------------- --

    # first read all config db information into dicts for later processing

    for conf in Session.query(Config).all():
        conf_dict[conf.Key] = conf.Value
        type_dict[conf.Key] = conf.Type
        desc_dict[conf.Key] = conf.Description

        # a continuous entry is indicated by the type 'C' and the description
        # search for the entry which starts with '0:' as it will provide the
        # number of continuous entries

        if conf.Type == 'C' and conf.Description[:len('0:')] == '0:':
            _start, num = conf.Description.split(':')
            cont_dict[conf.Key] = int(num)

    # ---------------------------------------------------------------------- --

    # cleanup the config from continuous entries

    for key, number in cont_dict.items():

        value = conf_dict[key]

        for i in range(number + 1):

            search_key = "%s__[%d:%d]" % (key, i, number)

            if search_key in conf_dict:
                value = value + conf_dict[search_key]
                del conf_dict[search_key]

        conf_dict[key] = value

        search_key = "%s__[%d:%d]" % (key, number, number)
        type_dict[key] = type_dict.get(search_key)
        desc_dict[key] = desc_dict.get(search_key)

    # ---------------------------------------------------------------------- --

    # finally put the entries into the to be returned config dictionary
    # caring for the linotp. prefix and the exanding of config values

    for key, value in conf_dict.items():

        if key.startswith("linotp.") is False:
            key = "linotp." + key

        nVal = expand_here(value)
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

# eof #

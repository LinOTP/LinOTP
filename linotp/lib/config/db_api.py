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
"""handle all configuration items with aspekts like persitance and
syncronysation and provides this to all requests
"""

import logging

from linotp.lib.config.util import expand_here
from linotp.lib.crypto.encrypted_data import EncryptedData
from linotp.lib.error import ConfigAdminError
from linotp.lib.text_utils import UTF8_MAX_BYTES, simple_slice, utf8_slice
from linotp.model import db
from linotp.model.config import Config

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
    insert or update the entry with key, value, type and
    description in the config DB

    """
    value = val

    if not key.startswith("linotp."):
        key = "linotp." + key

    if isinstance(key, str):
        key = "" + key

    log.debug("Changing config entry %r in database: New value is %r", key, val)

    # ---------------------------------------------------------------------- --

    # in case of an encrypted entry where the typ is 'encrypted_data', we store
    # the encrypted value which is retreived by the str value of the
    # EncrypteData object

    # other types like datetime or int are simply stored

    if not isinstance(value, str):
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
    text_slice = utf8_slice if len(value) < len(value.encode("utf-8")) else simple_slice
    chunks = list(text_slice(value, MAX_VALUE_LEN))

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

    search_key = f"{key}__[%:%]"
    continous_entries = Config.query.filter(Config.Key.like(search_key))

    for continous_entry in continous_entries:
        db.session.delete(continous_entry)


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
        cont_desc = f"{i}:{number_of_chunks - 1}"
        cont_key = f"{key}__[{i}:{number_of_chunks - 1}]"

        # first one will contain the correct key with type 'C' continuous
        if i == 0:
            cont_key = key

        # the last one will contain the correct type and description
        elif i == number_of_chunks - 1:
            cont_typ = typ
            cont_desc = desc

        res = _storeConfigEntryDB(cont_key, cont_value, typ=cont_typ, desc=cont_desc)

    return res


def _storeConfigEntryDB(key, value, typ=None, desc=None):
    """
    lowest level for storing database entries in the config table
    """

    confEntries = Config.query.filter_by(Key=str(key))
    theConf = None

    # update
    if confEntries.count() == 1:
        theConf = confEntries[0]
        theConf.Value = str(value)
        theConf.Type = typ
        theConf.Description = desc

    # insert
    elif confEntries.count() == 0:
        theConf = Config(
            Key=str(key),
            Value=str(value),
            Type=str(typ),
            Description=str(desc),
        )
    if theConf is not None:
        db.session.add(theConf)

    return 101


def _removeConfigDB(key):
    """
    remove entry from config table

    :param key: the name of the entry
    :return: number of deleted entries
    """
    log.debug("removing config entry %r from database table", key)

    key = str(key)
    if not key.startswith(("linotp.", "enclinotp.")):
        key = f"linotp.{key}"

    confEntries = Config.query.filter_by(Key=str(key)).all()

    if not confEntries:
        return 0

    theConf = confEntries[0]

    to_be_deleted = []
    to_be_deleted.append(theConf)

    # if entry is a contious type, delete all of this kind
    if theConf.Type == "C" and theConf.Description[: len("0:")] == "0:":
        _start, end = theConf.Description.split(":")
        search_key = f"{key}__[%:{end}]"
        cont_entries = Config.query.filter(Config.Key.like(search_key)).all()

        to_be_deleted.extend(cont_entries)

    try:
        for entry in to_be_deleted:
            # Session.add(theConf)
            db.session.delete(entry)

    except Exception as exx:
        msg = f"remove Config failed for {key!r}: {exx!r}"
        raise ConfigAdminError(msg, id=1133) from exx

    return len(to_be_deleted)


def _retrieveConfigDB(Key):
    # prepend "linotp." if required
    key = str(Key)
    if not key.startswith(("linotp.", "enclinotp.")):
        key = f"linotp.{key}"

    myVal = None

    entries = Config.query.filter_by(Key=key).all()

    if not entries:
        return None

    theConf = entries[0]

    # other types than continous: we are done
    if theConf.Type != "C":
        myVal = theConf.Value
        myVal = expand_here(myVal)
        return myVal

    # else we have the continue type: we iterate over all entries where the
    # number of entries is stored in the description as range end
    _start, end = theConf.Description.split(":")

    # start accumulating the value
    value = theConf.Value

    for i in range(int(end)):
        search_key = f"{key}__[{i}:{int(end)}]"
        cont_entries = Config.query.filter_by(Key=search_key).all()
        if cont_entries:
            value = value + cont_entries[0].Value

    return value


def _retrieveAllConfigDB():
    """
    Retrieve all configuration entries from the database

    All configuration values are retrieved at once, and then parsed into
    a hierarchical format.

    remark: for support for continous entries dedicated dicts for
            description and type are used for interim processing

    :return: config dict
    """

    conf_dict = {}
    type_dict = {}
    desc_dict = {}
    cont_dict = {}

    db_config: list[Config] = Config.query.all()

    # put all information in the dicts for later processing

    for conf in db_config:
        log.debug("[retrieveAllConfigDB] key %r:%r", conf.Key, conf.Value)

        conf_dict[conf.Key] = conf.Value
        type_dict[conf.Key] = conf.Type
        desc_dict[conf.Key] = conf.Description

        # a continuous entry is indicated by the type 'C' and the description
        # search for the entry which starts with '0:' as it will provide the
        # number of continuous entries

        if conf.Type == "C" and conf.Description.startswith("0:"):
            _start, num = conf.Description.split(":")
            cont_dict[conf.Key] = int(num)

    # ---------------------------------------------------------------------- --

    # cleanup the config from continuous entries

    for key, number in list(cont_dict.items()):
        value = conf_dict[key]

        for i in range(number + 1):
            search_key = f"{key}__[{i}:{number}]"

            if search_key in conf_dict:
                value = value + conf_dict[search_key]
                del conf_dict[search_key]

        conf_dict[key] = value

        search_key = f"{key}__[{number}:{number}]"
        # allow the reading of none existing entries
        type_dict[key] = type_dict.get(search_key)
        desc_dict[key] = desc_dict.get(search_key)

    # ---------------------------------------------------------------------- --

    # normal processing as before continous here

    config = {
        k if k.startswith("linotp.") else f"linotp.{k}": expand_here(v)
        for k, v in conf_dict.items()
    }
    # ---------------------------------------------------------------------- --

    # special treatment of encrypted_data:
    # instead of decrypting the data during the loading of the config, the
    # encrypted data is provided EncryptedData object, which allows to only
    # decrypt the data when needed.
    # This allows to drop the delayed loading handling

    for key, value in config.items():
        myTyp = type_dict.get(key)

        if myTyp and myTyp == "encrypted_data":
            config[key] = EncryptedData(value)

    return config, False


# eof #

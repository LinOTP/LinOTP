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
"""handle all configuration items with aspekts like persitance and
syncronysation and provides this to all requests
"""

import logging

from linotp.flap import tmpl_context as c
from linotp.lib.config.config_class import LinOtpConfig
from linotp.lib.config.type_definition import type_definitions
from linotp.lib.crypto.encrypted_data import EncryptedData

log = logging.getLogger(__name__)


###############################################################################
#     public interface
###############################################################################


def getLinotpConfig():
    """
    Get the complete configuration and store in context

    Calling this function results in a number of operations:
    * Retrieve the complete configuration from the database
    * Parse into a hierarchical format
    * Make available in application context (flap.config)

    The resulting class can be found under c.linotpConfig,
    but is more generally accessed using the symbol `config`:

    from linotp.flap import config
    foo = config['foo']

    :return: local config dict
    :rtype: dict
    """

    ret = {}
    try:
        if not hasattr(c, "linotpConfig"):
            c.linotpConfig = LinOtpConfig()

        ty = type(c.linotpConfig).__name__
        if ty != "LinOtpConfig":
            try:
                c.linotpConfig = LinOtpConfig()
            except Exception as exx:
                log.error(
                    "Could not add LinOTP configuration to Flask "
                    "application context. Exception was: %r",
                    exx,
                )
                raise exx
        ret = c.linotpConfig

        if ret.delay is True:
            if hasattr(c, "hsm") is True and isinstance(c.hsm, dict):
                hsm = c.hsm.get("obj")
                if hsm is not None and hsm.isReady() is True:
                    ret = LinOtpConfig()
                    c.linotpConfig = ret

    except Exception:
        # FIXME: this happens once every server start and seems quite unnecessary.
        # Please, please, please refactor this method in the future to get rid
        # of the FOUR instantiations of LinOtpConfig() in this method alone.
        log.debug("Bad Hack: Retrieving LinotpConfig without controller context")
        ret = LinOtpConfig()

        if ret.delay is True:
            if hasattr(c, "hsm") is True and isinstance(c.hsm, dict):
                hsm = c.hsm.get("obj")
                if hsm is not None and hsm.isReady() is True:
                    ret = LinOtpConfig()

    return ret


# ########## external interfaces ###############


def storeConfig(key, val, typ=None, desc=None):
    """
    storing the config entry into the db and in the global config

    - external interface for storing config entries, which implies
      the conversion of the encrypted data to an encrypted data object

    :param key: name of the entry
    :param val: the value
    :param typ: -optional- the type
    :param desc: -optional- the description

    """
    if not typ and key in type_definitions:
        typ, converter = type_definitions[key]
        val = converter(val)

    if typ and typ.lower() in ["password", "encrypted_data"]:
        typ = "encrypted_data"
        if not isinstance(val, EncryptedData):
            val = EncryptedData.from_unencrypted(val)

    if isinstance(val, EncryptedData):
        typ = "encrypted_data"

    log.debug("Changing config entry %r: New value is %r", key, val)
    conf = getLinotpConfig()

    conf.addEntry(key, val, typ, desc)

    return True


def updateConfig(confi):
    """
    update the server config entries incl. syncing it to disc
    """
    entries = set()
    update_entries = {}

    for entry in confi.keys():
        if entry.endswith(".type") or entry.endswith(".desc"):
            key = entry[: -len(".type")]
        else:
            key = entry

        if key in entries:
            continue

        if (
            key not in type_definitions
            and not confi.get(key + ".type")
            and not confi.get(key + ".desc")
        ):
            update_entries[key] = confi.get(key)
        else:
            entries.add(key)
            storeConfig(
                key,
                confi.get(key),
                confi.get(key + ".type"),
                confi.get(key + ".desc"),
            )

    if update_entries:
        conf = getLinotpConfig()
        conf.update(update_entries)

    return True


def getFromConfig(key, defVal=None, decrypt=False):
    """
    retrieve an entry from the linotp config

    :param key: the name of the value
    :param defValue: default value if the entry could not be found
    :param decrypt: boolean, if true and the entry is an encrypted data object,
                    return the decrypted value
    """

    conf = getLinotpConfig()

    value = conf.get(key, defVal)

    if isinstance(value, EncryptedData) and decrypt:
        return value.get_unencrypted()

    return value


def refreshConfig():
    conf = getLinotpConfig()
    conf.refreshConfig(do_reload=True)


def removeFromConfig(key, iCase=False):
    log.debug("Removing config entry %r", key)
    conf = getLinotpConfig()

    if iCase:
        # Case-insensitive delete
        fConf = [
            k
            for k in conf
            if k.lower() == key.lower() or k.lower() == "linotp." + key.lower()
        ]

        for k in fConf:
            if k in conf or "linotp." + k in conf:
                del conf[k]
    elif key in conf:
        # Case-sensitive delete
        del conf[key]

    return True


# eof #########################################################################

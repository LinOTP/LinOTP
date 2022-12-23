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

import logging
from os import path, walk

import flask

from linotp.lib.error import TokenTypeNotSupportedError
from linotp.lib.registry import ClassRegistry

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

tokenclass_registry = ClassRegistry()

# ------------------------------------------------------------------------------


def reload_classes():
    """

    iterates through the modules in this package
    and import every single one of them

    """

    # ---------------------------------------------------------------------- --

    # if there is a list of predefined tokens in a linotp.cfg file

    activated_modules = flask.current_app.config["TOKEN_MODULES"]
    if activated_modules:
        for activated_module in activated_modules.split():
            load_module(activated_module)
        return

    # ---------------------------------------------------------------------- --

    # if no activated tokens specified, we import the local tokens

    import_base = "linotp.tokens."

    abs_file = path.abspath(__file__)
    base_dir = path.dirname(abs_file)

    # remove the filesystem base

    for root, _subdirs, sfiles in walk(base_dir):

        # remove the filesystem base

        rel = root.replace(base_dir, "").replace(path.sep, ".").strip(".")

        if rel:
            rel = rel + "."

        for sfile in sfiles:

            if sfile.endswith(".py") and not sfile.startswith("__"):

                token_module = import_base + rel + sfile[:-3]

                load_module(token_module)

    return


def load_module(mod_rel):
    """
    load a token module from a relative token module name

    :param mod_rel:

    :raises: TokenTypeNotSupportedError or genric Exception
    """

    try:

        __import__(mod_rel, globals=globals(), level=0)
        return True

    except TokenTypeNotSupportedError:
        log.warning("Token type not supported on this setup: %s", mod_rel)

    except Exception as exx:
        log.warning("unable to load token module : %r (%r)", mod_rel, exx)

    return False

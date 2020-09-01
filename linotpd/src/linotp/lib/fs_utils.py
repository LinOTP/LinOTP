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

"""File system utility functions."""

import errno
import os
# from typing import Protocol     # Only from Python 3.8 on

import logging
logger = logging.getLogger(__name__)


# Unfortunately, we'll have to wait for Python 3.8 to use `Protocol`.
#
# class HasConfig(Protocol):
#     """A class that has a `config` attribute which is a `dict` (or
#     subclass of `dict`).
#     """

#     config: dict[str, str]      # for typechecking purposes


def ensure_dir(app,  # : HasConfig
               what: str, conf_name: str,
               *sub_dirs: str, mode: int = 0o770):
    """Make sure the directory whose name is given by
    `app.config[conf_name]/sub/dirs` exists. If it needs to be
    created, create all its parents if necessary, and use mode
    `mode`. `app.config[conf_name]` must exist in any case. Return
    `dirname`. Use `what` to describe what sort of directory you're
    creating; this will show up in the log if there is an error.
    """

    if (not conf_name.endswith('_DIR')) or (conf_name not in app.config):
        raise KeyError(f"Invalid LinOTP configuration setting '{conf_name}'")

    base_name = app.config[conf_name]
    if not os.path.exists(base_name):
        raise FileNotFoundError(
            errno.ENOENT,
            f"Directory '{base_name}' ({conf_name}) does not exist",
            base_name)
    if not os.path.isdir(base_name):
        raise NotADirectoryError(
            errno.ENOTDIR,
            f"File '{base_name}' ({conf_name}) is not a directory",
            base_name)

    if sub_dirs:
        dir_name = os.path.join(base_name, *sub_dirs)
        if not os.path.isdir(dir_name):
            try:
                os.makedirs(dir_name, mode=mode, exist_ok=True)
            except OSError as ex:
                raise OSError(ex.errno,
                              f"Error creating {what} directory '{dir_name}': "
                              f"{ex.strerror} ({ex.errno})", dir_name)
        return dir_name

    return base_name

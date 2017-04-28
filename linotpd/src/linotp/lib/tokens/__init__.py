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

from linotp.lib.registry import ClassRegistry
from linotp.lib.error import TokenTypeNotSupportedError
from linotp.config.environment import get_activated_token_modules
from os import path, listdir
import logging

log = logging.getLogger(__name__)

# ------------------------------------------------------------------------------

tokenclass_registry = ClassRegistry()

# ------------------------------------------------------------------------------


def reload_classes():

    """ iterates through the modules in this package
    and import every single one of them """

    activated_modules = get_activated_token_modules()

    # Find out the path this file resides in
    abs_file = path.abspath(__file__)
    abs_dir = path.dirname(abs_file)

    # list files
    files_in_ext_path = listdir(abs_dir)

    for fn in files_in_ext_path:

        # filter python files

        if fn.endswith('.py') and not fn == '__init__.py':

            # translate them into module syntax
            # and import

            mod_rel = fn[0:-3]

            if activated_modules is not None and \
               mod_rel not in activated_modules:
                continue

            try:
                __import__(mod_rel, globals=globals())
            except TokenTypeNotSupportedError:
                log.warning('Token type not supported on this setup: %s',
                            mod_rel)
            except Exception as exx:
                log.warning('unable to load resolver module : %r (%r)'
                            % (mod_rel, exx))

reload_classes()

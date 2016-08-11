#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP userid resolvers.
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

'''
The useridresolver is responsible for getting userids for loginnames and vice versa.

This base module contains the base class UserIdResolver.UserIdResolver and also the
community class PasswdIdResolver.IdResolver, that is inherited from the base class.
'''

from os import path, listdir
import logging

log = logging.getLogger(__name__)


# IMPORTANT! This file is imported by setup.py, therefore do not (directly or
# indirectly) import any module that might not yet be installed when installing
# LinOtpUserIdResolver.

__copyright__ = "Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH"
__license__ = "Gnu AGPLv3"
__contact__ = "www.linotp.org"
__email__ = "linotp@lsexperts.de"
__version__ = '2.9'


# ------------------------------------------------------------------------------


class ClassRegistry(dict):

    """
    A simple class registry, that provides a convenient decorator.

    Usage:

    >>> cls_reg = ClassRegistry()

    >>> cls_reg.class_entry(registry_key='foo_cls')
    >>> class Foo (object):
    >>>    pass
    """

    def class_entry(self, registry_key=None):

        """ decorator factory to insert classes into
        this registry """

        def _inner(cls_):

            # _registry_key assignment is a workaround
            # for the missing nonlocal statement in python2.x

            if registry_key is None:
                _registry_key = cls_.__name__
            else:
                _registry_key = registry_key

            self[_registry_key] = cls_
            return cls_

        return _inner

resolver_registry = ClassRegistry()


# ------------------------------------------------------------------------------


def reload_classes():

    """ iterates through the modules in this package
    and import every single one of them """

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
            try:
                __import__(mod_rel, globals=globals())
            except Exception as exx:
                log.warning('unable to load resolver module : %r (%r)'
                            % (mod_rel, exx))

reload_classes()

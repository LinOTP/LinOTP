#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#


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

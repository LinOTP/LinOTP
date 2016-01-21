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

from linotp.lib._compat import get_thread_ident
from linotp.lib.error import ProgrammingError

"""
A collection of classes that implement similar behavior as pythons threadlocals.
Objects of these classes can be used globally without compromising thread
safety. They are 'sandboxed' in the sense that they are unique for every thread.

Locals have some gotchas that have to do with python's thread recycling. If
you are using objects made from classes in here, remember to call release_local
at the end of every thread. Otherwise you will risk data leaks between threads.
"""

# inspired by werkzeugs local module, adapted to our needs

class LocalContainer(object):

    """
    LocalContainer works as a thread safety wrapper for objects allowing
    item assignment. On construction it demands a factory function that
    should produce an object that implements __getitem__, __setitem__
    and __contains__

    simple example:

    LocalContainer(source_func=list) or simply LocalContainer(list)

    produces an object that behaves like an empty list on start of
    every thread. Likewise using dict as source_func produces an object,
    that behaves like an empty dict, etc.

    When you are using custom factory functions keep in mind, that the
    function itself must be thread safe. References to global variables
    inside the source_func will compromise thread safety.

    custom function example:

    >>> def init_fruits ():
    >>>    return ['apple', 'banana', 'cherry']

    >>> basic_fruits = LocalContainer(source_func=init_fruits)
    >>> basic_fruits
    ['apple', 'banana', 'cherry']

    Like all classes in the local module it allows to use a custom
    thread identity function. This can come in handy when you are
    using something other than python threads (e.g. greenlets).
    Just provide a :param ident_func (default is get_ident from
    the thread module)

    Also you can configure an optional access_check method, that
    signifies if the local object may be accessed at the current
    time. This is used by context managers in lib.context to make
    sure local objects are only called inside the right context
    """

    def __init__(self,
                 source_func,
                 ident_func=get_thread_ident,
                 access_check=lambda: True):

        self.__storage__ = {}
        self.__ident_func__ = ident_func
        self.__source_func__ = source_func
        self.__access_check__ = access_check

    def __release_local__(self):
        thread_identity = self.__ident_func__()
        self.__storage__.pop(thread_identity, None)

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

    def __getitem__(self, key):
        return self._wrapped[key]

    def __setitem__(self, key, value):
        self._wrapped[key] = value

    def __repr__(self):
        return repr(self._wrapped)

    def __contains__(self, key):
        return key in self._wrapped

    @property
    def _wrapped(self):
        may_access = self.__access_check__()
        if not may_access:
            raise ProgrammingError('Access not possible in this context. Look '
                                   'up the docs in linotp.lib.context for the '
                                   'right context manager')
        thread_identity = self.__ident_func__()
        return self.__storage__.setdefault(thread_identity, self._source)

    @property
    def _source(self):
        return self.__source_func__()


def release_local(local):

    """
    removes the thread local data form the current local object. should be
    called at the end of every thread
    """

    local.__release_local__()

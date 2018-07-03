# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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
"""
ResourceScheduler - handle iteration on resources list with blocking
                    similar to a list of circuit breakers.

                    the ResourceSchedule keeps track to the resouces, which
                    might have been blocked for a certain time. After the
                    blocking time has been expired, the access to the resource
                    will be scheduled again
"""

from datetime import datetime
from datetime import timedelta

import logging

# ------------------------------------------------------------------------- --

# global registry, where all current resolver uri and

GLOBAL_REGISTRY = {}

log = logging.getLogger(__name__)


def string_to_list(string_list, sep=','):
    """
    tiny helper to create a list from a string with seperators

    :param string_list: single string which should be split into a list
    :param sep: the item seperator
    """
    entries = []

    for entry in string_list.split(sep):

        if entry and entry.strip():
            entries.append(entry.strip())

    return entries

# ------------------------------------------------------------------------- --


class ResourceRegistry(object):
    """
    the resource registry is a global registry, which keeps an entry
    per resource. The resource is identified by a unique identifier, eg. URI.
    the value could be specific eg. the block expiration time only
    """

    @classmethod
    def store_or_retrieve(cls, resource, value):
        """
        atomic operation - get or set a value from/into the registry. The set
        operation is only made, when there is no value for the resource in
        the registry
        """
        raise NotImplementedError()

    @classmethod
    def store(cls, resource, value):
        """
        abstraction to store the resource along with a new value

        :param resource: a resource identifier
        :param value: the value which should be associated with the resource
        """
        raise NotImplementedError()

# ------------------------------------------------------------------------- --

class DictResourceRegistry(ResourceRegistry):
    """
    the dict resource registry is a module global dict, which keeps an entry
    per resource. The advantage of the dict is that the operations on the dict
    are threadsafe. Other resource registries might use different strategies

    see:
    http://effbot.org/
            pyfaq/what-kinds-of-global-value-mutation-are-thread-safe.htm

    remark:
    we use the treadsafe dictionary method 'setdefault' which is an atomic
    version of:

    >>>    if key not in dict:
    >>>        dict[key] = value
    >>>    return dic[key]

    """

    registry = GLOBAL_REGISTRY

    @classmethod
    def store_or_retrieve(cls, resource, value):
        """
        if a resource already exists in the registry, it is returned.
        If it does not exist, it is preserved and then retrieved to be
        returned.

        :param resource: the resource
        :param value: the fallback value, if the resource does not exist
        :return: the value associated with the resource
        """

        return cls.registry.setdefault(resource, value)

    @classmethod
    def store(cls, resource, value):
        """
        store the resource along with a new value

        :param resource: the resource
        :param value: the value which should be associated with the resource
        """

        cls.registry[resource] = value

# ------------------------------------------------------------------------- --


class ResourceScheduler(object):
    """
    Class to manage the list of resources (uris) in a global register, while
    keeping track of the connectability

    example usage:

    >>>    rs = ResourceScheduler(
    >>>                retry=3, uri_list=['h://1', 'h://2', 'h://3', 'h://4'))
    >>>
    >>>    for uri in rs.next():
    >>>        try:
    >>>            return conn(uri)
    >>>        except TimeoutException:
    >>>            rs.block(uri, delay=2)
    >>>
    >>>    print "all resouces unavailable!"

    """

    def __init__(self, uri_list=None, tries=1,
                 resource_registry_class=DictResourceRegistry):
        """
        :param: uri_list - the list of unique resouces
        :param retry: number of retries
        """

        self.uri_list = uri_list or []

        self.tries = tries
        self._retry_complete = True

        # plugable resource registry
        self.resource_registry = resource_registry_class

    # --------------------------------------------------------------------- --

    # public interfaces

    def next(self):
        """
        iterate trough all the resouces and return only those, which are
        currently not blocked

        :yield: return the next, not blocked resource of the resource list
        """

        for uri in self.uri_list:

            log.debug('iterate through resource %r', uri)

            # -------------------------------------------------------------- --

            # check if the resouce is not blocked anymore

            blocked_until = self.resource_registry.store_or_retrieve(uri, None)
            if not self._is_blocked(blocked_until):

                # ---------------------------------------------------------- --

                # if the resource is not blocked anymore we unblock its

                self.resource_registry.store(uri, None)
                log.debug('resource %r unlocked', uri)

                # ---------------------------------------------------------- --

                # return the resouce n-times until the retry count is done

                for r_uri in self._retry_resource(uri):
                    yield r_uri

        return

    def block(self, resource, delay=30, immediately=False):
        """
        mark the given resource as blocked for a delay of seconds

        - the blocking is only possible if all retries are made. this
          is controlled by the _retry_complete, that is controlled in the
          retry iterator

        :param resource: the resource that should be blocked
        :param delay: optional - specify the delay, till a request
                      should be retriggerd
        :param immediately: should be locked immediately
        """

        if self._retry_complete or immediately:

            block_until = datetime.utcnow() + timedelta(seconds=delay)
            self.resource_registry.store(resource, block_until)

            log.info('blocking resource %r till %r', resource, block_until)

    # --------------------------------------------------------------------- --

    # interal interfaces

    def _retry_resource(self, uri):
        """
        retry iterator - return the uri n-times and track that with the last
                         return, its possible to mark the resource as blocked

        :param uri: the uri which should be returned n-times
        :yield: iterator - the next uri
        """

        self._retry_complete = False

        for i in range(0, self.tries):

            # the last of the list  is the last try, after which a blocking is
            # possible

            log.debug('try %d/%d for resource  %r', i, self.tries, uri)

            if i + 1 == self.tries:
                self._retry_complete = True

            yield uri

        self._retry_complete = True

    # --------------------------------------------------------------------- --

    @classmethod
    def _is_blocked(cls, blocked_until):
        """
        interal helper, which check if the given blocking time
        is expired

        :param blocked_until: blocking date or None
        :return: boolean - True, if it is still blocked
        """

        if blocked_until is not None and blocked_until > datetime.utcnow():

            log.debug('still blocked till %r', blocked_until)
            return True

        return False

    # --------------------------------------------------------------------- --

# eof #

# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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

import logging
from datetime import datetime, timedelta
from typing import Any, Dict

# ------------------------------------------------------------------------- --

# global registry, where all current resolver uri and

GLOBAL_REGISTRY: Dict[str, Any] = {}
MAX_BLOCK_COUNTER = 8  # delay = delay + delay * 2**block_counter

log = logging.getLogger(__name__)


class AllResourcesUnavailable(Exception):
    """
    to be thrown when all services are unavailable.
    """

    pass


def string_to_list(string_list, sep=","):
    """
    tiny helper to create a list from a string with separators

    :param string_list: single string which should be split into a list
    :param sep: the item separator
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
    we use the tread safe dictionary method 'setdefault' which is an atomic
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
    keeping track of the connect-ability

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


    *about:blocking*

    the blocking with a fixed delay could lead to the problem, that when
    a server is offline, the server will be retried after a short delay.
    Looking at the relevant functions next (S) and block (b) we have the
    following event sequence with a constant delay between the retries.

    ----------------------------------------------------------> timeline
          S     S    b    S    b    S    b    S    b    S   S

    * the sequence ( S -> S ) indicate that the server has been reachable
      in the first request.

    What required is, is that we remember if the previous state already has
    been blocked - the block_indicator

    ----------------------------------------------------------> timeline
          S     S    b    S    b    S    b    S    b    S   S
    in    0     0    0    1    0    1    0    1    0    1   0
    out   0     0    1    0    1    0    1    0    1    0   0

    as we can see, that if the next():S gets the input 1, it knows, that
    the former request was blocked.

    But this helps nothing as the next():S always resets the block status
    to give a chance for a new request. The idea is now to just remember
    the former state and this could as well be used to aggregate the number
    of b->S sequences. Therefore we use a second state, the block_counter.
    Thus we have the tuple
             (block_indicator, block_counter)

    with the following algorithm

    * the func block():b
      always only sets the block_indicator (x,n) -> (1,n)

    * the func next():S  takes the block_indicator
      - if set, and adds it to the block_counter       (1,n) -> (0, n+1)
      - if not set, the block_counter will be reseted  (0,n) -> (0,0)

    the upper sequence would have the following counters:

    ----------------------------------------------------------> timeline
          s     S    b    S    b    S    b    S    b    S   S
    in    0,0  0,0  0,0  1,0  0,1  1,1  0,2  1,2  0,3  1,4  0,5
    out   0,0  0,0  1,0  0,1  1,1  0,2  1,2  0,3  1,4  0,5  0,0

    Now we can dynamically adjust the delay by the doubling the time
    based on the counter: delay + delay * 2**n  assuming a delay of
    30 seconds, this will result in a sequence of doubling delays

       0 -> 30                   =   0,5 Min
       1 -> 30 + 30 * 2^1 =   90 =   1,5 Min
       2 -> 30 + 30 * 2^2 =  150 =   2,5 Min
       3 -> 30 + 30 * 2^3 =  270 =   4,5 Min
       4 -> 30 + 30 * 2^4 =  510 =   8,5 Min
       5 -> 30 + 30 * 2^5 =  990 =  16,5 Min
       6 -> 30 + 30 * 2^6 = 1950 =  32,5 Min
       7 -> 30 + 30 * 2^7 = 3970 =  64,5 Min
       8 -> 30 + 30 * 2^8 = 7710 = 128,5 Min

    the max delay time should be limited to 8 which is ~2 hours
    """

    def __init__(
        self,
        uri_list=None,
        tries=1,
        resource_registry_class=DictResourceRegistry,
    ):
        """
        :param: uri_list - the list of unique resources
        :param retry: number of retries
        """

        self.uri_list = uri_list or []

        self.tries = tries
        self._retry_complete = True

        # plugable resource registry
        self.resource_registry = resource_registry_class

    # --------------------------------------------------------------------- --

    # public interfaces

    def __next__(self):
        """
        iterate trough all the resources and return only those, which are
        currently not blocked

        :yield: return the next, not blocked resource of the resource list
        """

        for uri in self.uri_list:

            log.debug("iterate through resource %r", uri)

            # -------------------------------------------------------------- --

            # check if the resouce is not blocked anymore

            (
                blocked_until,
                block_indicator,
                block_counter,
            ) = self.resource_registry.store_or_retrieve(uri, (None, 0, 0))

            if not self._is_blocked(blocked_until):

                # ---------------------------------------------------------- --

                # we calculate the new blocking counter from the blocking
                # indicator
                if block_indicator == 0:
                    new_block_conuter = 0

                else:
                    new_block_conuter = min(
                        MAX_BLOCK_COUNTER, block_indicator + block_counter
                    )

                # if the resource is not blocked anymore we unblock it with
                # setting it to None, while remembering the blocking counter

                self.resource_registry.store(uri, (None, 0, new_block_conuter))
                log.debug("resource %r unlocked", uri)

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
                      should be re-triggered
        :param immediately: should be locked immediately
        """

        if self._retry_complete or immediately:

            # get the former values of the resource
            (
                _blocked_until,
                block_indicator,
                block_counter,
            ) = self.resource_registry.store_or_retrieve(
                resource, (None, 0, 0)
            )

            adjusted_delay = delay + delay * 2 ** block_counter
            block_until = datetime.utcnow() + timedelta(seconds=adjusted_delay)

            log.info("blocking for %r seconds", adjusted_delay)

            self.resource_registry.store(
                resource, (block_until, block_indicator + 1, block_counter)
            )

            log.info("blocking resource %r till %r", resource, block_until)

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

            log.debug("try %d/%d for resource  %r", i, self.tries, uri)

            if i + 1 == self.tries:
                self._retry_complete = True

            yield uri

        self._retry_complete = True

    # --------------------------------------------------------------------- --

    @classmethod
    def _is_blocked(cls, blocked_until):
        """
        internal helper, which check if the given blocking time
        is expired

        :param blocked_until: blocking date or None
        :return: boolean - True, if it is still blocked
        """

        if blocked_until is not None and blocked_until > datetime.utcnow():

            log.debug("still blocked till %r", blocked_until)
            return True

        return False

    # --------------------------------------------------------------------- --


# eof #

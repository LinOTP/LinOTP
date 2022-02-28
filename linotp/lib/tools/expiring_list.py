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

import time

# import redis
# from beaker.cache import CacheManager
# from beaker.util import parse_cache_config_options


class ExpiringList:

    """
    An interface class for a general storage of items in which
    each item has it's own expiry time
    """

    DEFAULT_EXPIRY_IN = 15 * 60  # seconds

    def __init__():
        pass

    def item_in_list(self, item):
        """
        :returns: True if item is in the list and not expired
        """
        pass

    def add_item(self, item, expiry):
        """
        Function to add an Item to the list

        :param item: the item to be kept
        :param ex: expiry in seconds
        """
        pass


# class RedisExpiringList(ExpiringList):
#     def __init__(self):
#         self.redislist = redis.StrictRedis(
#             host="localhost", port=6379, db=0, decode_responses=True
#         )

#     def item_in_list(self, item):
#         found_item = self.redislist.get(item)
#         return found_item is not None

#     def add_item(self, item, expiry=None):
#         if expiry is None:
#             expiry = timedelta(seconds=self.DEFAULT_EXPIRY_IN)
#         self.redislist.set(item, "", ex=expiry)


# class BeakerExpiringList(ExpiringList):
#     def __init__(self):
#         cache_opts["cache_type"] = "memory"
#         self.beakerlist = CacheManager(
#             parse_cache_config_options(cache_opts)
#         ).get_cache(type="memory", expiretime=expiration)

#     def item_in_list(self, item):
#         self.beakerlist.get(item)

#     def add_item(self, item, ex):
#         key = json.dumps(item)
#         self.beakerlist.get_value(key, value=True, expiretime=ex)


class CustomExpiringList(ExpiringList):
    """
    A simple item container with expiry time
    janitor runs after every new item is added
    """

    def __init__(self):
        self._itemsdic = {}
        self._last_janitor = self._now()

    def item_in_list(self, item):
        return (item in self._itemsdic) and (not self._is_expired(item))

    def add_item(self, item, expiry):
        self.__janitor__()
        self._itemsdic[item] = expiry + self._now()

    def _now(self):
        return time.time()

    def _is_expired(self, item):
        """assumes that item is in the list"""
        return self._itemsdic[item] < self._now()

    def __janitor__(self):
        now = self._now()
        self._itemsdic = {
            item: ex for (item, ex) in self._itemsdic.items() if ex > now
        }

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

import time


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


class CustomExpiringList(ExpiringList):
    """
    A simple item container with expiry time.
    A janitor runs after every new item is added to clean
    the expired items up.
    """

    def __init__(self):
        self._itemsdic = {}

    def item_in_list(self, item):
        """
        :returns: True if item is in the list and not expired
        """
        return (item in self._itemsdic) and (not self._is_expired(item))

    def add_item(self, item, expiry=None):
        """
        Function to add an Item to the list

        :param item: the item to be kept
        :param ex: expiry in seconds
        """
        if expiry is None:
            expiry = self.DEFAULT_EXPIRY_IN
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

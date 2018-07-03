# -*- coding: utf-8 -*-
#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010 - 2018 KeyIdentity GmbH
#
#   This file is part of LinOTP server.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU Affero General Public
#   License, version 3, as published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the
#              GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#   E-mail: linotp@keyidentity.com
#   Contact: www.linotp.org
#   Support: www.keyidentity.com

"""
unit test for the ResourceScheduler handling, which supports circuit breaking
"""

import unittest

from freezegun import freeze_time

from linotp.lib.resources import ResourceScheduler, string_to_list
from linotp.lib.resources import DictResourceRegistry


class TestResourceScheduler(unittest.TestCase):
    """
    test the iteration of the uri list of an resolver
    """

    def test_blocking_all_uris(self):
        """
        test that the uris will be blocked and unblocked after delay
        """

        # -------------------------------------------------------------- --

        # setup a local registry for the test

        DictResourceRegistry.registry = {}

        # ------------------------------------------------------------------ --

        # setup the Resource Scheduler

        res_sched = ResourceScheduler(
                            tries=1,
                            resource_registry_class=DictResourceRegistry)

        res_sched.uri_list = string_to_list("uri://1, uri://2, uri://3, ")

        # ------------------------------------------------------------------ --

        # check that all uris are blocked

        with freeze_time("2012-01-14 12:00:00"):

            # -------------------------------------------------------------- --

            # block all uris

            for uri in res_sched.next():
                res_sched.block(uri, delay=30)

            # -------------------------------------------------------------- --

            # verify that all uris are blocked and none is iterated

            uris = []
            for uri in res_sched.next():
                uris.append(uri)

            self.assertTrue(len(uris) == 0)

        # one minute later
        with freeze_time("2012-01-14 12:01:00"):

            # -------------------------------------------------------------- --

            # verify that all uris are un blocked after the delay

            uris = []
            for uri in res_sched.next():
                uris.append(uri)

            self.assertTrue('uri://1' in uris)
            self.assertTrue('uri://2' in uris)
            self.assertTrue('uri://3' in uris)

        return

    def test_uris_retry(self):
        """
        test all uris will be n-times tried
        """

        # -------------------------------------------------------------- --

        # setup a local registry for the test

        DictResourceRegistry.registry = {}

        # -------------------------------------------------------------- --

        # setup the Resource Scheduler

        res_sched = ResourceScheduler(
                            tries=3,
                            resource_registry_class=DictResourceRegistry)

        res_sched.uri_list = string_to_list("bluri://1, bluri://2, bluri://3, ")

        # -------------------------------------------------------------- --

        # check that the retry will be run through all uris n-times

        uris = []
        for uri in res_sched.next():
            uris.append(uri)

        self.assertTrue(len(uris) == 9)

        # -------------------------------------------------------------- --

        # check that every uri is registered in the global registry

        for _key, value in res_sched.resource_registry.registry.items():
            self.assertTrue(value is None)

        return

    def test_blocking_one_uri(self):
        """
        test that if one entry is blocked it will not be in the iteration list
        """

        # -------------------------------------------------------------- --

        # setup a local registry for the test

        DictResourceRegistry.registry = {}

        # -------------------------------------------------------------- --

        # setup the Resource Scheduler

        res_sched = ResourceScheduler(
                            tries=3,
                            resource_registry_class=DictResourceRegistry)

        res_sched.uri_list = string_to_list("bluri://1, bluri://2, bluri://3, ")

        the_blocked_one = res_sched.uri_list[1]

        with freeze_time("2012-01-14 12:00:00"):

            # -------------------------------------------------------------- --

            # block the second entry

            res_sched.block(the_blocked_one, 30, immediately=True)

            # -------------------------------------------------------------- --

            # verify that the second entry will not be iterated

            uris = []
            for uri in res_sched.next():
                uris.append(uri)

            self.assertTrue(the_blocked_one not in uris)

            # -------------------------------------------------------------- --

            # verify that the retry is done 3 times for the other two

            self.assertTrue(len(uris) == 6)

            # -------------------------------------------------------------- --

            # verify that the blocked one is marked as blocked in the registry

            for key, value in res_sched.resource_registry.registry.items():
                if key == the_blocked_one:
                    self.assertTrue(value is not None)
                else:
                    self.assertTrue(value is None)

        # one minute later

        with freeze_time("2012-01-14 12:01:00"):

            uris = []
            for uri in res_sched.next():
                uris.append(uri)

            # -------------------------------------------------------------- --

            # verify that the former blocked one is now not more blocked

            self.assertTrue(the_blocked_one in uris)

            # -------------------------------------------------------------- --

            # verify that the former blocked one is as well unblocked in the
            # registry

            for _key, value in res_sched.resource_registry.registry.items():
                self.assertTrue(value is None)

        return

# eof #

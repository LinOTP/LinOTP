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


import datetime
import unittest

from freezegun import freeze_time

from linotp.lib.tools.expiring_list import CustomExpiringList


class TestExpiringList(unittest.TestCase):
    def test_item_hold(self):
        ex_list = CustomExpiringList()

        someitems = [
            "somRandomtext",
            "SomeotherRandomtext",
            "SomemoreText",
            "and even more text",
            12,
            25,
        ]
        expiry_times = [12, 10, 10, 140, 150, 600]

        for item, ex in zip(someitems, expiry_times):
            ex_list.add_item(item, ex)

        for item in someitems:
            assert ex_list.item_in_list(item)

        # test that items will not be reported as being in the list if their
        # expiry passes
        with freeze_time(datetime.timedelta(seconds=12)):
            items_in = [ex_list.item_in_list(item) for item in someitems]
        assert sum(items_in) == 3

        # just before the expiry of last item
        with freeze_time(datetime.timedelta(seconds=500)):
            items_in = [ex_list.item_in_list(item) for item in someitems]
        assert sum(items_in) == 1

        # check janitor functionality
        with freeze_time(datetime.timedelta(seconds=620)):
            ex_list.add_item("a new item", 20)
            # all other items should be janitored by now
            assert len(ex_list._itemsdic) == 1
            assert ex_list.item_in_list("a new item")

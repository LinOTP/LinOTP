# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
#
#    This file is part of LinOTP smsprovider.
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

import unittest
from unittest import TestCase

from linotp.provider.smsprovider.RestSMSProvider import RestSMSProvider


class TestPhoneTemplate(TestCase):
    '''
    test the replacement of phone numbers in the template
    '''

    def test_simple_phone(self):
        """
        run test vector for the template phone replacement
        """

        phone = '1234567890'

        test_vector = [

            # simple text
            ("<phone>", phone),
            # empty text
            ("", phone),
            # none
            (None, phone),
            # other simple type
            (1, phone),
            # text replace
            ("This is my <phone> number", "This is my %s number" % phone),

            # list replace
            (['<phone>'], [phone]),
            # list replace with multiple items
            ([1, 'phone', '<phone>', {'<phone>': '<phone>'}],
                [1, 'phone', phone, {'<phone>': '<phone>'}]),
            # list replace with multiple items
            (['<phone>', 'This is my <phone> number', ],
                [phone, 'This is my %s number' % phone, ]),

            # other data types: dict
            ({'<phone>': '<phone>'}, phone),
            # other data types: set
            (set('<phone>'), phone),
            # other data types: tuple
            (('<phone>',), phone)

        ]

        for item in test_vector:
            template, expected = item

            replaced = RestSMSProvider._apply_phone_template(
                phone, template)

            assert expected == replaced

        return


# eof

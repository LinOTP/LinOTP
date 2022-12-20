# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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

import pytest

from linotp.provider.smsprovider.RestSMSProvider import (
    RestSMSProvider,
    json_replace,
)


class TestJSONReplace:
    """
    Test the nested replacement mechanism for JSON data structures.
    """

    @pytest.mark.parametrize(
        "base,path,expected",
        [
            ({"foo": "bar"}, "foo", {"foo": "MOD"}),
            ({"foo": {"bar": "baz"}}, "foo.bar", {"foo": {"bar": "MOD"}}),
            ({"foo": ["bar", "baz"]}, "foo.1", {"foo": ["bar", "MOD"]}),
            ({"foo": ["bar", "baz"]}, "foo[1]", {"foo": ["bar", "MOD"]}),
            ({"foo": ["bar"]}, "foo[1]", {"foo": ["bar", "MOD"]}),
            ({"foo": ["bar"]}, "foo[2]", {"foo": ["bar", "MOD"]}),
            (
                {"foo": [{"bar": "baz"}]},
                "foo[0].bar",
                {"foo": [{"bar": "MOD"}]},
            ),
            (
                {"foo": [["bar", "baz"], ["quux", "glorp"]]},
                "foo[1][0]",
                {"foo": [["bar", "baz"], ["MOD", "glorp"]]},
            ),
            ({"foo": "bar"}, "foo.bar.baz", TypeError),
        ],
    )
    def test_json_replace(self, base, path, expected):
        # Exception classes (like all classes) are instances of `type`.
        # `dict` objects (like all objects) are instances of `object`.
        if isinstance(expected, type):  # This is an (exception) class
            with pytest.raises(expected):
                json_replace(base, path, "MOD")
        else:  # This is an expected object
            replaced = json_replace(base, path, "MOD")
            assert expected == replaced


PHONE = "1234567890"


class TestPhoneTemplate:
    """
    test the replacement of phone numbers in the template
    """

    @pytest.mark.parametrize(
        "template,expected",
        [
            ("<phone>", PHONE),  # Simple text
            ("", PHONE),  # Empty text
            (None, PHONE),  # None
            (1, PHONE),  # Other simple type
            # Text replace
            ("This is my <phone> number", f"This is my {PHONE} number"),
            # List replace
            (["<phone>"], [PHONE]),
            # List replace with multiple items
            (
                [1, "phone", "<phone>", {"<phone>": "<phone>"}],
                [1, "phone", PHONE, {"<phone>": "<phone>"}],
            ),
            # Other data types: dict
            ({"<phone>": "<phone>"}, PHONE),
            # Other data types: set
            (set("<phone>"), PHONE),
            # Other data types: tuple
            (("<phone>",), PHONE),
        ],
    )
    def test_simple_phone(self, template, expected):
        """
        run tests for the template phone replacement
        """
        replaced = RestSMSProvider._apply_phone_template(PHONE, template)
        assert expected == replaced


# eof

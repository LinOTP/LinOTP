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
"""
Tests the regular expression match for token list search

- the user_expression_match is called from the ui token search, which supports
  the search for token which belong to a user matching an wildcard expression

"""

import unittest

from linotp.lib.tokeniterator import _user_expression_match


class TestUserSearchExpression(unittest.TestCase):
    """
    check the search expression match for a token owner
    """

    def test_not_matching_expressions(self):
        """test user search expression not matching"""

        token_owner = "maxwell@hotad.example.net"
        token_user_dict = {"match": token_owner}

        for user_search in [
            "maxwell",
            "maxwell@hotad.*.ned",
            "maxwell@hod*net",
            "maxwell@hod*",
            "*o@hotad.example.net",
            "*oxwell@hot*",
        ]:

            serials = _user_expression_match(
                user_search, list(token_user_dict.items())
            )

            assert "match" not in serials

        return

    def test_matching_expressions(self):
        """test user search expression matching"""

        token_owner = "maxwell@hotad.example.net"
        token_user_dict = {"match": token_owner}

        for user_search in [
            "maxwell*",
            "maxwell@hotad.*.net",
            "maxwell@hot*net",
            "maxwell@hot*",
            "*@hotad.example.net",
            "*xwell@hot*",
        ]:

            serials = _user_expression_match(
                user_search, list(token_user_dict.items())
            )

            assert "match" in serials, user_search

        return

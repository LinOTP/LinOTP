# -*- coding: utf-8 -*-

#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010-2019 KeyIdentity GmbH
#
#   This file is part of LinOTP userid resolvers.
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
#   E-mail: info@linotp.de
#   Contact: www.linotp.org
#   Support: www.linotp.de

"""
LDAP Resolver unit test
"""

import unittest

import pytest
from mock import patch

from linotp.useridresolver.LDAPIdResolver import IdResolver as LDAPResolver

from . import Bindresult


@pytest.mark.usefixtures("app")
class TestLDAPResolverAttributes(unittest.TestCase):
    """
    test setup for ldap library calls, which require parameters encoded
    as utf-8 while unicode is not allowed and will raise an exception
    """

    @patch("linotp.useridresolver.LDAPIdResolver.IdResolver.unbind")
    @patch("linotp.useridresolver.LDAPIdResolver.IdResolver.bind")
    def test_getUserId(self, mock_bind, mock_unbind):
        """
        test for absence of non-utf-8 encoded strings

        the ldap library used by the python ldap library requires all
        data encoded in utf-8, which has not been the case for the uidType
        """

        uid_type = "üid"

        # ------------------------------------------------------------------ --

        # setup the test environment

        bindresult = Bindresult(uid_type=uid_type)
        mock_bind.return_value = bindresult
        mock_unbind.return_value = None

        resolver = LDAPResolver()
        resolver.filter = "(&(uid=%s)(objectClass=inetOrgPerson))"
        resolver.uidType = uid_type

        # ------------------------------------------------------------------ --

        # finally trigger the call to run the test

        userid = resolver.getUserId("mözart")

        # check if attribute is a python unicode str
        if not isinstance(userid, str):
            raise Exception("non Unicode character recieved")

        # if unicode could be converted to utf-8 and back
        userid.encode("utf-8").decode("utf-8")

        # ------------------------------------------------------------------ --

        # extend the test to verify as well the getUserLDAPInfo and getUserInfo

        userLdapInfo = resolver.getUserLDAPInfo("Üßalad")

        for key, val_list in list(userLdapInfo.items()):

            # check if attribute is a python unicode str
            if not isinstance(key, str) and not isinstance(key, str):
                raise Exception("Non Unicode character recieved")

            # val could be str with ascii or non ascii (str.encode(utf-8).
            # If the str could converted to utf-8 and back it is ensured
            # that we have the correct encoding

            key.encode("utf-8").decode("utf-8")

            val = val_list[0]

            # check if attribute is a python unicode str
            if not isinstance(val, str) and not isinstance(key, str):
                raise Exception("Non Unicode character recieved")

            # val could be str with ascii or non ascii (str.encode(utf-8).
            # If the str could converted to utf-8 and back it is ensured
            # that we have the correct encoding

            val.encode("utf-8").decode("utf-8")

        # ------------------------------------------------------------------ --

        userInfo = resolver.getUserInfo("Üßalad")

        for key, val in list(userInfo.items()):

            if not isinstance(key, str):

                # check if attribute is a python unicode str
                if not isinstance(key, str):
                    raise Exception("Non Unicode character recieved")

            # key could be str with ascii or non ascii (str.encode(utf-8).
            # If the str could converted to utf-8 and back it is ensured
            # that we have the correct encoding

            key.encode("utf-8").decode("utf-8")

            # check if attribute is a python unicode str
            if not isinstance(val, str):
                raise Exception("Non Unicode character recieved")

            # val could be str with ascii or non ascii (str.encode(utf-8).
            # If the str could converted to utf-8 and back it is ensured
            # that we have the correct encoding

            val.encode("utf-8").decode("utf-8")

        return


# eof #

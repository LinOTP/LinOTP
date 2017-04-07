# -*- coding: utf-8 -*-

#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
#   E-mail: linotp@keyidentity.com
#   Contact: www.linotp.org
#   Support: www.keyidentity.com

"""
LDAP Resolver unit test
"""

import unittest
from mock import patch
from linotp.useridresolver.LDAPIdResolver import IdResolver as LDAPResolver


class TestLDAPResolverAttributes(unittest.TestCase):
    """
    test setup for ldap library calls, which require parameters encoded
    as utf-8 while unicode is not allowed and will raise an exception
    """

    @patch('linotp.useridresolver.LDAPIdResolver.IdResolver.unbind')
    @patch('linotp.useridresolver.LDAPIdResolver.IdResolver.bind')
    def test_getUserId(self, mock_bind, mock_unbind):
        """
        test for absence of non-utf-8 encoded strings

        the ldap library used by the python ldap library requires all
        data encoded in utf-8, which has not been the case for the uidType
        """

        class Bindresult(object):

            def search_ext(self, base, scope_subtree, filterstr=None,
                           sizelimit=None, attrlist=None, timeout=None):

                if attrlist:
                    for attr in attrlist:

                        # check if attribute is not a python unicode str
                        if isinstance(attr, unicode):
                            raise Exception('Unicode character recieved')

                        # invalid utf-8 will raise an exception too
                        attr.decode('utf-8')

                return True

            def result(self, l_id, all=1):
                return [
                    [],
                    [('cn=Wolfgang Amadeus Mozart,ou=people,dc=blackdog,'
                      'dc=corp,dc=lsexperts,dc=de',
                      {'entryUUID':
                       ['f4450c88-1df9-1033-90e8-713823084e1f']})]]

        bindresult = Bindresult()
        mock_bind.return_value = bindresult
        mock_unbind.return_value = None

        resolver = LDAPResolver()
        resolver.filter = u'(&(uid=%s)(objectClass=inetOrgPerson))'
        resolver.uidType = u'entryUUIDä'

        # finally trigger the call to run the test

        _userid = resolver.getUserId(u'mozart')

# eof #

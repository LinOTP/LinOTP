# -*- coding: utf-8 -*-

#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010 - 2019 KeyIdentity GmbH
#   Copyright (C) 2019 -      netgo software GmbH
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

        uid_type = u'üid'
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

                # check if filterstr is not a python unicode str
                if isinstance(filterstr, unicode):
                    raise Exception('Unicode character recieved')

                # val could be str with ascii or non ascii (str.encode(utf-8).
                # If the str could converted back from utf-8 it is ensured
                # that we have the correct encoding

                filterstr.decode('utf-8')

                return True

            def result(self, l_id, all=1):
                return [
                    [],
                    [('cn=Wolfgang Amadeus Mözart,ou=people,dc=blackdog,'
                      'dc=corp,dc=lsexperts,dc=de',
                      {uid_type:
                       ['f4450c88-1df9-1033-90e8-Wolfgang Amadeus Mözart']})]]

        # ------------------------------------------------------------------ --

        # setup the test environment

        bindresult = Bindresult()
        mock_bind.return_value = bindresult
        mock_unbind.return_value = None

        resolver = LDAPResolver()
        resolver.filter = u'(&(uid=%s)(objectClass=inetOrgPerson))'
        resolver.uidType = uid_type

        # ------------------------------------------------------------------ --

        # finally trigger the call to run the test

        userid = resolver.getUserId(u'mözart')

        # check if attribute is a python unicode str
        if not isinstance(userid, unicode):
            raise Exception('non Unicode character recieved')

        # if unicode could be converted to utf-8 and back
        userid.encode('utf-8').decode('utf-8')

        # ------------------------------------------------------------------ --

        # extend the test to verify as well the getUserLDAPInfo and getUserInfo

        userLdapInfo = resolver.getUserLDAPInfo(u'Üßalad')

        for key, val_list in userLdapInfo.items():

            # check if attribute is a python unicode str
            if not isinstance(key, unicode) and not isinstance(key, str):
                raise Exception('Non Unicode character recieved')

            # val could be str with ascii or non ascii (str.encode(utf-8).
            # If the str could converted to utf-8 and back it is ensured
            # that we have the correct encoding

            key.encode('utf-8').decode('utf-8')

            val = val_list[0]

            # check if attribute is a python unicode str
            if not isinstance(val, unicode) and not isinstance(key, str):
                raise Exception('Non Unicode character recieved')

            # val could be str with ascii or non ascii (str.encode(utf-8).
            # If the str could converted to utf-8 and back it is ensured
            # that we have the correct encoding

            val.encode('utf-8').decode('utf-8')

        # ------------------------------------------------------------------ --

        userInfo = resolver.getUserInfo(u'Üßalad')

        for key, val in userInfo.items():

            if not isinstance(key, str):

                # check if attribute is a python unicode str
                if not isinstance(key, unicode):
                    raise Exception('Non Unicode character recieved')

            # key could be str with ascii or non ascii (str.encode(utf-8).
            # If the str could converted to utf-8 and back it is ensured
            # that we have the correct encoding

            key.encode('utf-8').decode('utf-8')

            # check if attribute is a python unicode str
            if not isinstance(val, unicode):
                raise Exception('Non Unicode character recieved')

            # val could be str with ascii or non ascii (str.encode(utf-8).
            # If the str could converted to utf-8 and back it is ensured
            # that we have the correct encoding

            val.encode('utf-8').decode('utf-8')


        return
# eof #

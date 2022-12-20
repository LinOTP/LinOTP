# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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

import unittest
import json

# -------------------------------------------------------------------------- --

# TODO:
# in the jenkins unit test environment, there seems to be no lib ldap available
#

try:

    from linotp.useridresolver.LDAPIdResolver import IdResolver as ldap_resolver
    from linotp.useridresolver.SQLIdResolver import IdResolver as sql_resolver
    NO_LDAP_AVAILABLE = ''

except ImportError as exx:

    NO_LDAP_AVAILABLE = "%r" % exx


class TestResolverTestCase(unittest.TestCase):
    """
    unit test for some resolver static methods

    """

    def setUp(self):
        pass

    def test_detect_ldap_primary_change(self):
        """
        unit test for ldap primary key change

        the ldap resolver defines the primary key by the parameter UIDTYPE
        """

        if NO_LDAP_AVAILABLE:
            self.skipTest("skipping test: %s" % NO_LDAP_AVAILABLE)

        ldap_cls = ldap_resolver

        res = ldap_cls.primary_key_changed({}, {})
        self.assertFalse(res)

        res = ldap_cls.primary_key_changed({'UIDTYPE': 'objectGUID'},
                                           {'UIDTYPE': 'uid'})

        self.assertTrue(res)

        res = ldap_cls.primary_key_changed({'UIDTYPE': 'uid'},
                                           {'UIDTYPE': 'uid'})

        self.assertFalse(res)

        return

    def test_detect_sql_primary_change(self):
        """
        unit test for sql primary key change

        the sql resolver defines the primary key in the user mapping
        """

        if NO_LDAP_AVAILABLE:
            self.skipTest("skipping test: %s" % NO_LDAP_AVAILABLE)

        sql_cls = sql_resolver

        res = sql_cls.primary_key_changed({}, {})
        self.assertFalse(res)

        u_map_1 = json.dumps({'userid': 'id'})
        u_map_2 = json.dumps({'userid': 'uid'})

        res = sql_cls.primary_key_changed({'Map': u_map_1},
                                          {'Map': u_map_2})

        self.assertTrue(res)

        res = sql_cls.primary_key_changed({'Map': u_map_1},
                                          {'Map': u_map_1})

        self.assertFalse(res)

        return

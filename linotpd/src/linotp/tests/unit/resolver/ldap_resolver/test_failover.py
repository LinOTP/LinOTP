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
from ldap import LDAPError
from ldap import INVALID_CREDENTIALS

from linotp.lib.resources import ResourceScheduler, DictResourceRegistry

from linotp.useridresolver.LDAPIdResolver import IdResolver as LDAPResolver
from linotp.useridresolver.UserIdResolver import ResolverNotAvailable

from freezegun import freeze_time

TRIES = 2


class MockedLdapObject:
    """
    Mocked LDAP Object - will be called for a simple_bind
    """

    def __init__(self, uri):
        self.uri = uri

    def simple_bind_s(self, user, passw, *args, **kwargs):
        """  emulate a simple_bind  """

        if 'fail' in self.uri:
            raise LDAPError('failed to connect')

        if passw != 'geheim1':
            raise INVALID_CREDENTIALS('not geheim1!')

        return True

    def unbind_s(self):
        return


class FakeLdapResolver(LDAPResolver):
    """
    Mocked LDAP Resolver - used to count the calling events
    """

    called = []

    def __init__(self, *args, **kwargs):
        super(FakeLdapResolver, self).__init__(*args, **kwargs)

    @classmethod
    def m_connect(cls, uri, *args, **kwargs):
        """
        mocked connect - to return the mocked ladp object and count the calls
        """
        cls.called.append(uri)
        return MockedLdapObject(uri=uri)


class MockedBindPW:
    """ simple helper  to emulate the crypted data / password """

    def __init__(self, pw):
        self.pw = pw

    def get_unencrypted(self):
        """ mock the return of crypted data """
        return self.pw


class MockedResourceRegistry(DictResourceRegistry):
    """ mock the registry, so we can access the registry data localy """
    registry = {}


class MockedResourceScheduler(ResourceScheduler):
    """ mock the resource scheduler, so we can establish our local registry """

    def __init__(self, uri_list=None, tries=1):
        """ overload the constuctor so we can control the retries """
        super(MockedResourceScheduler, self).__init__(
                uri_list=uri_list, tries=TRIES,
                resource_registry_class=MockedResourceRegistry)


class TestLDAPResolverFailover(unittest.TestCase):
    """
    tests the ldap bind with failover using the Resource Scheduler
    """

    def setUp(self):
        """ initialize the test """

        unittest.TestCase.setUp(self)

        # ------------------------------------------------------------------ --

        # reset the class static registry and the class static called list

        FakeLdapResolver.called = []
        MockedResourceRegistry.registry = {}


    @patch('linotp.useridresolver.LDAPIdResolver.ResourceScheduler',
           MockedResourceScheduler)
    def test_bind_with_failover(self):
        """
        test the failover in the bind handling
        """

        # ------------------------------------------------------------------ --

        # setup the ldap fake resolver, which requires:
        # - an mocked connect
        # - an mocked bindpw, which in normal case would contain the
        #   crypted data
        # the mocked resolver loads the derived mocked ResouceSchduler with
        # the mocked Registry so that we can access the calling data

        IDRS = LDAPResolver
        IDRS.connect = FakeLdapResolver.m_connect

        myldap = IDRS()
        myldap.ldapuri = ("ldap://fail_bind1.psw.de, "
                        "ldap://fail_bind2.psw.de, "
                        "ldap://ok_bind3.psw.de, "
                        "ldap://ok_bind4.psw.de, "
                        )

        myldap.bindpw = MockedBindPW('geheim1')

        # ------------------------------------------------------------------ --

        # run the bind test

        myldap.bind()

        # ------------------------------------------------------------------ --

        # evaluate the result: how often called

        called = FakeLdapResolver.called

        self.assertTrue(len(called) == 2 * TRIES + 1)
        self.assertTrue('ldap://ok_bind4.psw.de' not in called)

        # ------------------------------------------------------------------ --

        # evaluate the result: failed should be blocked, other not

        registry = MockedResourceRegistry.registry

        for key, val in registry.items():
            value, _b_ind, _b_count = val

            if 'fail' in key:
                self.assertTrue(value is not None)
            else:
                self.assertTrue(value is None)

        # ------------------------------------------------------------------ --

        # verify that the 4th entry was never evaluated

        self.assertTrue('ldap://ok_bind4.psw.de' not in registry)

        return

    @patch('linotp.useridresolver.LDAPIdResolver.ResourceScheduler',
           MockedResourceScheduler)
    def test_bind_with_fail(self):
        """
        test the failover in the bind handling
        """

        # ------------------------------------------------------------------ --

        # setup the ldap fake resolver, which requires:
        # - an mocked connect
        # - an mocked bindpw, which in normal case would contain the
        #   crypted data
        # the mocked resolver loads the derived mocked ResouceSchduler with
        # the mocked Registry so that we can access the calling data

        IDRS = LDAPResolver
        IDRS.connect = FakeLdapResolver.m_connect

        myldap = IDRS()
        myldap.ldapuri = ("ldap://fail_bind1.psw.de, "
                        "ldap://fail_bind2.psw.de, "
                        "ldap://fail_bind3.psw.de, "
                        "ldap://fail_bind4.psw.de, "
                        )

        myldap.binddn = "Heinz"
        myldap.bindpw = MockedBindPW('geheim1')

        # ------------------------------------------------------------------ --

        # run the bin test
        with freeze_time("2012-01-14 12:00:00"):

            with self.assertRaises(ResolverNotAvailable):
                myldap.bind()

            # -------------------------------------------------------------- --

            # evaluate the result: how often called

            called = FakeLdapResolver.called

            self.assertTrue(len(called) == 4 * TRIES)
            self.assertTrue('ldap://fail_bind4.psw.de' in called)

            # -------------------------------------------------------------- --

            # evaluate the result: failed should be blocked, other not

            registry = MockedResourceRegistry.registry

            for key, value in registry.items():
                self.assertTrue(value is not None)

            # -------------------------------------------------------------- --

            # verify that the 4th entry was evaluated

            self.assertTrue('ldap://fail_bind4.psw.de' in registry)

            # -------------------------------------------------------------- --

            # now reset the calle registration

            FakeLdapResolver.called = []

#           # -------------------------------------------------------------- --

            # and re-run the bind

            with self.assertRaises(ResolverNotAvailable):
                myldap.bind()

            # -------------------------------------------------------------- --

            # now all resources are marked as blocked and
            # none will be called

            called = FakeLdapResolver.called

            self.assertTrue(len(called) == 0)
            self.assertTrue('ldap://fail_bind1.psw.de' not in called)

        with freeze_time("2012-01-14 12:01:00"):

            # -------------------------------------------------------------- --

            # one minute later re-run the bind

            myldap.ldapuri = ("ldap://fail_bind1.psw.de, "
                              "ldap://fail_bind2.psw.de, "
                              "ldap://go_bind3.psw.de, "
                              "ldap://go_bind4.psw.de, "
                              )

            myldap.bind()

            # -------------------------------------------------------------- --

            # evaluate the result: how often called

            called = FakeLdapResolver.called

            self.assertTrue(len(called) == 2 * TRIES + 1)
            self.assertTrue('ldap://go_bind4.psw.de' not in called)

            # -------------------------------------------------------------- --

            # evaluate the result: failed should be blocked, other not

            registry = MockedResourceRegistry.registry

            for key, val in registry.items():
                value, _b_ind, _b_count = val

                if 'fail' in key:
                    self.assertTrue(value is not None)
                else:
                    self.assertTrue(value is None)

            # -------------------------------------------------------------- --

            # verify that the 4th entry was never evaluated

            self.assertTrue('ldap://go_bind4.psw.de' not in registry)

        return

    @patch('linotp.useridresolver.LDAPIdResolver.ResourceScheduler',
           MockedResourceScheduler)
    def test_checkPass_with_failover(self):
        """
        test the failover in the checkPass handling - pw check has no impact
        """

        # ------------------------------------------------------------------ --

        # setup the ldap fake resolver, which requires:
        # - an mocked connect
        # - an mocked bindpw, which in normal case would contain the
        #   crypted data
        # the mocked resolver loads the derived mocked ResouceSchduler with
        # the mocked Registry so that we can access the calling data

        IDRS = LDAPResolver
        IDRS.connect = FakeLdapResolver.m_connect

        myldap = IDRS()
        myldap.ldapuri = ("ldap://fail_bind1.psw.de, "
                          "ldap://fail_bind2.psw.de, "
                          "ldap://ok_bind3.psw.de, "
                          "ldap://ok_bind4.psw.de, "
                        )

        myldap.bindpw = MockedBindPW('geheim1')

        # ------------------------------------------------------------------ --

        # run the checkPass test

        myldap.checkPass('myUid', 'not geheim1')

        # ------------------------------------------------------------------ --

        # evaluate the result: how often called

        called = FakeLdapResolver.called

        self.assertTrue(len(called) == 2 * TRIES + 1)
        self.assertTrue('ldap://ok_bind4.psw.de' not in called)

        # ------------------------------------------------------------------ --

        # evaluate the result: failed should be blocked, other not

        registry = MockedResourceRegistry.registry

        for key, val in registry.items():
            value, _b_ind, _b_count = val

            if 'fail' in key:
                self.assertTrue(value is not None)
            else:
                self.assertTrue(value is None)

        # ------------------------------------------------------------------ --

        # verify that the 4th entry was never evaluated

        self.assertTrue('ldap://ok_bind4.psw.de' not in registry)

        # ------------------------------------------------------------------ --

        # reset the called from the last run

        FakeLdapResolver.called = []

        # ------------------------------------------------------------------ --

        # run the checkPass test

        myldap.checkPass('myUid', 'geheim1')

        # ------------------------------------------------------------------ --

        # evaluate the result: how often called

        called = FakeLdapResolver.called

        self.assertTrue(len(called) == 1)
        self.assertTrue('ldap://ok_bind4.psw.de' not in called)

        # ------------------------------------------------------------------ --

        # evaluate the result: failed should be blocked, other not

        registry = MockedResourceRegistry.registry

        for key, val in registry.items():
            value, _b_ind, _b_count = val

            if 'fail' in key:
                self.assertTrue(value is not None)
            else:
                self.assertTrue(value is None)

        # ------------------------------------------------------------------ --

        # verify that the 4th entry was never evaluated

        self.assertTrue('ldap://ok_bind4.psw.de' not in registry)

        return

# eof #

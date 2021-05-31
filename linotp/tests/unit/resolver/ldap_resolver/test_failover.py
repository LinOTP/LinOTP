# -*- coding: utf-8 -*-

#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
from ldap import LDAPError
from ldap import INVALID_CREDENTIALS

from linotp.lib.resources import ResourceScheduler, DictResourceRegistry

from linotp.useridresolver import LDAPIdResolver as ldap_resolver_module
from linotp.useridresolver.LDAPIdResolver import IdResolver as LDAPResolver
from linotp.useridresolver.UserIdResolver import ResolverNotAvailable

from freezegun import freeze_time
import pytest

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


@pytest.mark.usefixtures("app")
class TestLDAPResolverFailover(unittest.TestCase):
    """
    tests the ldap bind with failover using the Resource Scheduler
    """

    @pytest.fixture(autouse=True)
    def mocked_ldap(self, monkeypatch):
        FakeLdapResolver.called = []
        MockedResourceRegistry.registry = {}

        monkeypatch.setattr(LDAPResolver, 'connect',
                            FakeLdapResolver.m_connect)

        monkeypatch.setattr(ldap_resolver_module, 'ResourceScheduler',
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

        myldap = LDAPResolver()
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

        assert len(called) == 2 * TRIES + 1
        assert 'ldap://ok_bind4.psw.de' not in called

        # ------------------------------------------------------------------ --

        # evaluate the result: failed should be blocked, other not

        registry = MockedResourceRegistry.registry

        for key, val in list(registry.items()):
            value, _b_ind, _b_count = val

            if 'fail' in key:
                assert value is not None
            else:
                assert value is None

        # ------------------------------------------------------------------ --

        # verify that the 4th entry was never evaluated

        assert 'ldap://ok_bind4.psw.de' not in registry

        return

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

        myldap = LDAPResolver()
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

            with pytest.raises(ResolverNotAvailable):
                myldap.bind()

            # -------------------------------------------------------------- --

            # evaluate the result: how often called

            called = FakeLdapResolver.called

            assert len(called) == 4 * TRIES
            assert 'ldap://fail_bind4.psw.de' in called

            # -------------------------------------------------------------- --

            # evaluate the result: failed should be blocked, other not

            registry = MockedResourceRegistry.registry

            for key, value in list(registry.items()):
                assert value is not None

            # -------------------------------------------------------------- --

            # verify that the 4th entry was evaluated

            assert 'ldap://fail_bind4.psw.de' in registry

            # -------------------------------------------------------------- --

            # now reset the calle registration

            FakeLdapResolver.called = []

#           # -------------------------------------------------------------- --

            # and re-run the bind

            with pytest.raises(ResolverNotAvailable):
                myldap.bind()

            # -------------------------------------------------------------- --

            # now all resources are marked as blocked and
            # none will be called

            called = FakeLdapResolver.called

            assert len(called) == 0
            assert 'ldap://fail_bind1.psw.de' not in called

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

            assert len(called) == 2 * TRIES + 1
            assert 'ldap://go_bind4.psw.de' not in called

            # -------------------------------------------------------------- --

            # evaluate the result: failed should be blocked, other not

            registry = MockedResourceRegistry.registry

            for key, val in list(registry.items()):
                value, _b_ind, _b_count = val

                if 'fail' in key:
                    assert value is not None
                else:
                    assert value is None

            # -------------------------------------------------------------- --

            # verify that the 4th entry was never evaluated

            assert 'ldap://go_bind4.psw.de' not in registry

        return

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

        myldap = LDAPResolver()
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

        assert len(called) == 2 * TRIES + 1
        assert 'ldap://ok_bind4.psw.de' not in called

        # ------------------------------------------------------------------ --

        # evaluate the result: failed should be blocked, other not

        registry = MockedResourceRegistry.registry

        for key, val in list(registry.items()):
            value, _b_ind, _b_count = val

            if 'fail' in key:
                assert value is not None
            else:
                assert value is None

        # ------------------------------------------------------------------ --

        # verify that the 4th entry was never evaluated

        assert 'ldap://ok_bind4.psw.de' not in registry

        # ------------------------------------------------------------------ --

        # reset the called from the last run

        FakeLdapResolver.called = []

        # ------------------------------------------------------------------ --

        # run the checkPass test

        myldap.checkPass('myUid', 'geheim1')

        # ------------------------------------------------------------------ --

        # evaluate the result: how often called

        called = FakeLdapResolver.called

        assert len(called) == 1
        assert 'ldap://ok_bind4.psw.de' not in called

        # ------------------------------------------------------------------ --

        # evaluate the result: failed should be blocked, other not

        registry = MockedResourceRegistry.registry

        for key, val in list(registry.items()):
            value, _b_ind, _b_count = val

            if 'fail' in key:
                assert value is not None
            else:
                assert value is None

        # ------------------------------------------------------------------ --

        # verify that the 4th entry was never evaluated

        assert 'ldap://ok_bind4.psw.de' not in registry

        return

# eof #

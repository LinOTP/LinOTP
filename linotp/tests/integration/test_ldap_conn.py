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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""LinOTP integration test for LDAP connections."""

import pytest
from click.testing import CliRunner

from linotp.useridresolver.LDAPIdResolver import ldap_test

# This test inspects the output of the `linotp ldap-test` command,
# which does an exhaustive run through all the different ways to
# connect to an LDAP server, including some that can't be reached from
# the web frontend via Selenium. In particular, we test what happens
# if certificates must be validated but can't.


@pytest.mark.xfail(reason="wants a local linotp instance")
def test_ldap_conn():
    runner = CliRunner(env={"FLASK_APP": "linotp.app"}, mix_stderr=False)
    people = "ou=people,dc=blackdog,dc=corp,dc=lsexperts,dc=de"
    result = runner.invoke(
        ldap_test,
        [
            "-u",
            "ldap://blackdog.corp.lsexperts.de",
            "-b",
            people,
            "-d",
            'cn="عبد الحليم حافظ",' + people,
            "-p",
            "Test123!",
            "--all-cases",
        ],
    )
    assert result.exit_code == 0  # All tests have succeeded.

    # The `linotp ldap-test … --all-cases` command prefixes each test
    # case output line (and no others) with a `.`. Case output lines
    # that end in “Yes” mean “success”, and make us happy. We wish to
    # be completely happy.

    assert all(
        line.endswith("Yes")
        for line in result.output.split("\n")
        if line and line[0] == "."
    )

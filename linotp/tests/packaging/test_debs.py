#!/bin/env python3
#
# LinOTP - the Open Source solution for multi-factor authentication
#
# Coypright © 2020- arxes-tolina GmbH
#
# Pytest interface to test-upgrade tool

import os
import pytest

from subprocess import run, DEVNULL, STDOUT


def run_test_upgrade_command(cmd: str):
    tool = "./test-upgrade"

    envvars = [
        "LINOTP_PURGE_ALLOW",
        "http_proxy",
        "integration_suite",
        "mysql_root_password",
        "linotp3_deb",
        "sudo",
        "DOTENV",
    ]

    # Pass through environment variables
    env = {v: os.environ.get(v, "") for v in envvars}

    # Run test tool command
    ret = run([tool, cmd], check=False, env=env, stdin=DEVNULL, stderr=STDOUT)

    assert ret.returncode == 0, ret


@pytest.mark.parametrize(
    "name,description",
    [
        ("install2", "Purge, install v2, selenium test"),
        ("install3", "Purge, install v3"),
        ("upgrade2to3", "Purge, install v2, upgrade to v3"),
        ("install3psql", "Purge, install using postgres database"),
        ("3reinstall", "Install v3 then reinstall v3"),
        ("selenium_check", "Selenium test currently installed package"),
        ("mysql_password", "Check v3 install with password containing spaces"),
        ("htpasswd", "Check admin password can be changed"),
        ("noapache", "Install / reconfigure with apache disabled"),
        ("purgecheck", "Install packages and check removal"),
        ("nodatabase", "Install without database service"),
        ("encodingfix", "Check encoding fix during migration"),
    ],
)
def test_run_upgrade_test(name, description):
    run_test_upgrade_command(name)

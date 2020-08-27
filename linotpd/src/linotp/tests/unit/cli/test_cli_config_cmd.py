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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""LinOTP test for `linotp config` command group."""

import re

import pytest

from linotp.cli import main as cli_main


@pytest.fixture
def runner(app):
    return app.test_cli_runner(mix_stderr=False)


@pytest.mark.parametrize("name,options,value,expected", [
    ("AUDIT_POOL_RECYCLE", [], None, "AUDIT_POOL_RECYCLE=<>\n"),
    ("AUDIT_POOL_RECYCLE", ['--values'], None, "<>\n"),
    ("AUDIT_POOL_RECYCLE", ['-V'], None, "<>\n"),
    ("AUDIT_POOL_RECYCLE", ['--modified'], None, ""),
    ("AUDIT_POOL_RECYCLE", ['-m'], None, ""),
    ("AUDIT_POOL_RECYCLE", [], 1000, "AUDIT_POOL_RECYCLE=1000\n"),
    ("AUDIT_POOL_RECYCLE", ['--modified'], 1000, "AUDIT_POOL_RECYCLE=1000\n"),
    ("AUDIT_POOL_RECYCLE", ['-m'], 1000, "AUDIT_POOL_RECYCLE=1000\n"),
    ("AUDIT_POOL_RECYCLE", ['-V', '-m'], None, ""),
    ("AUDIT_POOL_RECYCLE", ['-V', '-m'], 1000, "1000\n"),
])
def test_config_show_single(app, runner, name, options, value, expected):
    if value is not None:
        app.config[name] = value
    result = runner.invoke(cli_main, ['config', 'show', name] + options)
    assert result.exit_code == 0
    assert result.output == expected.replace('<>', str(app.config[name]))


@pytest.mark.parametrize("names,options,values,expected", [
    (["AUDIT_POOL_RECYCLE", "LOGFILE_NAME"], [], {},
     "AUDIT_POOL_RECYCLE=<AUDIT_POOL_RECYCLE>\nLOGFILE_NAME=<LOGFILE_NAME>\n"),
    (["AUDIT_POOL_RECYCLE", "LOGFILE_NAME"], ['--values'], {},
     "<AUDIT_POOL_RECYCLE>\n<LOGFILE_NAME>\n"),
    (["AUDIT_POOL_RECYCLE", "LOGFILE_NAME"], [], {'LOGFILE_NAME': 'foo'},
     "AUDIT_POOL_RECYCLE=<AUDIT_POOL_RECYCLE>\nLOGFILE_NAME=foo\n"),
    (["AUDIT_POOL_RECYCLE", "LOGFILE_NAME"], ['--modified'], {}, ""),
    (["AUDIT_POOL_RECYCLE", "LOGFILE_NAME"], ['--modified'],
     {'LOGFILE_NAME': 'foo'}, "LOGFILE_NAME=foo\n"),
    (["AUDIT_POOL_RECYCLE", "LOGFILE_NAME"], ['--modified', '--values'],
     {'LOGFILE_NAME': 'foo'}, "foo\n"),
])
def test_config_show_multi(app, runner, names, options, values, expected):
    for key, value in values.items():
        app.config[key] = value
    result = runner.invoke(cli_main, ['config', 'show'] + names + options)
    assert result.exit_code == 0
    print(f"output:\n{result.output}")
    assert result.output == re.sub(
        r'<(\w+?)>', lambda m: str(app.config[m.group(1)]), expected)


def test_config_show_all(app, runner):
    result = runner.invoke(cli_main, ['config', 'show'])
    assert result.exit_code == 0

    lines = result.output.strip('\n').split('\n')

    # Check that all output lines start with an identifier and equals sign.

    assert all(re.match(r'^\w+?=', ln) for ln in lines)

    # Check that the identifiers agree with actual configuration items. (This
    # is not as ridiculous as it seems; it has turned up one configuration
    # item that wasn't actually in the schema.)

    assert (
        [ln.split('=')[0] for ln in sorted(lines)] == list(sorted(app.config))
    )


@pytest.mark.parametrize("name,options,value,expected", [
    ("BABEL_DOMAIN", [], None,
     ("BABEL_DOMAIN:\n"
      "  Type: str\n"
      "  Default value: linotp\n"
      "  Current value: linotp\n"
      "  Description: LinOTP message catalog files are called `linotp.mo`.\n"
      "    Tweak this setting at your own risk.\n")),
    ("BABEL_DOMAIN", [], "foobar",
     ("BABEL_DOMAIN:\n"
      "  Type: str\n"
      "  Default value: linotp\n"
      "  Current value: foobar\n"
      "  Description: LinOTP message catalog files are called `linotp.mo`.\n"
      "    Tweak this setting at your own risk.\n")),
    ("BABEL_DOMAIN", ['--sample-file'], None,
     ("# This is a sample LinOTP configuration file.\n"
      "# It contains some configuration settings with their hard-coded\n"
      "# defaults. Feel free to copy this file and uncomment and edit any of\n"
      "# these (with appropriate caution). The LINOTP_CFG environment "
      "variable\n"
      "# can be used to specify a list of LinOTP configuration files which\n"
      "# will be read in order (the last encountered value for any "
      "configuration\n"
      "# setting wins.) On many installations, a good place for your own\n"
      "# configuration settings is /etc/linotp/linotp.cfg.\n"
      "\n"
      "# BABEL_DOMAIN: LinOTP message catalog files are called `linotp.mo`.\n"
      "# Tweak this setting at your own risk.\n"
      "\n"
      "## BABEL_DOMAIN = 'linotp'\n"
      "\n")),
    ("BABEL_DOMAIN", ['--sample-file'], "foobar",  # doesn't change output
     ("# This is a sample LinOTP configuration file.\n"
      "# It contains some configuration settings with their hard-coded\n"
      "# defaults. Feel free to copy this file and uncomment and edit any of\n"
      "# these (with appropriate caution). The LINOTP_CFG environment "
      "variable\n"
      "# can be used to specify a list of LinOTP configuration files which\n"
      "# will be read in order (the last encountered value for any "
      "configuration\n"
      "# setting wins.) On many installations, a good place for your own\n"
      "# configuration settings is /etc/linotp/linotp.cfg.\n"
      "\n"
      "# BABEL_DOMAIN: LinOTP message catalog files are called `linotp.mo`.\n"
      "# Tweak this setting at your own risk.\n"
      "\n"
      "## BABEL_DOMAIN = 'linotp'\n"
      "\n")),
    ("BABEL_DOMAIN", ['--sample-file', '--no-banner'], None,
     ("# BABEL_DOMAIN: LinOTP message catalog files are called `linotp.mo`.\n"
      "# Tweak this setting at your own risk.\n"
      "\n"
      "## BABEL_DOMAIN = 'linotp'\n"
      "\n")),
    ("AUDIT_POOL_RECYCLE", [], None,
     ("AUDIT_POOL_RECYCLE:\n"
      "  Type: int\n"
      "  Constraints: value >= 0\n"
      "  Default value: 3600\n"
      "  Current value: 3600\n"
      "  Description: Recycle time for the SQLAlchemy connection pool used\n"
      "    for the audit database (in seconds). Connections that are older\n"
      "    than the value of this parameter are invalidated and replaced "
      "when\n"
      "    the application requests a new connection.\n")),
    ("FIZZBIN", [], None, "No information on FIZZBIN\n"),
])
def test_config_explain_single(app, runner, name, options, value, expected):
    if value is not None:
        app.config[name] = value
    result = runner.invoke(cli_main, ['config', 'explain', name] + options)
    assert result.exit_code == 0
    assert result.output == expected


def test_config_explain_multiple(runner):
    result = runner.invoke(cli_main, ['config', 'explain',
                                      "BABEL_DOMAIN", "AUDIT_POOL_RECYCLE"])
    assert result.exit_code == 0
    assert result.output == (
        "BABEL_DOMAIN:\n"
        "  Type: str\n"
        "  Default value: linotp\n"
        "  Current value: linotp\n"
        "  Description: LinOTP message catalog files are called `linotp.mo`.\n"
        "    Tweak this setting at your own risk.\n"
        "AUDIT_POOL_RECYCLE:\n"
        "  Type: int\n"
        "  Constraints: value >= 0\n"
        "  Default value: 3600\n"
        "  Current value: 3600\n"
        "  Description: Recycle time for the SQLAlchemy connection pool used\n"
        "    for the audit database (in seconds). Connections that are older\n"
        "    than the value of this parameter are invalidated and replaced "
        "when\n"
        "    the application requests a new connection.\n")


def test_config_explain_multiple_sample(runner):
    result = runner.invoke(cli_main, ["config", "explain", "--sample-file",
                                      "BABEL_DOMAIN", "AUDIT_POOL_RECYCLE"])
    assert result.exit_code == 0
    assert result.output == (
        "# This is a sample LinOTP configuration file.\n"
        "# It contains some configuration settings with their hard-coded\n"
        "# defaults. Feel free to copy this file and uncomment and edit any "
        "of\n"
        "# these (with appropriate caution). The LINOTP_CFG environment "
        "variable\n"
        "# can be used to specify a list of LinOTP configuration files which\n"
        "# will be read in order (the last encountered value for any "
        "configuration\n"
        "# setting wins.) On many installations, a good place for your own\n"
        "# configuration settings is /etc/linotp/linotp.cfg.\n"
        "\n"
        "# BABEL_DOMAIN: LinOTP message catalog files are called "
        "`linotp.mo`.\n"
        "# Tweak this setting at your own risk.\n"
        "\n"
        "## BABEL_DOMAIN = 'linotp'\n"
        "\n"
        "# AUDIT_POOL_RECYCLE: Recycle time for the SQLAlchemy connection "
        "pool\n"
        "# used for the audit database (in seconds). Connections that are "
        "older\n"
        "# than the value of this parameter are invalidated and replaced "
        "when\n"
        "# the application requests a new connection.\n"
        "#\n"
        "# Constraints: value >= 0\n"
        "\n"
        "## AUDIT_POOL_RECYCLE = 3600\n"
        "\n")


def test_config_explain_all(app, runner):
    result = runner.invoke(cli_main, ["config", "explain"])
    assert result.exit_code == 0

    # The number of unindented lines corresponds to the number of items
    # in the output of the `linotp config explain` command. It must equal
    # the number of items in the configuration schema.

    lines = result.output.strip('\n').split('\n')
    assert (
        len([ln for ln in lines if not ln[0].isspace()])
        == len(app.config.config_schema.as_dict()))


def test_config_explain_all_schema(app, runner):
    result = runner.invoke(cli_main, ['config', 'explain', '--sample-file'])
    assert result.exit_code == 0

    lines = result.output.strip('\n').split('\n')

    # Check banner at the beginning
    assert lines[0].startswith("# This is a sample")
    assert lines[1].startswith("# It contains all available configuration")

    # The number of lines starting with two hash marks corresponds to
    # the number of items in the output of the `linotp config explain`
    # command. It must equal the number of items in the configuration
    # schema.

    assert (
        len([ln for ln in lines if ln and ln.startswith('## ')])
        == len(app.config.config_schema.as_dict()))


def test_config_explain_invalid_argument(app, runner):
    result = runner.invoke(cli_main, ['config', 'explain', '--foobar'])
    assert result.exit_code == 2
    assert result.output == ""
    assert result.stderr[result.stderr.find("Usage: "):] == (
        # The real error message has `linotp config explain` rather than just
        # `explain`, but the test runner can't know this.
        "Usage: linotp config explain [OPTIONS] [ITEMS]...\n"
        'Try "linotp config explain --help" for help.\n'
        "\n"
        "Error: no such option: --foobar\n")

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

import base64
import datetime
import os
from pathlib import Path
import stat
import subprocess

import pytest

import click.termui

from linotp.app import LinOTPApp
from linotp.cli import main, Echo, get_backup_filename
import linotp.cli.init_cmd as c

from sqlalchemy import create_engine
from linotp.model import Config, meta, setup_db, set_defaults


@pytest.fixture
def app(tmp_path):
    app = LinOTPApp()
    config = {
        'TESTING': True,
        'BACKUP_FILE_TIME_FORMAT': '%Y-%m-%d_%H-%M',
        'SQLALCHEMY_DATABASE_URI': "sqlite:///" + str(tmp_path/"linotp.sqlite")
    }
    app.config.update(config)
    return app


def feed(input):
    """Used to mock lines of input from a string."""
    input_list = input.split('\n')

    def f(prompt):
        if not input_list:
            return None
        input = input_list[0]
        del input_list[0]
        return input

    return f


# ----------------------------------------------------------------------
# Tests for `_overwrite_check`
# ----------------------------------------------------------------------

@pytest.mark.parametrize("what,filename,input,result,output", [
    ("foo", "bar", "yes", True, ("a foo in 'bar'", "write existing foo")),
    ("abc", "baz", "yes", True, ("an abc in 'baz'", "write existing abc")),
    ("foo", "bar", "no", False, ("a foo in 'bar'", "write existing foo",
                                 "Not overwriting existing foo.")),
    ("foo", "bar", "xyz\nno", False, ("a foo in 'bar'", "write existing foo",
                                      "Not overwriting existing foo.")),
])
def test_overwrite_check(monkeypatch, capsys, app,
                         what, filename, input, result, output):
    monkeypatch.setattr(click.termui, 'visible_prompt_func', feed(input))
    fn_result = c._overwrite_check(what, filename)
    assert fn_result == result
    captured = capsys.readouterr()
    for s in output:
        assert s in captured.out


# ----------------------------------------------------------------------
# Tests for `_make_backup`
# ----------------------------------------------------------------------

@pytest.mark.parametrize("permissions,result", [
    (0o700, True),
    (0o500, False),
])
def test_make_backup(app, capsys, freezer, tmp_path, permissions, result):
    app.echo = Echo(verbosity=1)  # we're not going through main so need this
    freezer.move_to("2020-08-18 19:25:33")
    filename = "foo"
    data = "supercalifragilisticexpialidocious"
    (tmp_path / filename).write_text(data)
    time_format = app.config["BACKUP_FILE_TIME_FORMAT"]
    expected_name = (
        filename + "." + datetime.datetime.now().strftime(time_format)
    )
    tmp_path.chmod(permissions)
    fn_result = c._make_backup("test file", str(tmp_path / filename))
    assert result == fn_result
    captured = capsys.readouterr()
    if result:                  # expecting success
        assert not (tmp_path / filename).exists()
        assert (tmp_path / expected_name).exists()
        assert (tmp_path / expected_name).read_text() == data
        assert ("Moved existing test file to "
                f"{str(tmp_path / expected_name)}") in captured.err
    else:                       # expecting failure
        assert (tmp_path / filename).exists()
        assert not (tmp_path / expected_name).exists()
        assert (f"Error moving test file to {str(tmp_path / expected_name)}: "
                in captured.err)


# ----------------------------------------------------------------------
# Tests for `_run_command`
# ----------------------------------------------------------------------

@pytest.mark.parametrize("cmd,exit_code,output,stderr", [
    (["echo", "foo"], 0, "foo\n", ""),
    (["false"], 1, "",
     "Test failed:\nCommand 'false' returned exit code 1\nOutput was:\n\n"),
    (["blarglqwertz"], None,
     "[Errno 2] No such file or directory: 'blarglqwertz': 'blarglqwertz'",
     ("Test failed:\nCommand 'blarglqwertz' raised exception\nOutput was:\n"
      "[Errno 2] No such file or directory: 'blarglqwertz': 'blarglqwertz'\n")
     ),
])
def test_run_command(app, capsys, cmd, exit_code, output, stderr):
    app.echo = Echo()        # need this here as we're not going through main

    ret = c._run_command("Test", cmd)
    captured = capsys.readouterr()
    assert ret.exit_code == exit_code
    if output is not None:
        assert ret.output == output
    if stderr is not None:
        assert captured.err == stderr


def test_run_command_signal(app, capsys, monkeypatch):
    app.echo = Echo()        # need this here as we're not going through main

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, -11, b"foo", b"bar")

    monkeypatch.setattr(subprocess, 'run', fake_run)
    ret = c._run_command("Test", ["true"])
    captured = capsys.readouterr()
    assert ret.exit_code == -11
    assert ret.output == "foo"
    assert captured.err == (
        "Test failed:\nCommand 'true' terminated by signal 11\n"
        "Output was:\nfoo\n"
    )


# ----------------------------------------------------------------------
# Tests for `linotp init database`
# ----------------------------------------------------------------------

def setup_db_ok(app, erase_all_data):
    print("ERASE" if erase_all_data else "KEEP")


def setup_db_exception(app, erase_all_data):
    raise Exception("Generic exception")


@pytest.mark.parametrize("args,setup_fn,input,output,result", [
    (["-v", "init", "database"], setup_db_ok, "",
     ["Creating database", "KEEP", "created"], 0),
    (["-v", "init", "database", "--erase-all-data"], setup_db_ok, "no",
     ["Do you really want to erase the database?"], 0),
    (["-v", "init", "database", "--erase-all-data"], setup_db_ok, "yes",
     ["Do you really want to erase the database?",
      "Recreating", "ERASE", "Database created"], 0),
    (["-v", "init", "database", "--erase-all-data", "--yes"], setup_db_ok, "",
     ["Recreating", "ERASE", "Database created"], 0),
    (["init", "database"], setup_db_exception, "",
     ["Failed to create database: Generic exception"], 1),

])
def test_init_database_cmd(app, monkeypatch, capsys, runner,
                           args, setup_fn, input, output, result):
    # This tests option handling only. Database ops are tested elsewhere.

    monkeypatch.setattr(c, 'setup_db', setup_fn)
    cmd_result = runner.invoke(main, args, input=input)
    assert cmd_result.exit_code == result
    for s in output:
        assert s in cmd_result.output


# These tests should really go to where the model tests live.

@pytest.fixture
def engine(app):
    return create_engine(app.config["SQLALCHEMY_DATABASE_URI"])


def test_setup_db_creates_tables(app, engine, capsys):
    app.echo = Echo(verbosity=1)

    # GIVEN an empty database
    assert 'Config' not in engine.table_names()

    # WHEN I call `setup_db` without additional arguments
    setup_db(app)
    captured = capsys.readouterr()

    # THEN the tables are created
    assert 'Setting up database' in captured.err
    assert 'Config' in engine.table_names()


@pytest.mark.parametrize('erase', (False, True))
def test_setup_db_erase_all(app, engine, capsys, erase):
    app.echo = Echo(verbosity=1)

    # GIVEN a database with records
    setup_db(app)

    KEY = "linotp.foobar"
    item = Config(Key=KEY, Value="123", Type="int", Description="test item")
    meta.Session.add(item)
    meta.Session.commit()
    assert meta.Session.query(Config).filter_by(Key=KEY).count() == 1
    meta.Session.remove()

    # WHEN I invoke `setup_db`
    setup_db(app, drop_data=erase)

    if erase:
        # Additional record should have disappeared
        assert meta.Session.query(Config).filter_by(Key=KEY).count() == 0
    else:
        # Additional record should still be there
        assert meta.Session.query(Config).filter_by(Key=KEY).count() == 1

        item = meta.Session.query(Config).filter_by(Key=KEY).first()
        meta.Session.delete(item)
        meta.Session.commit()


# ----------------------------------------------------------------------
# Tests for `linotp init enc-key`
# ----------------------------------------------------------------------

KEY_INSTRUCTIONS = """/key 2020-08-18T19:25:33

INSTRUCTIONS: Print this and store it in a safe place. Remember where you put
it.

To recover the keys, concatenate the FIRST column of each line and pass the
result to `linotp init enc-key` using the `--keys` option (spaces are
allowed to make the key data easier to enter):

  linotp init enc-key --keys '000102030405...5a5b5c5d5e5f'

Compare the output to this list; if the values on the final lines agree,
everything is probably OK. Otherwise compare the values in the second columns;
if there is a mismatch, then the data in the first column on that line
contains one or more typoes. Enjoy!

"""

KEY_BYTES = c.KEY_COUNT * c.KEY_LENGTH

SECRET_KEY = bytes(range(KEY_BYTES))
ZERO_KEY = bytes(KEY_BYTES)

KEY_DUMP = """0001020304050607 b8317597
08090a0b0c0d0e0f 385944a4
1011121314151617 5960a73e
18191a1b1c1d1e1f d908960d
2021222324252627 a1e3d684
28292a2b2c2d2e2f 218be7b7
3031323334353637 40b2042d
38393a3b3c3d3e3f c0da351e
4041424344454647 8b9433b1
48494a4b4c4d4e4f 0bfc0282
5051525354555657 6ac5e118
58595a5b5c5d5e5f eaadd02b
                 f13e9b66\n"""


@pytest.mark.parametrize("with_instructions,output", [
    (False, KEY_DUMP),
    (True, KEY_INSTRUCTIONS + KEY_DUMP),
])
def test_dump_key(app, capsys, freezer, tmp_path, with_instructions, output):
    freezer.move_to("2020-08-18 19:25:33")
    filename = tmp_path / "key"
    filename.write_bytes(SECRET_KEY)
    c.dump_key(str(filename), instructions=with_instructions)
    captured = capsys.readouterr()
    fn_start = captured.out.find("/key")
    cap_out = captured.out[fn_start:] if fn_start >= 0 else captured.out
    assert cap_out == output


# Replaces `test_enckey.test_key_file_content()`
# and `test_enckey.test_file_access()`

@pytest.mark.parametrize("data,content", [
    ('', ZERO_KEY),
    (bytes.hex(SECRET_KEY), SECRET_KEY),
])
def test_create_secret_key(monkeypatch, tmp_path, data, content):
    monkeypatch.setattr(os, 'urandom', lambda n: bytes(n))
    filename = tmp_path / "encKey"
    c.create_secret_key(str(filename), data)
    assert filename.exists()
    assert filename.read_bytes() == content
    permissions = stat.S_IMODE(filename.stat().st_mode)
    assert permissions == c.SECRET_FILE_PERMISSIONS


def create_secret_key_ok(filename, data=''):
    if not data:
        data = SECRET_KEY
    open(filename, "wb").write(data)


def create_secret_key_exception(filename, data=""):
    raise OSError("Generic OS-level exception")


# Replaces `test_enckey.test_file_not_exists()`,
# `test_enckey.test_file_exists_no_overwrite()`,
# `test_enckey.test_file_exists_and_overwrite() and then some.

@pytest.mark.parametrize(
    "args,csk_fn,input,output,has_file,makes_file,result",
    [(['init', 'enc-key'], create_secret_key_ok, "", [], False, True, 0),
     (['init', 'enc-key'], create_secret_key_ok, "no\n",
      ["There is already an enc-key", "Dire Consequences", "Not overwriting"],
      True, False, 0),
     (['-v', 'init', 'enc-key'], create_secret_key_ok, "yes\n",
      ["There is already an enc-key", "Dire Consequences",
       "Moved existing enc-key to", "Wrote enc-key to"], True, True, 0),
     (['-v', 'init', 'enc-key', '--force'], create_secret_key_ok, "",
      ["Wrote enc-key to"], True, True, 0),
     (['-v', 'init', 'enc-key', '--force'], create_secret_key_ok, "",
      ["Wrote enc-key to"], False, True, 0),
     (['init', 'enc-key'], create_secret_key_exception, "",
      ["Error writing enc-key to", "encKey: Generic OS-level exception"],
      False, False, 1),
     (['-v', 'init', 'enc-key', '--dump'], create_secret_key_ok, "",
      ["INSTRUCTIONS", "linotp init enc-key --keys '000102030405...5a",
       "\n0001020304050607 b8317597\n", "\n                 f13e9b66\n"],
      False, True, 0),
     ])
def test_init_enc_key_cmd(app, tmp_path, monkeypatch, runner,
                          args, csk_fn, input, output,
                          has_file, makes_file, result):
    monkeypatch.setattr(c, 'create_secret_key', csk_fn)
    secret_file_name = tmp_path / "encKey"
    app.config["SECRET_FILE"] = str(secret_file_name)
    if has_file:
        secret_file_name.write_bytes(ZERO_KEY)
    else:
        assert not secret_file_name.exists()
    cmd_result = runner.invoke(main, args, input=input)
    assert cmd_result.exit_code == result
    for s in output:
        assert s in cmd_result.output
    if makes_file:
        assert secret_file_name.exists()
        assert secret_file_name.read_bytes() == SECRET_KEY
    else:
        if (secret_file_name.exists()
                and secret_file_name.read_bytes() == SECRET_KEY):  # noqa: E129
            assert False, "secret file was created but shouldn't have been"
        elif has_file and secret_file_name.exists():
            if secret_file_name.read_bytes() == ZERO_KEY:
                pass                # still the old file, this is OK
            else:
                assert False, "shouldn't touch secret file but it was changed"


def test_init_enc_key_cmd_failed_backup(app, tmp_path, runner):
    secret_file_name = tmp_path / "encKey"
    app.config["SECRET_FILE"] = str(secret_file_name)
    secret_file_name.write_bytes(ZERO_KEY)
    os.chmod(tmp_path, 0o000)   # make writing a new file fail
    cmd_result = runner.invoke(main, ["init", "enc-key", "--force"])
    os.chmod(tmp_path, 0o700)   # back to normal
    assert cmd_result.exit_code == 1
    assert secret_file_name.exists()
    assert "Error writing enc-key to" in cmd_result.output
    assert "encKey: [Errno 13] Permission denied: " in cmd_result.output


# ----------------------------------------------------------------------
# Tests for `linotp init audit-keys`
# ----------------------------------------------------------------------

KEY_START = "-----BEGIN {0} KEY-----"
KEY_END = "-----END {0} KEY-----"


def check_key_validity(s: str, type_: str) -> bool:
    lines = s.strip('\n').split('\n')
    assert lines[0] == KEY_START.format(type_)
    assert lines[-1] == KEY_END.format(type_)
    # The following will raise binascii.Error on errors
    assert base64.b64decode("".join(lines[1:-1]).encode('ascii')) != b''


@pytest.mark.parametrize(("args,input,output,has_file,"
                          "makes_file,check_backup,result"), [
    (['-v', 'init', 'audit-keys'], "",
     ["Wrote private audit key to", "Extracted public audit key to"],
     False, True, False, 0),
    (['-v', 'init', 'audit-keys', '--force'], "",
     ["Wrote private audit key to", "Extracted public audit key to"],
     False, True, False, 0),
    (['-v', 'init', 'audit-keys'], "no",
     ["There is already a private audit key in",
      "Not overwriting existing private audit key."], True, False, False, 0),
    (['-v', 'init', 'audit-keys'], "yes",
     ["There is already a private audit key in",
      "Moved existing private audit key to",
      "Wrote private audit key to", "Extracted public audit key to"],
     True, False, True, 0),
    (['-v', 'init', 'audit-keys', '--force'], "",
     ["Moved existing private audit key to",
      "Wrote private audit key to", "Extracted public audit key to"],
     True, False, True, 0),
])
def test_init_audit_keys_cmd(app, tmp_path, runner, freezer,
                             args, input, output,
                             has_file, makes_file, check_backup, result):
    freezer.move_to("2020-08-18 19:25:33")
    private_key_file = tmp_path / "private.pem"
    public_key_file = tmp_path / "public.pem"
    app.config["AUDIT_PRIVATE_KEY_FILE"] = str(private_key_file)
    app.config["AUDIT_PUBLIC_KEY_FILE"] = str(public_key_file)

    PRIVATE_KEY = "EXISTING PRIVATE KEY"
    if has_file:
        private_key_file.write_text(PRIVATE_KEY)
    else:
        assert not private_key_file.exists()

    cmd_result = runner.invoke(main, args, input=input)
    assert cmd_result.exit_code == result
    for s in output:
        assert s in cmd_result.output
    if makes_file:
        assert private_key_file.exists()
        check_key_validity(private_key_file.read_text(), 'RSA PRIVATE')
        assert public_key_file.exists()
        check_key_validity(public_key_file.read_text(), 'PUBLIC')
    if check_backup:
        backup_file = Path(get_backup_filename(str(private_key_file)))
        assert backup_file.exists()
        assert backup_file.read_text() == PRIVATE_KEY


def test_init_audit_keys_cmd_failed_backup(app, tmp_path, runner, monkeypatch):
    private_key_file = tmp_path / "private.pem"
    public_key_file = tmp_path / "public.pem"
    app.config["AUDIT_PRIVATE_KEY_FILE"] = str(private_key_file)
    app.config["AUDIT_PUBLIC_KEY_FILE"] = str(public_key_file)

    def os_replace_exception(src, dst, **kwargs):
        raise OSError("Generic OS-level exception")

    monkeypatch.setattr(os, 'replace', os_replace_exception)

    private_key_file.write_bytes(ZERO_KEY)
    cmd_result = runner.invoke(main, ["init", "audit-keys", "--force"])
    assert cmd_result.exit_code == 1
    assert private_key_file.exists()
    assert "Error moving private audit key to" in cmd_result.output
    assert ": Generic OS-level exception\n" in cmd_result.output

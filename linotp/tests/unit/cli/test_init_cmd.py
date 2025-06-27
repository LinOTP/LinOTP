#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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

import base64
import binascii
import datetime
import os
import stat
import subprocess
from pathlib import Path

import click.termui
import pytest
from sqlalchemy import create_engine, inspect

import linotp.cli.init_cmd as c
from linotp import __version__
from linotp.app import LinOTPApp
from linotp.cli import Echo, get_backup_filename, main
from linotp.lib.security.default import DefaultSecurityModule
from linotp.model import db, init_db_tables, setup_db
from linotp.model.config import Config
from linotp.model.token import Token


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setitem(os.environ, "LINOTP_CMD", "init")
    app = LinOTPApp()
    config = {
        "TESTING": True,
        "BACKUP_FILE_TIME_FORMAT": "%Y-%m-%d_%H-%M",
        "DATABASE_URI": "sqlite:///" + str(tmp_path / "linotp.sqlite"),
        "AUDIT_DATABASE_URI": "SHARED",
        "ADMIN_USERNAME": "",
        "ADMIN_PASSWORD": "",
        "ADMIN_REALM_NAME": "",
        "ADMIN_RESOLVER_NAME": "",
    }
    app.config.update(config)
    yield app


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


def feed(input):
    """Used to mock lines of input from a string."""
    input_list = input.split("\n")

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


@pytest.mark.parametrize(
    "what,filename,input,result,output",
    [
        ("foo", "bar", "yes", True, ("a foo in 'bar'", "write existing foo")),
        ("abc", "baz", "yes", True, ("an abc in 'baz'", "write existing abc")),
        (
            "foo",
            "bar",
            "no",
            False,
            (
                "a foo in 'bar'",
                "write existing foo",
                "Not overwriting existing foo.",
            ),
        ),
        (
            "foo",
            "bar",
            "xyz\nno",
            False,
            (
                "a foo in 'bar'",
                "write existing foo",
                "Not overwriting existing foo.",
            ),
        ),
    ],
)
def test_overwrite_check(
    monkeypatch, capsys, app, what, filename, input, result, output
):
    monkeypatch.setattr(click.termui, "visible_prompt_func", feed(input))
    fn_result = c._overwrite_check(what, filename)
    assert fn_result == result
    captured = capsys.readouterr()
    for s in output:
        assert s in captured.out


# ----------------------------------------------------------------------
# Tests for `_make_backup`
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "has_write_permission,result",
    [
        (True, True),
        (False, False),
    ],
)
def test_make_backup(
    app, capsys, freezer, tmp_path, monkeypatch, has_write_permission, result
):
    # Raise an OSError if we don't have write permission
    def mock_replace(src, dst):
        if not has_write_permission:
            raise OSError(13, "Permission denied")
        os.rename(src, dst)

    monkeypatch.setattr("os.replace", mock_replace)

    # Test setup
    app.echo = Echo(verbosity=1)  # we're not going through main so need this
    freezer.move_to("2020-08-18 19:25:33")
    filename = "foo"
    data = "supercalifragilisticexpialidocious"
    (tmp_path / filename).write_text(data)
    time_format = app.config["BACKUP_FILE_TIME_FORMAT"]
    expected_name = filename + "." + datetime.datetime.now().strftime(time_format)

    # Actual test
    fn_result = c._make_backup("test file", str(tmp_path / filename))
    assert result == fn_result
    captured = capsys.readouterr()
    if result:  # expecting success
        assert not (tmp_path / filename).exists()
        assert (tmp_path / expected_name).exists()
        assert (tmp_path / expected_name).read_text() == data
        assert (
            f"Moved existing test file to {tmp_path / expected_name!s}"
        ) in captured.err
    else:  # expecting failure
        assert (tmp_path / filename).exists()
        assert not (tmp_path / expected_name).exists()
        assert (
            f"Error moving test file to {tmp_path / expected_name!s}: " in captured.err
        )


# ----------------------------------------------------------------------
# Tests for `_run_command`
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd,exit_code,output,stderr",
    [
        (["echo", "foo"], 0, "foo\n", ""),
        (
            ["false"],
            1,
            "",
            "Test failed:\nCommand 'false' returned exit code 1\nOutput was:\n\n",
        ),
        (
            ["blarglqwertz"],
            None,
            "[Errno 2] No such file or directory: 'blarglqwertz'",
            (
                "Test failed:\nCommand 'blarglqwertz' raised exception\nOutput was:\n"
                "[Errno 2] No such file or directory: 'blarglqwertz'"
            ),
        ),
    ],
)
def test_run_command(app, capsys, cmd, exit_code, output, stderr):
    app.echo = Echo()  # need this here as we're not going through main

    ret = c._run_command("Test", cmd)
    captured = capsys.readouterr()
    assert ret.exit_code == exit_code
    if output is not None:
        assert output in ret.output
    if stderr is not None:
        assert stderr in captured.err


def test_run_command_signal(app, capsys, monkeypatch):
    app.echo = Echo()  # need this here as we're not going through main

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, -11, b"foo", b"bar")

    monkeypatch.setattr(subprocess, "run", fake_run)
    ret = c._run_command("Test", ["true"])
    captured = capsys.readouterr()
    assert ret.exit_code == -11
    assert ret.output == "foo"
    assert captured.err == (
        "Test failed:\nCommand 'true' terminated by signal 11\nOutput was:\nfoo\n"
    )


# ----------------------------------------------------------------------
# Tests for `linotp init database`
# ----------------------------------------------------------------------


def init_db_tables_ok(app, erase_all_data):
    print("ERASE" if erase_all_data else "KEEP")


def init_db_tables_exception(app, erase_all_data):
    msg = "Generic exception"
    raise Exception(msg)


@pytest.mark.parametrize(
    "args,idt_fn,input,output,result",
    [
        (
            ["-v", "init", "database"],
            init_db_tables_ok,
            "",
            ["Creating database", "KEEP", "created"],
            0,
        ),
        (
            ["-v", "init", "database", "--erase-all-data"],
            init_db_tables_ok,
            "no",
            ["Do you really want to erase the database?"],
            0,
        ),
        (
            ["-v", "init", "database", "--erase-all-data"],
            init_db_tables_ok,
            "yes",
            [
                "Do you really want to erase the database?",
                "Recreating",
                "ERASE",
                "Database created",
            ],
            0,
        ),
        (
            ["-v", "init", "database", "--erase-all-data", "--yes"],
            init_db_tables_ok,
            "",
            ["Recreating", "ERASE", "Database created"],
            0,
        ),
        (
            ["init", "database"],
            init_db_tables_exception,
            "",
            ["Failed to create database: Generic exception"],
            1,
        ),
    ],
)
def test_init_database_cmd(
    app, monkeypatch, capsys, runner, args, idt_fn, input, output, result
):
    # This tests option handling only. Database ops are tested elsewhere.

    monkeypatch.setattr("linotp.model.setup_db", lambda: None)
    # Monkey-patch `init_db_tables` in `c` to get the correct one.
    monkeypatch.setattr(c, "init_db_tables", idt_fn)
    cmd_result = runner.invoke(main, args, input=input)
    assert cmd_result.exit_code == result
    for s in output:
        assert s in cmd_result.output


# These tests should really go to where the model tests live.


@pytest.fixture
def engine(app):
    return create_engine(app.config["DATABASE_URI"])


def test_setup_db_doesnt_create_tables(app, engine, capsys):
    app.echo = Echo(verbosity=1)

    # GIVEN an empty database
    assert "Config" not in inspect(engine).get_table_names()

    # WHEN I call `setup_db` without additional arguments
    setup_db(app)

    # THEN the tables are NOT created (because `init_db_tables` does that).
    assert "Config" not in inspect(engine).get_table_names()


def test_padding_migration(app, base_app, engine):
    """Check that the padding migration has changed

    0. create an empty database
    1. set the security module to the old padding, and
    2. set the db schema version to lower than the padding migration
        version and generate an encrypted value with the old padding
        and store both entries
    3. restore the original padding function
    4. run the db_init, which now re-encryptes the values

    the stored encrypted values must now be different, while the decrypted
    values should be the same

    """

    class MockSecurityModule(DefaultSecurityModule):
        @staticmethod
        def old_padd_data(input_data):
            data = b"\x01\x02"
            padding = (16 - len(input_data + data) % 16) % 16
            return input_data + data + padding * b"\0"

    app.echo = Echo(verbosity=1)

    # we need a base_app context which contains the security provider that is
    # needed for the re-encryption during the 3.1.0.0 migration

    with base_app.app_context():
        # GIVEN a database with records
        app.cli_cmd = "init-database"

        # 0. drop all data and add defaults
        init_db_tables(app, drop_data=True, add_defaults=False)

        # 1. set the security module to the old padding

        sec_provider = base_app.security_provider
        sec_module = sec_provider.security_modules[sec_provider.activeOne]
        sec_module.padd_data = MockSecurityModule.old_padd_data

        # 2.
        # set the db schema version to lower than the padding migration
        # version and generate an encrypted value with the old padding
        # and store both entries

        db_schema_version = "linotp.sql_data_model_version"
        db.session.query(Config).filter_by(Key=db_schema_version).delete()

        item = Config(
            Key=db_schema_version,
            Value="3.0.0.0",
            Type="",
            Description="db schema version",
        )
        db.session.add(item)
        item = Config(
            Key="linotp.Config",
            Value="2021-08-25 11:26:13.101147",
            Type="",
            Description="db config change time stamp",
        )
        db.session.add(item)

        value = "Test123Test123Test123Test123Test123"
        enc_value = sec_module.encryptPassword(value.encode("utf-8"))

        enc_data_key = "linotp.padding_migration_test_password"
        enc_item = Config(
            Key=enc_data_key,
            Value=enc_value,
            Type="encrypted_data",
            Description="migration test password",
        )
        db.session.add(enc_item)

        pw_token = Token(serial="new_pw_token")
        pw_token.LinOtpTokenType = "pw"
        pw_token.LinOtpKeyIV = binascii.hexlify(b":1:")
        pw_token.LinOtpKeyEnc = binascii.hexlify(
            b"$6$XjPTQ1cdb8xFEdnF$m.XoQ//RSPABWGym7o9aPx/.RS1ZySekGBDW7wu"
            b"TZlCDhEM7nf7aOjp03Erk1UFX2OiOhKqaXBMw0a.o4Sbev."
        )
        db.session.add(pw_token)

        hmac_token = Token(serial="new_hmac_token")
        hmac_token.LinOtpTokenType = "hmac"

        crypted_value = sec_module.encryptPin(
            cryptPin=b"01234567890123456789012345678901"
        )
        iv, _, enc_key = crypted_value.partition(":")
        hmac_token.LinOtpKeyIV = iv.encode("utf-8")
        hmac_token.LinOtpKeyEnc = enc_key.encode("utf-8")

        db.session.add(hmac_token)

        db.session.commit()
        db.session.remove()

        # 3. restore the original padding function

        sec_module.padd_data = DefaultSecurityModule.padd_data

        # 4. run the db_init, which now re-encrypts the values

        setup_db(app)
        init_db_tables(app, drop_data=False, add_defaults=False)

        # verify the expected behavior

        new_enc = db.session.query(Config).filter_by(Key=enc_data_key).first()

        assert new_enc.Value != enc_value

        new_value = sec_module.decryptPassword(new_enc.Value).decode("utf-8")

        assert new_value == value


@pytest.mark.parametrize("erase", (False, True))
def test_setup_db_erase_all(app, base_app, engine, capsys, erase):
    app.echo = Echo(verbosity=1)

    # we need a base_app context which contains the security provider that is
    # needed for the re-encryption for the 3.0.2.0 migration

    with base_app.app_context():
        # GIVEN a database with records
        app.cli_cmd = "init-database"

        init_db_tables(app, drop_data=True, add_defaults=True)

        KEY = "linotp.foobar"
        item = Config(Key=KEY, Value="123", Type="int", Description="test item")
        db.session.add(item)
        db.session.commit()
        assert db.session.query(Config).filter_by(Key=KEY).count() == 1
        db.session.remove()

        init_db_tables(app, drop_data=erase, add_defaults=False)

        if erase:
            # Additional record should have disappeared
            assert db.session.query(Config).filter_by(Key=KEY).count() == 0
        else:
            # Additional record should still be there
            assert db.session.query(Config).filter_by(Key=KEY).count() == 1

            item = db.session.query(Config).filter_by(Key=KEY).first()
            db.session.delete(item)
            db.session.commit()


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


@pytest.mark.parametrize(
    "with_instructions,output",
    [
        (False, KEY_DUMP),
        (True, KEY_INSTRUCTIONS + KEY_DUMP),
    ],
)
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


@pytest.mark.parametrize(
    "data,content",
    [
        ("", ZERO_KEY),
        (bytes.hex(SECRET_KEY), SECRET_KEY),
    ],
)
def test_create_secret_key(monkeypatch, tmp_path, data, content):
    monkeypatch.setattr(os, "urandom", lambda n: bytes(n))
    filename = tmp_path / "encKey"
    c.create_secret_key(str(filename), data)
    assert filename.exists()
    assert filename.read_bytes() == content
    permissions = stat.S_IMODE(filename.stat().st_mode)
    assert permissions == c.SECRET_FILE_PERMISSIONS


def create_secret_key_ok(filename, data=""):
    if not data:
        data = SECRET_KEY
    with open(filename, "wb") as f:
        f.write(data)


def create_secret_key_exception(filename, data=""):
    msg = "Generic OS-level exception"
    raise OSError(msg)


# Replaces `test_enckey.test_file_not_exists()`,
# `test_enckey.test_file_exists_no_overwrite()`,
# `test_enckey.test_file_exists_and_overwrite() and then some.


@pytest.mark.parametrize(
    "args,csk_fn,input,output,has_file,makes_file,result",
    [
        (["init", "enc-key"], create_secret_key_ok, "", [], False, True, 0),
        (
            ["init", "enc-key"],
            create_secret_key_ok,
            "no\n",
            [
                "There is already an enc-key",
                "Dire Consequences",
                "Not overwriting",
            ],
            True,
            False,
            0,
        ),
        (
            ["-v", "init", "enc-key"],
            create_secret_key_ok,
            "yes\n",
            [
                "There is already an enc-key",
                "Dire Consequences",
                "Moved existing enc-key to",
                "Wrote enc-key to",
            ],
            True,
            True,
            0,
        ),
        (
            ["-v", "init", "enc-key", "--force"],
            create_secret_key_ok,
            "",
            ["Wrote enc-key to"],
            True,
            True,
            0,
        ),
        (
            ["-v", "init", "enc-key", "--force"],
            create_secret_key_ok,
            "",
            ["Wrote enc-key to"],
            False,
            True,
            0,
        ),
        (
            ["init", "enc-key"],
            create_secret_key_exception,
            "",
            ["Error writing enc-key to", "encKey: Generic OS-level exception"],
            False,
            False,
            1,
        ),
        (
            ["-v", "init", "enc-key", "--dump"],
            create_secret_key_ok,
            "",
            [
                "INSTRUCTIONS",
                "linotp init enc-key --keys '000102030405...5a",
                "\n0001020304050607 b8317597\n",
                "\n                 f13e9b66\n",
            ],
            False,
            True,
            0,
        ),
    ],
)
def test_init_enc_key_cmd(
    app,
    tmp_path,
    monkeypatch,
    runner,
    args,
    csk_fn,
    input,
    output,
    has_file,
    makes_file,
    result,
):
    monkeypatch.setattr(c, "create_secret_key", csk_fn)
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
    elif secret_file_name.exists() and secret_file_name.read_bytes() == SECRET_KEY:
        msg = "secret file was created but shouldn't have been"
        raise AssertionError(msg)
    elif has_file and secret_file_name.exists():
        if secret_file_name.read_bytes() == ZERO_KEY:
            pass  # still the old file, this is OK
        else:
            msg = "shouldn't touch secret file but it was changed"
            raise AssertionError(msg)


def test_init_enc_key_cmd_failed_backup(app, tmp_path, runner):
    secret_file_name = tmp_path / "non-existent" / "encKey"
    app.config["SECRET_FILE"] = str(secret_file_name)
    cmd_result = runner.invoke(main, ["init", "enc-key", "--force"])
    assert cmd_result.exit_code == 1
    assert not secret_file_name.exists()
    assert "Error writing enc-key to" in cmd_result.output
    assert "encKey: [Errno 2] No such file or directory: " in cmd_result.output


# ----------------------------------------------------------------------
# Tests for `linotp init audit-keys`
# ----------------------------------------------------------------------

KEY_START = "-----BEGIN {0} KEY-----"
KEY_END = "-----END {0} KEY-----"


class AuditKeys:
    """Provide audit key files to tests"""

    def __init__(self, tmp_path):
        self.private: Path = tmp_path / "private.pem"
        self.public: Path = tmp_path / "public.pem"


@pytest.fixture
def audit_keys(app, tmp_path: "Path") -> "AuditKeys":
    keys = AuditKeys(tmp_path)
    app.config["AUDIT_PRIVATE_KEY_FILE"] = str(keys.private)
    app.config["AUDIT_PUBLIC_KEY_FILE"] = str(keys.public)
    return keys


def check_key_validity(s: str, type_: str) -> bool:
    lines = s.strip("\n").split("\n")
    assert lines[0] == KEY_START.format(type_)
    assert lines[-1] == KEY_END.format(type_)
    # The following will raise binascii.Error on errors
    assert base64.b64decode("".join(lines[1:-1]).encode("ascii")) != b""


@pytest.mark.parametrize(
    ("args,input,output,has_file,makes_file,check_backup,result"),
    [
        (
            ["-v", "init", "audit-keys"],
            "",
            ["Wrote private audit key to", "Extracted public audit key to"],
            False,
            True,
            False,
            0,
        ),
        (
            ["-v", "init", "audit-keys", "--force"],
            "",
            ["Wrote private audit key to", "Extracted public audit key to"],
            False,
            True,
            False,
            0,
        ),
        (
            ["-v", "init", "audit-keys"],
            "no",
            [
                "There is already a private audit key in",
                "Not overwriting existing private audit key.",
            ],
            True,
            False,
            False,
            0,
        ),
        (
            ["-v", "init", "audit-keys"],
            "yes",
            [
                "There is already a private audit key in",
                "Moved existing private audit key to",
                "Wrote private audit key to",
                "Extracted public audit key to",
            ],
            True,
            False,
            True,
            0,
        ),
        (
            ["-v", "init", "audit-keys", "--force"],
            "",
            [
                "Moved existing private audit key to",
                "Wrote private audit key to",
                "Extracted public audit key to",
            ],
            True,
            False,
            True,
            0,
        ),
    ],
)
def test_init_audit_keys_cmd(
    app,
    audit_keys: AuditKeys,
    runner,
    freezer,
    args,
    input,
    output,
    has_file,
    makes_file,
    check_backup,
    result,
):
    freezer.move_to("2020-08-18 19:25:33")

    PRIVATE_KEY = "EXISTING PRIVATE KEY"
    if has_file:
        audit_keys.private.write_text(PRIVATE_KEY)
    else:
        assert not audit_keys.private.exists()

    cmd_result = runner.invoke(main, args, input=input)
    assert cmd_result.exit_code == result
    for s in output:
        assert s in cmd_result.output
    if makes_file:
        assert audit_keys.private.exists()
        check_key_validity(audit_keys.private.read_text(), "PRIVATE")
        assert audit_keys.public.exists()
        check_key_validity(audit_keys.public.read_text(), "PUBLIC")
    if check_backup:
        backup_file = Path(get_backup_filename(str(audit_keys.private)))
        assert backup_file.exists()
        assert backup_file.read_text() == PRIVATE_KEY


def test_init_audit_keys_cmd_failed_backup(
    app, audit_keys: AuditKeys, runner, monkeypatch
):
    def os_replace_exception(src, dst, **kwargs):
        msg = "Generic OS-level exception"
        raise OSError(msg)

    monkeypatch.setattr(os, "replace", os_replace_exception)

    audit_keys.private.write_bytes(ZERO_KEY)
    cmd_result = runner.invoke(main, ["init", "audit-keys", "--force"])
    assert cmd_result.exit_code == 1
    assert audit_keys.private.exists()
    assert "Error moving private audit key to" in cmd_result.output
    assert ": Generic OS-level exception\n" in cmd_result.output


def test_init_audit_keys_cmd_failed_openssl(
    app, audit_keys: AuditKeys, runner, monkeypatch
):
    class mock_exit:
        """Fake that the command failed"""

        exit_code = 999

    def mock_run_command(task: str, cmd: list[str], **kargs):
        assert cmd[0] == "openssl"
        return mock_exit()

    monkeypatch.setattr(c, "_run_command", mock_run_command)

    cmd_result = runner.invoke(main, ["init", "audit-keys", "--force"])
    assert cmd_result.exit_code == 1


def test_version(app, runner):
    "Test that --version returns the correct version format"

    cmd_result = runner.invoke(main, ["--version"])

    assert cmd_result.output.split() == ["LinOTP", __version__]

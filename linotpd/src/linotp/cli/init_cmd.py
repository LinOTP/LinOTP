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

""" linotp init commands.

linotp init database
linotp init enc-key
linotp init audit-keys

"""

import binascii
from dataclasses import dataclass
import datetime
import hashlib
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List

import click

from datetime import datetime

from flask import current_app

from flask.cli import AppGroup
from flask.cli import with_appcontext

from linotp.model import setup_db


from linotp.cli import get_backup_filename, main as cli_main

KEY_COUNT = 3                    # Number of keys in the `SECRET_FILE`
KEY_LENGTH = 32                  # Number of bytes per key in the `SECRET_FILE`
SECRET_FILE_PERMISSIONS = 0o400


# ----------------------------------------------------------------------
# Subroutines of general interest
# ----------------------------------------------------------------------

def _overwrite_check(what: str, filename: str) -> bool:
    n = "n" if what[0].lower() in "aeio" else ""
    click.echo(f"There is already a{n} {what} in '{filename}'.\n"
               "Overwriting this might have Dire Consequences.\n")
    answer = click.prompt(
        f"Overwrite existing {what}", default="no",
        type=click.Choice(['yes', 'no'], case_sensitive=True),
        show_choices=True)
    if answer != 'yes':
        click.echo(f'Not overwriting existing {what}.')
        return False
    return True


def _make_backup(what: str, filename: str) -> bool:
    backup_filename = get_backup_filename(filename)
    try:
        os.replace(filename, backup_filename)
        current_app.echo(f"Moved existing {what} to {backup_filename}", v=1)
    except OSError as ex:
        current_app.echo(f"Error moving {what} to {backup_filename}: {ex!s}")
        return False
    return True


def _run_command(task: str, cmd: List[str], **kwargs: Dict[str, Any]) -> bool:
    """Execute a shell command given as a list of strings, with
    error checking.
    """

    @dataclass
    class CmdResult:
        exception: bool = True
        exit_code: int = 0
        output: str = ""

    kwargs.update({'stdout': subprocess.PIPE, 'stderr': subprocess.STDOUT})
    try:
        result = subprocess.run(cmd, **kwargs)
    except OSError as ex:
        ret = CmdResult(True, None, str(ex))
    else:
        ret = CmdResult(False, result.returncode,
                        result.stdout.decode("utf-8"))
    if ret.exception or ret.exit_code != 0:
        cmd_str = " ".join(cmd)
        current_app.echo(f"{task} failed:")
        if ret.exception:
            current_app.echo(
                f"Command '{cmd_str}' raised exception")
        elif ret.exit_code < 0:
            current_app.echo(
                f"Command '{cmd_str}' terminated by signal {-ret.exit_code}")
        else:
            current_app.echo(
                f"Command '{cmd_str}' returned exit code {ret.exit_code}")
        current_app.echo(f"Output was:\n{ret.output}")

    return ret

# init commands: database + enc-key

init_cmds = AppGroup('init')


def erase_confirm(ctx, param, value):
    if ctx.params['erase_all_data']:
        # The user asked for data to be erased. We now look for a confirmation
        # or prompt the user
        if not value:
            prompt = click.prompt('Do you really want to erase the database?',
                                  type=click.BOOL)
            if not prompt:
                ctx.abort()


@init_cmds.command('database', help="Create tables in the database")
@click.option('--erase-all-data', is_flag=True, help="Erase ALL existing data")
@click.option('--yes', is_flag=True, callback=erase_confirm,
              expose_value=False,
              help="Erase data without prompting for confirmation")
@with_appcontext
def init_db_command(erase_all_data):
    """
    Create new tables

    The database is initialized and optionally data is cleared.
    """

    if erase_all_data:
        info = 'Recreating database'
    else:
        info = 'Creating database'

    current_app.echo(info, v=1)
    try:
        setup_db(current_app, erase_all_data)
    except Exception as exx:
        current_app.echo(f'Failed to create database: {exx!s}')
        raise click.Abort()
    current_app.echo('database created', v=1)
# ----------------------------------------------------------------------
# Command `linotp init enc-key`
# ----------------------------------------------------------------------

CHUNK_SIZE = 16


def dump_key(filename, instructions=True):
    with open(filename, "rb") as f:
        secret_key = f.read().hex()

    if instructions:
        click.echo(f"{filename} {datetime.datetime.now().isoformat()}\n")
        click.echo("INSTRUCTIONS: Print this and store it in a safe place. "
                   "Remember where you put\nit.\n\n"
                   "To recover the keys, concatenate the FIRST column of each "
                   "line and pass the\nresult to `linotp init enc-key` "
                   "using the `--keys` option (spaces are\n"
                   "allowed to make the key data easier to enter):\n\n"
                   "  linotp init enc-key --keys "
                   f"'{secret_key[:12]}...{secret_key[-12:]}'\n\n"
                   "Compare the output to this list; if the values on the "
                   "final lines agree,\neverything is probably OK. "
                   "Otherwise compare the values in the second columns;\n"
                   "if there is a mismatch, then the data in the first "
                   "column on that line\ncontains one or more typoes. "
                   "Enjoy!\n")

    m = hashlib.sha1()
    for k in range(0, len(secret_key), CHUNK_SIZE):
        chunk = secret_key[k:k+CHUNK_SIZE]
        check = binascii.crc32(chunk.encode('ascii')) & 0xffffffff
        m.update(chunk.encode('ascii'))
        click.echo(f"{chunk} {check:08x}")
    click.echo(f"{' '*CHUNK_SIZE} {m.hexdigest()[:8]}")


@init_cmds.command('enc-key',
                   help='Generate AES keys for encryption and decryption')
@click.option('--force', '-f', is_flag=True,
              help='Overwrite key file if it exists already.')
@click.option('--dump', is_flag=True,
              help='Output paper emergency-backup version of the key file.')
@click.option('--keys', default='',
              help='Decode key from emergency backup data.')
def init_enc_key_cmd(force, dump, keys):
    """Creates a LinOTP secret file to encrypt and decrypt values in database

    The key file is used via the default security provider to encrypt
    token seeds, configuration values...
    If --force or -f is set and the encKey file exists already, it
    will be overwritten.
    """
    filename = current_app.config["SECRET_FILE"]

    if os.path.exists(filename):
        if not force:
            if not _overwrite_check("enc-key", filename):
                sys.exit(0)
        if not _make_backup("enc-key", filename):
            sys.exit(1)

    try:
        create_secret_key(filename, data=keys.replace(' ', ''))
        current_app.echo(f"Wrote enc-key to {filename}", v=1)
    except OSError as ex:
        current_app.echo(f"Error writing enc-key to {filename}: {ex!s}")
        sys.exit(1)

    if dump or keys:
        dump_key(filename, instructions=dump)


def create_secret_key(filename, data=''):
    """Creates a LinOTP secret file to encrypt and decrypt values in database

    The key file is used via the default security provider to encrypt
    token seeds, configuration values...

    The key file contains 3 key of length 256 bit (32 Byte) each.
    """

    with tempfile.NamedTemporaryFile(mode='wb',
                                     dir=os.path.dirname(filename),
                                     delete=False) as f:
        os.fchmod(f.fileno(), SECRET_FILE_PERMISSIONS)
        if not data:
            f.write(os.urandom(KEY_COUNT * KEY_LENGTH))
        else:
            f.write(bytes.fromhex(data))
    os.replace(f.name, filename)     # atomic rename, since Python 3.3


# ----------------------------------------------------------------------
# Command `linotp init audit-keys`
# ----------------------------------------------------------------------

AUDIT_PRIVKEY_BITS = 2048       # Number of bits in a private audit key


@init_cmds.command('audit-keys',
                   help='Generate RSA key pair for audit log signing')
@click.option('--force', '-f', is_flag=True,
              help='Overwrite key pair if it exists already.')
@with_appcontext
def init_audit_keys_cmd(force):
    privkey_filename = current_app.config["AUDIT_PRIVATE_KEY_FILE"]
    pubkey_filename = current_app.config["AUDIT_PUBLIC_KEY_FILE"]

    if os.path.exists(privkey_filename):
        if not force:
            if not _overwrite_check("private audit key", privkey_filename):
                sys.exit(0)
        if not _make_backup("private audit key", privkey_filename):
            sys.exit(1)

    create_audit_keys(privkey_filename, pubkey_filename)


def create_audit_keys(privkey_filename, pubkey_filename):
    ret = _run_command("Creating private audit key",
                       ["openssl", "genrsa", "-out", privkey_filename,
                        str(AUDIT_PRIVKEY_BITS)])
    if ret.exit_code == 0:
        try:
            current_app.echo(f"Wrote private audit key to {privkey_filename}",
                             v=1)
        except RuntimeError:
            pass
    else:
        sys.exit(1)

    # The public key can always be reconstructed from the private key, so
    # we don't worry about a backup of the public key file.

    ret = _run_command("Extracting public audit key",
                       ["openssl", "rsa", "-in", privkey_filename,
                        "-pubout", "-out", pubkey_filename])
    if ret.exit_code == 0:
        try:
            current_app.echo(
                f"Extracted public audit key to {pubkey_filename}", v=1)
        except RuntimeError:
            pass
    else:
        sys.exit(1)

# -*- coding: utf-8 -*-
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

"""Tests for `linotp.lib.fs_utils` module."""

import errno
import os
import stat

import pytest

from linotp.lib.fs_utils import ensure_dir

# ----------------------------------------------------------------------
# Tests for `ensure_dir()` function.
# ----------------------------------------------------------------------


def test_ensure_dir_ok(app, tmp_path):
    parent = os.path.join(app.config["ROOT_DIR"], "foo")
    d = os.path.join(parent, "bar")
    mode = 0o700
    umask = os.umask(0)
    d0 = ensure_dir(app, "test", "ROOT_DIR", "foo", "bar", mode=mode)
    os.umask(umask)
    assert d == d0
    for path, wanted_mode in ((parent, 0o777), (d, mode)):
        p_mode = os.stat(path).st_mode
        assert stat.S_ISDIR(p_mode) != 0
        assert stat.S_IMODE(p_mode) == wanted_mode


def test_ensure_dir_err(app, tmp_path, monkeypatch):
    def fake_makedirs(name, mode=0o777, exist_ok=False):
        raise FileNotFoundError(errno.ENOENT, "BOO", name)

    monkeypatch.setattr(os, "makedirs", fake_makedirs)
    d = os.path.join(app.config["ROOT_DIR"], "foo", "bar")
    with pytest.raises(FileNotFoundError) as ex:
        ensure_dir(app, "test", "ROOT_DIR", "foo", "bar")
    assert "Error creating test directory " in str(ex.value)
    assert f": BOO ({errno.ENOENT})" in str(ex.value)
    assert not os.path.exists(d)


@pytest.mark.parametrize(
    "var",
    [
        ("DATABASE_URI",),  # doesn't end in `_DIR`
        ("FLORP_DIR"),  # doesn't exist
    ],
)
def test_ensure_dir_bad_config(app, var):
    var = "FLORP_DIR"
    with pytest.raises(KeyError) as ex:
        ensure_dir(app, "test", var, "")
    assert f"Invalid LinOTP configuration setting '{var}'" in str(ex.value)


def test_ensure__dir_missing_base_dir(app, caplog):
    os.rmdir(app.config["CACHE_DIR"])
    with pytest.raises(FileNotFoundError) as ex:
        ensure_dir(app, "test", "CACHE_DIR", "foo", mode=0x700)
    assert (
        f"Directory '{app.config['CACHE_DIR']}' (CACHE_DIR) does not exist"
        in str(ex.value)
    )


def test_ensure_dir_bad_base_dir(app):
    os.rmdir(app.config["CACHE_DIR"])
    with open(app.config["CACHE_DIR"], "w") as f:
        f.write("FOO\n")
    with pytest.raises(NotADirectoryError) as ex:
        ensure_dir(app, "test", "CACHE_DIR", "bar", mode=0x700)
    assert "(CACHE_DIR) is not a directory" in str(ex.value)

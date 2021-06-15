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

# pylint: disable=redefined-outer-name

"""
Command line tests
"""
from datetime import datetime

import pytest

from linotp.app import LinOTPApp
from linotp.cli import get_backup_filename


@pytest.fixture
def app():
    """
    A minimal app for testing

    The app is configured with an unitialised database and Testing mode
    """
    app = LinOTPApp()
    config = {
        "TESTING": True,
    }
    app.config.update(config)
    return app


# ----------------------------------------------------------------------
# Tests for `get_backup_filename()`
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "fmt,filename,now",
    [
        ("%Y-%m-%d_%H-%M", "foo.2020-08-18_19-25", None),
        ("%Y-%m-%d_%H-%M", "bar.2000-01-01_00-00", "2000-01-01T00:00:00"),
        ("%d%m%Y", "baz.18082020", None),
        ("%d%m%Y", "quux.01012000", "2000-01-01T00:00:00"),
    ],
)
def test_get_backup_filename(freezer, monkeypatch, app, fmt, filename, now):
    freezer.move_to("2020-08-18 19:25:33")
    monkeypatch.setitem(app.config, "BACKUP_FILE_TIME_FORMAT", fmt)
    fn = filename[: filename.rfind(".")]
    now_dt = datetime.fromisoformat(now) if isinstance(now, str) else None
    bfn = get_backup_filename(fn, now_dt)
    assert bfn == filename

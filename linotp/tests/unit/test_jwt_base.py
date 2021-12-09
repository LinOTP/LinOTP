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

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest  # noqa: F401

from linotp import __version__ as linotp_version

# ----------------------------------------------------------------------
# Tests for cookie settings.
# ----------------------------------------------------------------------


@patch("linotp.lib.user.User.exists", lambda x: True)
@patch("linotp.lib.user.User.checkPass", lambda self, psswd: True)
@patch(
    "linotp.controllers.base.getResolverObject",
    lambda x: MagicMock(checkPass=lambda a, b: True),
)
@patch("linotp.lib.user.User.get_uid_resolver", lambda self: [("aaa", "bbb")])
@pytest.mark.parametrize(
    "secure_cookies",
    [
        False,
        True,
    ],
)
@pytest.mark.parametrize(
    "auth_type",
    [
        {"api": "/admin/login", "cookie_name": "access_token_cookie"},
        {"api": "/userservice/login", "cookie_name": "user_selfservice"},
    ],
)
def test_session_cookie_secure(
    base_app, client, monkeypatch, secure_cookies, auth_type
):
    monkeypatch.setitem(
        base_app.config, "SESSION_COOKIE_SECURE", secure_cookies
    )

    # Note that we are using `client` rather than `adminclient`, because
    # `adminclient` already is logged in.
    client.cookie_jar.clear()
    res = client.post(
        auth_type["api"],
        data={"username": "foooooo", "password": "baaaaar"},
    )
    assert res.status_code == 200
    for cookie in client.cookie_jar:
        if cookie.name == auth_type["cookie_name"]:
            assert cookie.secure is secure_cookies
            break
    else:
        assert False, "no jwt access token cookie found"


def test_jwt_secret(base_app):
    secret_key = 3 * "abcdef0123456789" * 4
    base_app.config["JWT_SECRET_KEY"] = secret_key

    base_app.init_jwt_config()
    assert (
        base_app.config["JWT_SECRET_KEY"] == secret_key
    ), "the jwt secret key should be unchanged after app init"


@pytest.mark.parametrize(
    "salt,iterations",
    [
        ("deadbeef", 10),
        ("deadbeef", 100000),
        (b"\xde\xad\xbe\xef", 10),
        (b"\xde\xad\xbe\xef", 100000),
    ],
)
def test_default_jwt_secret(base_app, key_directory, salt, iterations):
    base_app.config["JWT_SECRET_KEY"] = None
    base_app.config["JWT_SECRET_SALT"] = salt
    base_app.config["JWT_SECRET_ITERATIONS"] = iterations
    base_app.config["SECRET_FILE"] = key_directory / "encKey"

    base_app.init_jwt_config()

    with Path(key_directory / "encKey").open("rb") as key_file:
        secret_key = key_file.read(32)
        jwt_key = hashlib.pbkdf2_hmac(
            "sha256",
            secret_key,
            salt=bytes.fromhex(salt) if isinstance(salt, str) else salt,
            iterations=iterations,
        )
        assert (
            base_app.config["JWT_SECRET_KEY"] == jwt_key
        ), "JWT secret derivation from encKey doesn't work"


def test_random_jwt_secret(base_app, key_directory):
    base_app.config["SECRET_FILE"] = key_directory / "encKey"

    base_app.config["JWT_SECRET_KEY"] = ""
    base_app.config["JWT_SECRET_SALT"] = ""
    base_app.init_jwt_config()
    secret_key_1 = base_app.config["JWT_SECRET_KEY"]

    base_app.config["JWT_SECRET_KEY"] = ""
    base_app.config["JWT_SECRET_SALT"] = ""
    base_app.init_jwt_config()
    secret_key_2 = base_app.config["JWT_SECRET_KEY"]

    # In theory this test can fail if the same (128-bit)
    # random salt is generated twice in a row, but this
    # is very unlikely indeed. If the test does fail it
    # is *way* more probable that there is a problem with
    # how the key derivation works.

    assert secret_key_1 != secret_key_2

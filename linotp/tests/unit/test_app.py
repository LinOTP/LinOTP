import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest  # noqa: F401

from flask import request, url_for

from linotp import __version__ as linotp_version
from linotp.app import LinOTPApp


def test_rootdir(app):
    rootdir = app.getConfigRootDirectory()

    assert os.path.exists(rootdir)


def test_healthcheck(client):
    wanted = {
        "status": lambda v: v == "alive",
        "version": lambda v: v == linotp_version,
        "uptime": lambda v: float(v) > 0,
    }
    res = client.get(url_for("healthcheck"))
    assert res.status_code == 200
    assert len(res.json) == len(
        wanted
    ), "healthcheck result must contain exactly {} items".format(len(wanted))
    for key, test_fn in list(wanted.items()):
        value = res.json.get(key, None)
        assert value is not None, "healthcheck result missing key {}".format(
            key
        )
        assert test_fn(value)


@pytest.mark.parametrize(
    "path,method,status",
    [
        ("testmethod", "get", 200),
        ("testmethod", "post", 200),
        ("testmethod", "put", 405),
        ("testmethod2", "get", 200),
        ("testmethod2", "post", 405),
        ("testmethod2", "put", 405),
        ("testmethod3", "get", 200),
        ("testmethod3", "post", 200),
        ("testmethod3", "put", 405),
    ],
)
@pytest.mark.app_config(
    {
        "CONTROLLERS": "test",
    }
)
def test_dispatch(adminclient, path, method, status):
    bound_method = getattr(adminclient, method)
    res = bound_method("/test/" + path)
    assert res.status_code == status
    if res.status_code == 200:
        assert request.method == method.upper()


@pytest.mark.app_config(
    {
        "CONTROLLERS": "test",
    }
)
def test_dispatch_args(adminclient):
    res = adminclient.get("/test/testmethod_args/foo/bar")
    assert res.status_code == 200
    assert request.method == "GET"
    assert request.view_args["s"] == "foo"
    assert request.view_args["t"] == "bar"


@pytest.mark.parametrize(
    "path,status, id_value",
    [
        ("testmethod_optional_id", 200, None),
        ("testmethod_optional_id/4711", 200, "4711"),
    ],
)
@pytest.mark.app_config(
    {
        "CONTROLLERS": "test",
    }
)
def test_dispatch_optional_id(adminclient, path, status, id_value):
    res = adminclient.get("/test/" + path)
    assert res.status_code == status
    if id_value is not None:
        assert request.view_args == {"id": id_value}
    else:
        assert request.view_args == {}


# ----------------------------------------------------------------------
# Tests for `CACHE_DIR` setting.
# ----------------------------------------------------------------------


@pytest.mark.app_config(
    {
        "BEAKER_CACHE_TYPE": "file",
    }
)
def test_cache_dir(app):
    wanted_cache_dir = os.path.join(app.config["ROOT_DIR"], "cache")
    assert app.config["CACHE_DIR"] == wanted_cache_dir
    assert os.path.isdir(wanted_cache_dir)
    assert os.path.isdir(os.path.join(wanted_cache_dir, "beaker"))


# ----------------------------------------------------------------------
# Tests for cookie settings.
# ----------------------------------------------------------------------


@patch("linotp.lib.user.User.exists", lambda x: True)
@patch("linotp.lib.user.User.checkPass", lambda self, psswd: True)
@patch(
    "linotp.lib.user.User.getUserObject",
    lambda x, realm: MagicMock(exists=lambda: True),
)
@patch("linotp.controllers.base.getUserId", lambda x: [None] * 3)
@patch(
    "linotp.controllers.base.getResolverObject",
    lambda x: MagicMock(checkPass=lambda a, b: True),
)
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
    for c in client.cookie_jar:
        if c.name == auth_type["cookie_name"]:
            assert c.secure is secure_cookies
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


def test_default_jwt_secret(base_app, key_directory):
    base_app.config["JWT_SECRET_KEY"] = None
    base_app.config["SECRET_FILE"] = key_directory / "encKey"

    base_app.init_jwt_config()

    with Path(key_directory / "encKey").open("rb") as key_file:
        secret_key = key_file.read(32).hex()
        assert (
            base_app.config["JWT_SECRET_KEY"] == secret_key
        ), "the jwt secret key should default to encKey if not defined at app init time"

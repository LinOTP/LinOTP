
import os

import pytest                   # noqa: F401

from flask import url_for, request

from linotp import __version__ as linotp_version
from linotp.app import LinOTPApp

def test_rootdir(app):
    rootdir = app.getConfigRootDirectory()

    assert os.path.exists(rootdir)

def test_healthcheck(base_app, client):
    wanted = {
        'status': lambda v: v == 'alive',
        'version': lambda v: v == linotp_version,
        'uptime': lambda v: float(v) > 0,
    }
    res = client.get(url_for('healthcheck'))
    assert res.status_code == 200
    assert len(res.json) == len(wanted), \
        'healthcheck result must contain exactly {} items'.format(len(wanted))
    for key, test_fn in list(wanted.items()):
        value = res.json.get(key, None)
        assert value is not None, \
            'healthcheck result missing key {}'.format(key)
        assert test_fn(value)


@pytest.mark.parametrize('path,method,status', [
    ('testmethod', 'get', 200),
    ('testmethod', 'post', 200),
    ('testmethod', 'put', 405),
    ('testmethod2', 'get', 200),
    ('testmethod2', 'post', 405),
    ('testmethod2', 'put', 405),
    ('testmethod3', 'get', 200),
    ('testmethod3', 'post', 200),
    ('testmethod3', 'put', 405),
])
def test_dispatch(base_app, client, path, method, status):
    bound_method = getattr(client, method)
    res = bound_method('/test/' + path)
    assert res.status_code == status
    if res.status_code == 200:
        assert request.method == method.upper()


def test_dispatch_args(base_app, client):
    res = client.get('/test/testmethod_args/foo/bar')
    assert res.status_code == 200
    assert request.method == 'GET'
    assert request.view_args['s'] == 'foo'
    assert request.view_args['t'] == 'bar'


@pytest.mark.parametrize('path,status, id_value', [
    ('testmethod_optional_id', 200, None),
    ('testmethod_optional_id/4711', 200, '4711'),
])
def test_dispatch_optional_id(base_app, client, path, status, id_value):
    res = client.get('/test/' + path)
    assert res.status_code == status
    if id_value is not None:
        assert request.view_args == {'id': id_value}
    else:
        assert request.view_args == {}


# ----------------------------------------------------------------------
# Tests for `CACHE_DIR` setting.
# ----------------------------------------------------------------------

@pytest.mark.app_config({
    'BEAKER_CACHE_TYPE': 'file',
})
def test_cache_dir(app):
    wanted_cache_dir = os.path.join(app.config['ROOT_DIR'], 'cache')
    assert app.config['CACHE_DIR'] == wanted_cache_dir
    assert os.path.isdir(wanted_cache_dir)
    assert os.path.isdir(os.path.join(wanted_cache_dir, "beaker"))


# ----------------------------------------------------------------------
# Tests for cookie settings.
# ----------------------------------------------------------------------

@pytest.mark.parametrize('sess_cookie_secure', [
    False,
    True,
])
def test_session_cookie_secure(base_app, client, monkeypatch,
                               sess_cookie_secure):
    monkeypatch.setitem(base_app.config, 'SESSION_COOKIE_SECURE',
                        sess_cookie_secure)
    # Note that we're using `client` rather than `adminclient`, because
    # `adminclient` adds a spurious extra session cookie.
    client.cookie_jar.clear()
    res = client.get('/admin/getsession')
    assert res.status_code == 200
    for c in client.cookie_jar:
        if c.name == 'admin_session':
            assert c.secure is sess_cookie_secure
            break
    else:
        assert False, "no admin_session cookie found"

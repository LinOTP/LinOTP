
import pytest                   # noqa: F401

from flask import url_for

from linotp import __version__ as linotp_version


def test_healthcheck(app, client):
    wanted = {
        'status': lambda v: v == 'alive',
        'version': lambda v: v == linotp_version,
        'uptime': lambda v: float(v) > 0,
    }
    res = client.get(url_for('healthcheck'))
    assert res.status_code == 200
    assert len(res.json) == len(wanted), \
        'healthcheck result must contain exactly {} items'.format(len(wanted))
    for key, test_fn in wanted.items():
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
def test_dispatch(app, client, path, method, status):
    bound_method = getattr(client, method)
    res = bound_method('/test/' + path)
    assert res.status_code == status
    if res.status_code == 200:
        assert res.data == 'method:' + method.upper()


def test_dispatch_args(app, client):
    res = client.get('/test/testmethod_args/foo/bar')
    assert res.status_code == 200
    assert res.data == 'method:GET,foo,bar'


@pytest.mark.parametrize('path,status, id_value', [
    ('testmethod_optional_id', 200, 'None'),
    ('testmethod_optional_id/4711', 200, '4711'),
])
def test_dispatch_optional_id(app, client, path, status, id_value):
    res = client.get('/test/' + path)
    assert res.status_code == status
    if res.status_code == 200:
        _, _, id_arg = res.data.rpartition('=')
        assert id_arg == id_value

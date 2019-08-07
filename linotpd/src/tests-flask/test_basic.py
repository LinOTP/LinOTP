
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


import pytest

import flask

from linotp.app import create_app


@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        flask.g.request_context = {
            'config': {},
        }
        yield app

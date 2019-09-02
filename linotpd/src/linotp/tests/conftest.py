import flask
import pytest

from linotp.app import create_app
from linotp.flap import set_config
from linotp.config.environment import load_environment

@pytest.fixture
def base_app():
    """
    App instance without context

    Creates and returns a bare app. If you wish
    an app with an initialised application context,
    use the `app` fixture instead
    """

    # create a temporary file to isolate the database for each test
    # db_fd, db_path = tempfile.mkstemp()
    # create the app with common test config
    app = create_app()

    yield app

    # close and remove the temporary database
    # os.close(db_fd)
    # os.unlink(db_path)

@pytest.fixture
def app(base_app):
    """
    Provide an app and configured application context
    """
    with base_app.app_context():
        set_config()
        load_environment(flask.g, base_app.config)
        yield base_app

# Pylons fixture
# based on pylons.test.PylonsPlugin

import os
import sys

import pkg_resources
import pylons
import pytest
from paste.deploy import loadapp
from pylons.i18n.translation import _get_translator

pylonsapp = None

def pytest_addoption(parser):
    parser.addoption('--with-pylons', default='test.ini', help='Pylons support: configuration file')

@pytest.fixture(scope="session", autouse=True)
def pylons_app(request):
    config_file = request.config.getoption('--with-pylons')

    path = os.getcwd()
    sys.path.insert(0, path)
    pkg_resources.working_set.add_entry(path)
    app = loadapp('config:' + config_file,
                                    relative_to=path)

    # Setup the config and app_globals, only works if we can get
    # to the config object
    conf = getattr(app, 'config')
    if conf:
        pylons.config._push_object(conf)

        if 'pylons.app_globals' in conf:
            pylons.app_globals._push_object(conf['pylons.app_globals'])

    # Initialize a translator for tests that utilize i18n
    translator = _get_translator(pylons.config.get('lang'))
    pylons.translator._push_object(translator)

    # Legacy - set global variable
    global pylonsapp
    pylonsapp = app

    return app

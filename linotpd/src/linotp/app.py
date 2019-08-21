# Flask application initialisation for LinOTP.

# LinOTP3's basic configuration comes from the following sources (in
# that order):
#
#   - Hard-coded defaults in one of the configuration classes in
#     `linotp3.settings`, selected by the content of the `LINOTP3_CONFIG`
#     environment variable (if it exists) or else the content of the
#     `FLASK_ENV` environment variable (if it exists; the only official
#     values are `development` and `production`) or else `default`.
#
#   - Settings in the file whose name is given by the content of the
#     `LINOTP3_CONFIG_FILE` environment variable (if it exists) or else
#     the `linotp.cfg` file in the top-level directory of the
#     distribution.
#
# Note that this is only the Flask end of things; these configuration
# settings are not to be confused with the actual configuration for
# what LinOTP is doing, which is kept in the SQL database.

from __future__ import print_function

import importlib
from logging.config import dictConfig as logging_dictConfig
import os
import time

from flask import Flask, jsonify

from . import __version__
from .settings import configs

start_time = time.time()
this_dir = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE_ENVVAR = "LINOTP_CONFIG_FILE"  # DRY
CONFIG_FILE_NAME = os.path.join(os.path.dirname(this_dir), "linotp.cfg")
if os.getenv(CONFIG_FILE_ENVVAR) is None:
    os.environ[CONFIG_FILE_ENVVAR] = CONFIG_FILE_NAME


class ConfigurationError(Exception):
    pass


def init_logging(app):
    """Sets up logging for LinOTP."""

    if app.config["LOGGING"] is None:
        app.config["LOGGING"] = {
            'version': 1,
            'disable_existing_loggers': False,
            'handlers': {
                'console': {
                    'level': 'DEBUG',
                    'class': 'logging.StreamHandler',
                    'formatter': 'linotp',
                },
                'file': {
                    'level': 'INFO',
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': os.path.join(
                        app.config["LOGFILE_DIR"], app.config["LOGFILE_NAME"]),
                    'maxBytes': app.config["LOGFILE_MAX_LENGTH"],
                    'backupCount': app.config["LOGFILE_MAX_VERSIONS"],
                },
            },
            'formatters': {
                'linotp': {
                    'format': app.config["LOGFILE_FILE_LINE_FORMAT"],
                },
            },
            'loggers': {
                'linotp.app': {
                    'handlers': ['file', 'console'],
                    'level': app.config["LOGGING_LEVEL"],
                    'propagate': False,
                },
            },
        }

    logfile_dir = app.config["LOGFILE_DIR"]
    if logfile_dir is not None and not os.path.exists(logfile_dir):
        os.mkdir(logfile_dir)

    logging_dictConfig(app.config["LOGGING"])

    app.logger.info("LinOTP {} starting ...".format(__version__))


def create_app(config_name='default'):
    app = Flask(__name__)

    app.config.from_object(configs[config_name])
    configs[config_name].init_app(app)

    app.config.from_envvar(CONFIG_FILE_ENVVAR, silent=True)

    init_logging(app)

    app.add_url_rule('/healthcheck/status', 'healthcheck', healthcheck)

    # `CONTROLLERS` is a string that contains a space-separated list
    # of controllers that should be made available. If an entry in
    # this list is `foo`, this means that the Python module
    # `linotp.controllers.foo` should be loaded and its
    # `FooController` class be made available as a Flask blueprint at
    # the `/foo` URL prefix. Our dispatch mechanism then ensures that
    # a request to `/foo/bar` will be dispatched to the
    # `FooController.bar()` view method.
    #
    # In general, controllers may be specified as
    # `module:url_prefix:class_prefix` (where `url_prefix` and
    # `class_prefix` are optional and will be constructed from
    # `module` as above if needed).

    for ctrl_name in app.config["CONTROLLERS"].split():
        bits = ctrl_name.split(':', 2)
        while len(bits) < 3:
            bits.append('')
        if not bits[0]:
            raise ConfigurationError(
                "no controller module specified: {}".format(ctrl_name))
        if not bits[1]:
            bits[1] = '/' + bits[0]    # "foobar" => "/foobar"
        if not bits[2]:
            # "foobar" => "FoobarController"
            bits[2] = bits[0].title() + 'Controller'
        ctrl_name, url_prefix, ctrl_class_name = bits
        mod = importlib.import_module('.' + ctrl_name, "linotp.controllers")
        cls = getattr(mod, ctrl_class_name, None)
        if cls is None:
            raise ConfigurationError(
                "{} does not define the '{}' class".format(ctrl_name,
                                                           ctrl_class_name))
        app.logger.debug(
            "Registering {0} class at {1}".format(ctrl_class_name, url_prefix))
        app.register_blueprint(cls(ctrl_name), url_prefix=url_prefix)

    return app


def healthcheck():
    uptime = time.time() - start_time
    return jsonify(status="alive", version=__version__, uptime=uptime)

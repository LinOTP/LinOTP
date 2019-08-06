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

from logging.config import dictConfig as logging_dictConfig
import os

from flask import Flask

from . import __version__
from .settings import configs

this_dir = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE_ENVVAR = "LINOTP_CONFIG_FILE"  # DRY
CONFIG_FILE_NAME = os.path.join(os.path.dirname(this_dir), "linotp.cfg")
if os.getenv(CONFIG_FILE_ENVVAR) is None:
    os.environ[CONFIG_FILE_ENVVAR] = CONFIG_FILE_NAME


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
                'flask.app': {
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

    print("app.config = {}".format(app.config))

    init_logging(app)

    return app

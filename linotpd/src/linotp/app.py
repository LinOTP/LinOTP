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

from flask import Flask, g as flask_g, jsonify
from flask_mako import MakoTemplates

from . import __version__
from . import flap
from .config.defaults import set_defaults
from .config.environment import load_environment
from .settings import configs
from .lib.ImportOTP.vasco import init_vasco

from sqlalchemy import create_engine
from .model import init_model, meta         # FIXME: Flask-SQLAlchemy
from .model.migrate import run_data_model_migration

start_time = time.time()
this_dir = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE_ENVVAR = "LINOTP_CONFIG_FILE"  # DRY
CONFIG_FILE_NAME = os.path.join(os.path.dirname(this_dir), "linotp.cfg")
if os.getenv(CONFIG_FILE_ENVVAR) is None:
    os.environ[CONFIG_FILE_ENVVAR] = CONFIG_FILE_NAME

mako = MakoTemplates()


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


def setup_db(app):
    """Set up the database for LinOTP. This used to be part of the
    `lib.base.setup_app()` function.

    FIXME: This is not how we would do this in Flask. We want to
    rewrite it once we get Flask-SQLAlchemy and Flask-Migrate
    working properly."""

    # Initialise the SQLAlchemy engine (this used to be in
    # linotp.config.environment and done once per request (barf)).

    engine = create_engine(app.config.get("SQLALCHEMY_DATABASE_URI"))
    init_model(engine)

    if app.config.get("TESTING_DROP_TABLES", False):
        app.logger.debug("Deleting previous tables ...")
        meta.metadata.drop_all(bind=meta.engine)

    # Create database tables if they don't already exist

    app.logger.info("Creating tables ...")
    meta.metadata.create_all(bind=meta.engine)

    # For the cloud mode, we require the `admin_user` table to
    # manage the admin users to allow password setting

    admin_username = app.config.get('ADMIN_USERNAME', None)
    admin_password = app.config.get('ADMIN_PASSWORD', None)

    if admin_username is not None and admin_password is not None:
        from .lib.tools.set_password import (
            SetPasswordHandler, DataBaseContext
        )
        db_context = DataBaseContext(sql_url=meta.engine.url)
        SetPasswordHandler.create_table(db_context)
        SetPasswordHandler.create_admin_user(
            db_context,
            username=admin_username, crypted_password=admin_password)

    # Hook for schema upgrade (Don't bother with this for the time being).

    # run_data_model_migration(meta)


def generate_secret_key_file(app):
    """Generate a secret-key file if it doesn't exist."""

    filename = app.config.get("SECRET_FILE", None)
    if filename is not None:
        try:
            open(filename)
        except IOError:
            app.logger.warning(
                "The Linotp Secret File could not be found. "
                "Creating a new one at {}".format(filename))
            with open(filename, "ab+") as f:
                # We're protecting the file before we're writing the
                # secret key material to it in order to avoid a
                # possible race condition.

                os.fchmod(f.fileno(), 0o400)
                secret = os.urandom(32 * 5)
                f.write(secret)
        app.logger.debug("SECRET_FILE: {}".format(filename))


def create_app(config_name='default', config_extra=None):
    """
    Generate a new instance of the Flask app

    This generates and configures the main application instance. Testing
    environments can use `config_extra` to provide extra configuration values
    such as a temporary database URL.

    @param config_name The name of the configuration to load from settings.py
    @param config_extra An optional dict of configuration override values
    """
    app = Flask(__name__)

    app.config.from_object(configs[config_name])
    configs[config_name].init_app(app)

    app.config.from_envvar(CONFIG_FILE_ENVVAR, silent=True)

    if config_extra is not None:
        app.config.update(config_extra)

    mako.init_app(app)
    init_logging(app)

    with app.app_context():
        setup_db(app)
        generate_secret_key_file(app)

    @app.before_request
    def setup_env():
        flap.set_config()
        set_defaults(app)
        load_environment(flask_g, app.config)
        init_vasco()

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

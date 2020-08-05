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

import importlib
import logging
from logging.config import dictConfig as logging_dictConfig
import re
import sys
import os
import time
from typing import List

import click
from datetime import datetime
from uuid import uuid4

from flask import (Flask, Config as FlaskConfig, current_app, g as flask_g,
                   jsonify, Blueprint, redirect)
from flask.cli import with_appcontext
from flask_babel import Babel, gettext
import flask_mako

from beaker.cache import CacheManager
from beaker.util import parse_cache_config_options

from .lib.config import getLinotpConfig
from .lib.config.db_api import _retrieveAllConfigDB
from .lib.config.global_api import getGlobalObject

from .lib.context import request_context

from .lib.crypto.utils import init_key_partition

from .lib.error import LinotpError

from .lib.logs import init_logging_config
from .lib.logs import log_request_timedelta

from .lib.policy.util import parse_policies

from .lib.resolver import initResolvers
from .lib.resolver import setupResolvers
from .lib.resolver import closeResolvers
from .lib.resolver import getResolverList

from .lib.user import getUserFromRequest

from .lib.realm import getDefaultRealm
from .lib.realm import getRealms
from .lib.reply import sendError

from .lib.type_utils import boolean

from .lib.util import get_client

from . import __version__
from .flap import config, set_config, tmpl_context as c, request
from .defaults import set_defaults
from .settings import configs, LinOTPConfigKeyError
from .tokens import reload_classes as reload_token_classes
from .lib.audit.base import getAudit
from .lib.config.global_api import initGlobalObject

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from .model import init_model, meta         # FIXME: With Flask-SQLAlchemy
from .model.migrate import run_data_model_migration

log = logging.getLogger(__name__)

start_time = time.time()
this_dir = os.path.dirname(os.path.abspath(__file__))

LINOTP_CFG_DEFAULT = "linotp.cfg"  # within app.root_path

# Monkey-patch the value of `_BABEL_IMPORTS`, which in the original
# Flask-Mako package refers to the old-style Flask extension import
# mechanism that no longer works, and would make LinOTP crash. The
# Flask-Mako guys may eventually get their act together and fix this
# (it's not as if this is a new thing), at which point this line won't
# hurt and we can get rid of it again.

flask_mako._BABEL_IMPORTS = flask_mako._BABEL_IMPORTS.replace(
    "flask.ext.babel", "flask_babel")

mako = flask_mako.MakoTemplates()


class ConfigurationError(Exception):
    pass


class ExtFlaskConfig(FlaskConfig):
    """This is a variation on Flask's `Config` class which handles
    directory and file names specially. If the name of a configuration
    setting ends with `_DIR` (except `ROOT_DIR`) or `_FILE`, then if
    its value is not an absolute name (i.e., doesn't begin with a slash),
    the value of `ROOT_DIR` is prepended to it whenever the configuration
    setting is looked at. This means that relative directory and file names
    in the configuration are relative to `ROOT_DIR`.
    """

    config_schema = None

    class RelativePathName(str):
        """“Marker” that a string is really a relative path name.
        """
        pass

    def __init__(self, *args, **kwargs):
        """Initialise the LinOTP config mechanism. The `config_schema`
        parameter, which isn't part of Flask's `Config` mechanism, lets us
        associate a `ConfigSchema` object with this app (see `settings.py`);
        this can later be used to convert and verify configuration items
        as they are assigned.
        """
        self.set_schema(kwargs.pop('config_schema', None))
        super().__init__(*args, **kwargs)

    def set_schema(self, config_schema):
        """Use `config_schema` as the configuration schema for this app.
        The configuration schema specifies data types, conversion functions,
        validation functions, and default values for configuration items; see
        `settings.py` for details.
        """
        self.config_schema = config_schema

    def from_env_variables(self):
        """Take configuration settings from environment variables. E.g.,
        an environment variable called `LINOTP_XYZ` can be used to set the
        `XYZ` configuration item, where its value will be appropriately
        converted from a string to whatever type `XYZ` uses (courtesy of
        `ConfigSchema.check_item()` by way of `self.__setitem__()`). This
        works only for configuration items that are listed in the
        configuration schema (which can be construed as a security feature).

        This is particularly useful when using LinOTP in a Docker-like
        environment.
        """
        if self.config_schema is not None:
            for key, value in os.environ.items():
                if key.startswith('LINOTP_') and key != 'LINOTP_CFG':
                    config_key = key[7:]
                    item = self.config_schema.find_item(config_key)
                    if item is not None:
                        self[config_key] = os.environ[key]

    def __setitem__(self, key, value):
        """Implementation of `self[key] = value` with some additional magic.
        If a configuration schema is defined and `key` occurs in the schema,
        then use the schema to convert the `value` if necessary, and to
        check its validity if appropriate. We also take special care of
        relative path names to make sure they get the value of `ROOT_DIR`
        prepended to them when they are retrieved.
        """
        if self.config_schema is not None:
            value = self.config_schema.check_item(key, value)
        if (key.endswith(('_DIR', '_FILE')) and key != 'ROOT_DIR'
                and value and value[0] != '/'):
            value = ExtFlaskConfig.RelativePathName(value)
        super().__setitem__(key, value)

    def __getitem__(self, key):
        """Returns the value of a configuration item. As a special case,
        configuration items that represent relative path names for files or
        directories have the value of `ROOT_DIR` prepended. We insert a `.`
        between the value of `ROOT_DIR` and the actual value to help with
        debugging. If `ROOT_DIR` is undefined, we use `/ROOT_DIR_UNSET` as
        a default value, which should at least make somewhat clear what is
        going on; it would be nicer to raise an exception but that doesn't
        seem to show up.
        """
        value = super().__getitem__(key)
        root_dir = (super().__getitem__('ROOT_DIR')  # can't say 'self[…]' here
                    if 'ROOT_DIR' in self else '/ROOT_DIR_UNSET')
        if isinstance(value, ExtFlaskConfig.RelativePathName):
            return os.path.join(root_dir, '.', value)
        if key == 'BABEL_TRANSLATION_DIRECTORIES':
            # This is a Flask-Babel setting that we can't really change,
            # so it needs to be special-cased – it is a semicolon-separated
            # search path of directory names, any of which could be relative.

            return ";".join(
                [os.path.join(root_dir, '.', fn) if fn[0] != '/' else fn
                 for fn in value.split(';')])
        return value

    def get(self, key, default=None):
        """We need to overload this so the relative-pathname hack will work
        even if people use `foo.get('bar')` instead of
        `foo['bar']`. (It turns out that the built-in `get()` method
        doesn't go through `__getitem__()` – `__getitem__()`'s mission
        in life is strictly to make the brackets do something.)
        """
        try:
            return self[key]
        except KeyError:
            log.warning("Relying on `.get()` to set a default for "
                        f"'{key}' violates the DRY principle. "
                        "Instead, ensure that the schema contains a suitable "
                        f"default (like {default!r}).")
            # raise LinOTPConfigKeyError(key)  # too drastic for now
            return default


class LinOTPApp(Flask):
    """
    The main LinOTP Flask application instance
    """

    cache = None
    """Beaker cache for this app"""

    enabled_controllers: List[str] = []
    """Currently activated controller names"""

    def __init__(self):
        self.config_class = ExtFlaskConfig  # our special `Config` class
        self.audit_obj = None               # No audit logging so far
        super().__init__(__name__,
                         static_folder='public', static_url_path='/static')

    def _run_setup(self):
        """
        Set up the app and database context for a request. Some of this is
        intended to be done only once and could be refactored into a
        before_first_request function
        """

        try:
            hsm = self.security_provider.getSecurityModule()
            self.hsm = hsm
            c.hsm = hsm
        except Exception as exx:
            log.exception('failed to assign hsm device: %r' % exx)
            raise exx

        l_config = getLinotpConfig()  # SQL-based configuration

        resolver_setup_done = config.get('resolver_setup_done', False)
        if resolver_setup_done is False:
            try:
                cache_dir = self.config["CACHE_DIR"]
                setupResolvers(config=l_config, cache_dir=cache_dir)
                config['resolver_setup_done'] = True
            except Exception as exx:
                config['resolver_setup_done'] = False
                log.error("Failed to setup resolver: %r", exx)
                raise exx

        # TODO: verify merge dropped
        # initResolvers()

    @property
    def security_provider(self):
        """
        Return the security provider, which is an instance of SecurityProvider
        """
        return flask_g.app_globals.security_provider

    def check_license(self):
        """
        if we are in the setup cycle, we check for the linotpLicenseFile
        """
        if "linotpLicenseFile" in config and 'license' not in config:
            license_str = ''
            filename = config.get("linotpLicenseFile", '')
            try:
                with open(filename) as f:
                    license_str = f.read()
            except IOError:
                log.error("could not open licence file: %s", filename)

            if not license_str:
                log.error("empty license file: %s", filename)
            else:
                request_context['translate'] = gettext

                import linotp.lib.support
                res, msg = linotp.lib.support.setSupportLicense(
                    license_str)
                if res is False:
                    log.error("failed to load license: %s: %s",
                                license_str, msg)

                else:
                    log.info("license successfully loaded")

    def load_providers(self):
        config_file = self.config.get('provider.config_file')
        if config_file:
            from linotp.provider import load_provider_ini
            load_provider_ini(config_file)

    def start_session(self):

        # we add a unique request id to the request enviroment
        # so we can trace individual requests in the logging

        request.environ['REQUEST_ID'] = str(uuid4())
        request.environ['REQUEST_START_TIMESTAMP'] = datetime.now()

        self.create_context(request, request.environ)

        try:
            user_desc = getUserFromRequest(request)
            self.base_auth_user = user_desc.get('login', '')
        except UnicodeDecodeError as exx:
            # we supress Exception here as it will be handled in the
            # controller which will return corresponding response
            self.base_auth_user = ''
            log.warning('Failed to identify user due to %r' % exx)

    def finalise_request(self, exc):
        meta.Session.remove()
        # free the lock on the scurityPovider if any
        # Make sure this doesn't crash in the absence of a `request_context`,
        # which can happen in certain tests.
        if hasattr(flask_g, 'request_context') and c.get('sep', False):
            c.sep.dropSecurityModule()
        closeResolvers()

        # hint for the garbage collector to make the dishes
        data_objects = ["resolvers_loaded",
                        "resolver_clazzes", "linotpConfig", "audit", "hsm"]
        for data_obj in data_objects:
            if hasattr(c, data_obj):
                data = getattr(c, data_obj)
                del data

        log_request_timedelta(log)

    def create_context(self, request, environment):
        """
        create the request context for all controllers
        """

        linotp_config = getLinotpConfig()  # SQL-based configuration

        # make the request id available in the request context
        request_context['RequestId'] = environment['REQUEST_ID']

        # a request local cache to get the user info from the resolver
        request_context['UserLookup'] = {}

        # a request local cache to get the resolver from user and realm
        request_context['UserRealmLookup'] = {}

        request_context['Config'] = linotp_config
        request_context['Policies'] = parse_policies(linotp_config)
        request_context['translate'] = gettext

        request_context['CacheManager'] = self.cache

        request_context['Path'] = request.path

        # ------------------------------------------------------------------------

        # setup the knowlege where we are

        request_context['action'] = None
        request_context['controller'] = None

        path = request.path.strip().strip('/').split('/')

        if path[0]:
            request_context['controller'] = path[0]

        request_context['action'] = 'index' if len(path) == 1 else path[-1]

        # ------------------------------------------------------------------------

        initResolvers()

        client = None
        try:
            client = get_client(request=request)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r" % exx)

        request_context['Client'] = client

        flask_g.audit = self.audit_obj.initialize(request, client=client)

        authUser = None
        try:
            authUser = getUserFromRequest(request)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r" % exx)

        request_context['AuthUser'] = authUser
        request_context['UserLookup'] = {}

        # ------------------------------------------------------------------ --
        # get the current resolvers

        resolvers = []
        try:
            resolvers = getResolverList(config=linotp_config)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r" % exx)

        request_context['Resolvers'] = resolvers

        # ------------------------------------------------------------------ --
        # get the current realms

        realms = {}
        try:
            realms = getRealms()
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r" % exx)

        request_context['Realms'] = realms

        # ------------------------------------------------------------------ --

        defaultRealm = ""
        try:
            defaultRealm = getDefaultRealm(linotp_config)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r" % exx)

        request_context['defaultRealm'] = defaultRealm

        # ------------------------------------------------------------------ --
        # load the providers

        from linotp.provider import Provider_types
        from linotp.provider import getProvider

        provider = {}
        for provider_type in list(Provider_types.keys()):
            provider[provider_type] = getProvider(provider_type)

        request_context['Provider'] = provider

        # ------------------------------------------------------------------ --

        # setup the SecretKey for the elliptic curve if it is not already done
        # elliptic curve are working with one partition (0) which is one
        # public / private key pair

        partition = 0
        if 'SecretKey.Partition.%d' % partition not in linotp_config:
            init_key_partition(linotp_config, partition=partition)

    def getRadiusDictionaryPath(self):
        """
        get the radius dictionary path

        The dictionary file is in the same directory as this file

        :return: path to dictionary file
        """

        dict_file = os.path.join(this_dir, 'dictionary')

        if not os.path.isfile(dict_file):
            log.error("Radius settings setup failed - missing dictionary file: %s", dict_file)

        return dict_file

    def getConfigRootDirectory(self):
        """
        Get root directory for local configuration files. This directory
        is used for storing files such as the DB secret key.

        An exception is thrown if the directory does not exist.
        """
        rootdir = config.get('ROOT_DIR')

        if not rootdir:
            raise ConfigurationError("Root directory (ROOT_DIR) is not set")

        if not os.path.exists(rootdir):
            raise ConfigurationError("Root directory {} does not exist")

        return rootdir

    def getCacheManager(self):
        """
        Get cache manager instance for caching classes

        A warning is logged if the cache manager is not available in the config
        """
        cache_manager = request_context['CacheManager']
        if not cache_manager:
            import traceback
            log.warning("[%s] Could not initialise cache due to missing manager", traceback.format_stack(None, 1))

        return cache_manager

    def getRequestParams(self):
        """
        Parses the request params from the request objects body / params
        dependent on request content_type.
        """
        try:
            if request.is_json:
                request_params = request.json
            else:
                request_params = {}
                for key in request.values:
                    if(key.endswith('[]')):
                        request_params[key[:-2]] = request.values.getlist(key)
                    else:
                        request_params[key] = request.values.get(key)
        except UnicodeDecodeError as exx:
            # we supress Exception here as it will be handled in the
            # controller which will return corresponding response
            log.warning('Failed to access request parameters: %r' % exx)

        return request_params

    def setup_controllers(self):
        """
        Initialise controllers and their routing

        `CONTROLLERS` is a string that contains a space-separated list
        of controllers that should be made available. If an entry in
        this list is `foo`, this means that the Python module
        `linotp.controllers.foo` should be loaded and its
        `FooController` class be made available as a Flask blueprint at
        the `/foo` URL prefix. Our dispatch mechanism then ensures that
        a request to `/foo/bar` will be dispatched to the
        `FooController.bar()` view method.

        In general, controllers may be specified as
        `module:url_prefix:class_prefix` (where `url_prefix` and
        `class_prefix` are optional and will be constructed from
        `module` as above if needed).

        This function should be called during application setup
        """
        for ctrl_name in self.config["CONTROLLERS"].split():
            bits = ctrl_name.split(':', 2)
            while len(bits) < 3:
                bits.append('')
            ctrl_name, url_prefix, ctrl_class_name = bits
            self.enable_controller(ctrl_name, url_prefix, ctrl_class_name)

    def enable_controller(self, ctrl_name, url_prefix=None, ctrl_class_name=None):
        """
        Initialise an individual controller and its routing

        :param ctrl_name: The name of the controller
        :param url_prefix: Alternative url prefix. Defaults to /`ctrl_name`
        :param ctrl_class_name: Name of controller class to load. Defaults to CtrlNameController
        """
        if not ctrl_name:
            raise ConfigurationError(
                "no controller module specified: {}".format(ctrl_name))
        if not url_prefix:
            url_prefix = '/' + ctrl_name    # "foobar" => "/foobar"
        if not ctrl_class_name:
            # "foobar" => "FoobarController"
            ctrl_class_name = ctrl_name.title() + 'Controller'

        mod = importlib.import_module('.' + ctrl_name, "linotp.controllers")
        cls = getattr(mod, ctrl_class_name, None)
        if cls is None:
            raise ConfigurationError(
                "{} does not define the '{}' class".format(ctrl_name,
                                                           ctrl_class_name))
        self.logger.debug(
            "Registering {0} class at {1}".format(ctrl_class_name, url_prefix))
        self.register_blueprint(cls(ctrl_name), url_prefix=url_prefix)

        self.enabled_controllers.append(ctrl_name)


def init_logging(app):
    """Sets up logging for LinOTP."""

    if app.config["LOGGING"] is None:
        app.config["LOGGING"] = {
            'version': 1,
            'disable_existing_loggers': False,
            'handlers': {
                'console': {
                    'level': app.config["LOGGING_CONSOLE_LEVEL"],
                    'class': 'logging.StreamHandler',
                    'formatter': 'linotp',
                },
                'file': {
                    'level': app.config["LOGGING_FILE_LEVEL"],
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
                'linotp': {
                    'handlers': ['console', 'file'],
                    'level': app.config["LOGGING_LEVEL"],
                    'propagate': True,
                },
                'sqlalchemy.engine': {
                    'handlers': ['console', 'file'],
                    'level': app.config["SQLALCHEMY_LOGGING_LEVEL"],
                    'propagate': True,
                },
            },
        }

    logfile_dir = app.config["LOGFILE_DIR"]
    if logfile_dir is not None and not os.path.exists(logfile_dir):
        os.mkdir(logfile_dir)

    logging_dictConfig(app.config["LOGGING"])

    app.logger.info("LinOTP {} starting ...".format(__version__))


def setup_cache(app):
    """Initialise the Beaker cache for this app."""

    cache_opts = {}
    cache_opts['cache_type'] = app.config["BEAKER_CACHE_TYPE"]
    if cache_opts['cache_type'] == 'file':
        beaker_dir = app.config["BEAKER_CACHE_DIR"]
        cache_opts['cache.data_dir'] = os.path.join(beaker_dir, 'data')
        cache_opts['cache.lock_dir'] = os.path.join(beaker_dir, 'lock')
    app.cache = CacheManager(**parse_cache_config_options(cache_opts))


def setup_db(app, drop_data=False):
    """Set up the database for LinOTP.

    This method is used during create_app() phase and as a separate
    flask command `init-db` in init_db_command() to initialize and setup
    the linotp database.

    FIXME: This is not how we would do this in Flask. We want to
    rewrite it once we get Flask-SQLAlchemy and Flask-Migrate
    working properly.

    :param drop_data: If True, all data will be cleared. Use with caution!
    """

    # Initialise the SQLAlchemy engine

    sql_uri = app.config.get("SQLALCHEMY_DATABASE_URI")

    # sqlite in-memory databases require special sqlalchemy setup:
    # https://docs.sqlalchemy.org/en/13/dialects/sqlite.html#using-a-memory-database-in-multiple-threads

    if sql_uri == "sqlite://":
        engine = create_engine(sql_uri,
                               connect_args={'check_same_thread': False},
                               poolclass=StaticPool)
    else:
        engine = create_engine(sql_uri)

    # Initialise database table model

    init_model(engine)

    # (Re)create and setup database tables if they don't already exist

    app.logger.info("Setting up database...")

    try:
        if drop_data:
            app.logger.info("Dropping tables to erase all data...")
            meta.metadata.drop_all(bind=meta.engine)

        meta.metadata.create_all(bind=meta.engine)

        run_data_model_migration(meta)
        set_defaults(app)

        # For the cloud mode, we require the `admin_user` table to
        # manage the admin users to allow password setting

        admin_username = app.config.get('ADMIN_USERNAME')
        admin_password = app.config.get('ADMIN_PASSWORD')

        if admin_username is not None and admin_password is not None:
            app.logger.info("Setting up cloud admin user...")
            from .lib.tools.set_password import (
                SetPasswordHandler, DataBaseContext
            )
            db_context = DataBaseContext(sql_url=meta.engine.url)
            SetPasswordHandler.create_table(db_context)
            SetPasswordHandler.create_admin_user(
                db_context,
                username=admin_username, crypted_password=admin_password)

    except Exception as exx:
        app.logger.exception(
            "Exception occured during database setup: %r", exx)
        meta.Session.rollback()
        raise exx

    meta.Session.commit()


def generate_secret_key_file(app):
    """Generate a secret-key file if it doesn't exist."""

    filename = app.config["SECRET_FILE"]
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


def setup_security_provider(app):
    """
    Set up the security provider (HSM or software). This is straight from
    `load_environment()` and should be rewritten to use Flask-style config
    settings, but this is a huge bowl of spaghetti.
    """
    try:
        flask_g.app_globals.security_provider.load_config(app.config)
    except Exception as e:
        app.logger.error("Failed to load security provider definition: {}"
                         .format(e))
        raise e


def setup_audit(app):
    """
    Set up audit logging for a request. This is, again, straight from
    `load_environment()` and as such should be looked at with a microscope,
    probably when we're fixing auditing.
    """
    app.audit_obj = getAudit(app.config)


def _configure_app(app, config_name='default', config_extra=None):
    """
    Testing the configuration mechanism is a lot easier if it can be
    invoked separately from `create_app()`, which does a lot of other
    stuff, too. Therefore we have pulled out all the configuration-related
    code from `create_app()` into this function.
    """
    app.config.from_object(configs[config_name])
    configs[config_name].init_app(app)

    # Read the configuration files

    linotp_cfg_files = os.environ.get("LINOTP_CFG", LINOTP_CFG_DEFAULT)
    if linotp_cfg_files:
        for fn in linotp_cfg_files.split(':'):
            fn = os.path.join(app.config.root_path, fn)  # better message
            if app.config.from_pyfile(fn, silent=True):
                print(f"Configuration loaded from {fn}", file=sys.stderr)
            else:
                print(f"Configuration from {fn} failed"
                      " (check location and permissions)",
                      file=sys.stderr)

    if config_extra is not None:
        app.config.update(config_extra)

    # Check the environment for further settings

    app.config.from_env_variables()


def create_app(config_name='default', config_extra=None):
    """
    Generate a new instance of the Flask app

    This generates and configures the main application instance. Testing
    environments can use `config_extra` to provide extra configuration values
    such as a temporary database URL.

    @param config_name The name of the configuration to load from settings.py
    @param config_extra An optional dict of configuration override values
    """
    app = LinOTPApp()

    _configure_app(app, config_name, config_extra)

    # Enable custom template directory for Mako. We can get away with this
    # because Mako's `TemplateLookup` object is only created when the first
    # template is rendered. Note that “`app.template_folder` as a tuple” is
    # a Flask-Mako thing and won't work with Jinja2; if we ever decide we
    # want to move over, we will need to come up with something else.

    if app.config["CUSTOM_TEMPLATES_DIR"] is not None:
        app.template_folder = (app.config["CUSTOM_TEMPLATES_DIR"],
                               app.template_folder)

    babel = Babel(app, configure_jinja=False, default_domain="linotp")

    # Determine which languages are available in the i18n directory.
    # Note that we always have English even without a translation file.

    app.available_languages = list(
        {'en'} | {t.language for t in babel.list_translations()}
    )

    mako.init_app(app)
    init_logging(app)

    with app.app_context():
        setup_cache(app)
        setup_db(app)
        set_config()       # ensure `request_context` exists
        setup_audit(app)
        initGlobalObject()
        generate_secret_key_file(app)
        reload_token_classes()
        app.check_license()
        app.load_providers()

    @app.before_request
    def setup_env():
        # The following functions are called here because they're
        # stuffing bits into `flask.g`, which is a per-request global
        # object. Much of what is stuffed into `flask.g` is actually
        # application-wide stuff that has no business being stored in
        # `flask.g` in the first place, but lots of code expects to be
        # able to look at the "request context" and find stuff
        # there. Disentangling the application-wide stuff in the
        # request context from the request-scoped stuff is a major
        # project that will not be undertaken just now, and we're
        # probably doing more work here than we need to. Global
        # variables suck.

        set_config()
        initGlobalObject()
        setup_security_provider(app)

    app.add_url_rule('/healthcheck/status', 'healthcheck', healthcheck)

    # Add pre request handlers
    app.before_first_request(init_logging_config)
    app.before_request(app._run_setup)
    app.before_request(app.start_session)

    # Per controller setup and handlers
    app.setup_controllers()

    if 'selfservice' in app.enabled_controllers:
        @app.route('/')
        def index():
            return redirect('/selfservice')

        @app.route('/account/login')
        def login():
            return redirect('/selfservice/login')

        @app.route('/account/logout')
        def logout():
            return redirect('/selfservice/logout')

    _setup_token_template_path(app)

    # Post handlers
    app.teardown_request(app.finalise_request)

    @app.errorhandler(LinotpError)
    def linotp_error_handler(e):
        """
        Pass LinotpError exceptions to sendError

        If Flask receives an exception which is derived from LinotpError,
        this handler will be called so that an error response can be
        returned to the user.
        """
        return sendError(None, e)

    @babel.localeselector
    def get_locale():
        """Figure out the locale for this request. We look at the
        request's `Accept-Language` header and pick the first language
        in the list that matches one of the languages that we actually
        support.
        """
        return request.accept_languages.best_match(app.available_languages,
                                                   "en")

    # Command line handler
    app.cli.add_command(init_db_command)

    # Enable profiling if desired. The options are debatable and could be
    # made more configurable. OTOH, we could all have a pony.
    profiling = False
    if app.config['PROFILE']:
        try:                    # Werkzeug >= 1.0.0
            from werkzeug.middleware.profiler import ProfilerMiddleware
            profiling = True
        except ImportError:
            try:                # Werkzeug < 1.0.0
                from werkzeug.contrib.profiler import ProfilerMiddleware
                profiling = True
            except ImportError:
                log.error("PROFILE is enabled but ProfilerMiddleware could "
                          "not be imported. No profiling for you!")
        if profiling:
            app.wsgi_app = ProfilerMiddleware(
                app.wsgi_app, profile_dir='profile',
                restrictions=[30], sort_by=['cumulative'])
            log.info("PROFILE is enabled (do not use this in production!)")

    return app

def erase_confirm(ctx, param, value):
    if ctx.params['erase_all_data']:
        # The user asked for data to be erased. We now look for a confirmation
        # or prompt the user
        if not value:
            prompt = click.prompt('Do you really want to erase the database?', type=click.BOOL)
            if not prompt:
                ctx.abort()

@click.command('init-db', help="Create tables in the database")
@click.option('--erase-all-data', is_flag=True, help="Erase ALL existing data")
@click.option('--yes', is_flag=True, callback=erase_confirm, expose_value=False, help="Erase data without prompting for confirmation")
@with_appcontext
def init_db_command(erase_all_data):
    """
    Create new tables

    The database is initialised and optionally data is cleared.
    """
    if erase_all_data:
        info = 'Recreating database'
    else:
        info = 'Creating database'

    click.echo(info)
    setup_db(current_app, erase_all_data)

def _setup_token_template_path(app):
    """
    Add Mako templates from tokens to the template path

    Tokens can bring their own Mako template with them, so
    we want to add the token directory to the template path.
    Flask allows us to do this by defining a Blueprint with
    a template path.

    This function should be called during application setup.
    """
    bp = Blueprint('token_templates', __name__, template_folder="tokens")
    app.register_blueprint(bp)

def healthcheck():
    uptime = time.time() - start_time
    return jsonify(status="alive", version=__version__, uptime=uptime)

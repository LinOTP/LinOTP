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
import os
import time
from typing import List

from datetime import datetime
from uuid import uuid4

from flask import Flask, g as flask_g, jsonify, Blueprint, redirect
from flask_mako import MakoTemplates

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

#
# manual schema migration
# - should become part of schema migration tool like alembic
from .model.migrate import run_data_model_migration
from .model import meta

from . import __version__
from .flap import LanguageError, config, set_config, set_lang, tmpl_context as c, request, _ as translate
from .defaults import set_defaults
from .settings import configs
from .tokens import reload_classes as reload_token_classes
from .lib.audit.base import getAudit
from .lib.config.global_api import initGlobalObject

from sqlalchemy import create_engine
from .model import init_model, meta         # FIXME: Flask-SQLAlchemy
from .model.migrate import run_data_model_migration

log = logging.getLogger(__name__)

start_time = time.time()
this_dir = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE_ENVVAR = "LINOTP_CONFIG_FILE"  # DRY
CONFIG_FILE_NAME = os.path.join(os.path.dirname(this_dir), "linotp.cfg")
if os.getenv(CONFIG_FILE_ENVVAR) is None:
    os.environ[CONFIG_FILE_ENVVAR] = CONFIG_FILE_NAME

mako = MakoTemplates()

# HTTP-ACCEPT-LANGUAGE strings are in the form of i.e.
# de-DE, de; q=0.7, en; q=0.3
accept_language_regexp = re.compile(r'\s*([^\s;,]+)\s*[;\s*q=[0-9.]*]?\s*,?')

class ConfigurationError(Exception):
    pass

class LinOTPApp(Flask):
    """
    The main LinOTP Flask application instance
    """

    cache = None
    """Beaker cache for this app"""

    enabled_controllers: List[str] = []
    """Currently activated controller names"""

    def __init__(self):
        super(LinOTPApp, self).__init__(__name__, static_folder='public', static_url_path='/static')

    def _run_setup(self):
        """
        Set up the app and database context for a request. Some of this is
        intended to be done only once and could be refactored into a
        before_first_request function
        """

        # TODO - language
        #self.set_language(request.headers)

        try:
            hsm = self.security_provider.getSecurityModule()
            self.hsm = hsm
            c.hsm = hsm
        except Exception as exx:
            log.exception('failed to assign hsm device: %r' % exx)
            raise exx

        l_config = getLinotpConfig()

        resolver_setup_done = config.get('resolver_setup_done', False)
        if resolver_setup_done is False:
            try:
                cache_dir = config.get("app_conf", {}).get("cache_dir", None)
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
                request_context['translate'] = translate

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
        if c.get('sep'):
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

    def set_language(self, headers):
        '''Invoke before everything else. And set the translation language'''
        languages = headers.get('Accept-Language', '')

        found_lang = False

        for match in accept_language_regexp.finditer(languages):
            # make sure we have a correct language code format
            language = match.group(1)
            if not language:
                continue
            language = language.replace('_', '-').lower()

            # en is the default language
            if language.split('-')[0] == 'en':
                found_lang = True
                break

            try:
                set_lang(language.split('-')[0])
                found_lang = True
                break
            except LanguageError:
                log.debug("Cannot set requested language: %s. Trying next"
                          " language if available.", language)

        if not found_lang and languages:
            log.warning("Cannot set preferred language: %r", languages)

        return

    def create_context(self, request, environment):
        """
        create the request context for all controllers
        """

        linotp_config = getLinotpConfig()

        # make the request id available in the request context
        request_context['RequestId'] = environment['REQUEST_ID']

        # a request local cache to get the user info from the resolver
        request_context['UserLookup'] = {}

        # a request local cache to get the resolver from user and realm
        request_context['UserRealmLookup'] = {}

        request_context['Config'] = linotp_config
        request_context['Policies'] = parse_policies(linotp_config)
        request_context['translate'] = translate

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

        Audit = config['audit']
        request_context['Audit'] = Audit
        request_context['audit'] = Audit.initialize(request, client=client)

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

        The dictionary file should be placed in the linotp configuration directory.
        If the file does not exist, an error is logged

        :return: path to dictionary file
        """

        dict_file = os.path.join(self.getConfigRootDirectory(), 'dictionary')

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
                    'handlers': ['console'],
                    'level': app.config["LOGGING_LEVEL"],
                    'propagate': False,
                },
                'linotp.lib': {
                    'handlers': ['console'],
                    'level': app.config["LOGGING_LEVEL"],
                    'propagate': True,
                },
                'linotp.lib.config.db_api': {
                    'handlers': ['console'],
                    'level': 'INFO',
                    'propagate': True,
                },
                'linotp.lib.security.provider': {
                    'handlers': ['console'],
                    'level': 'INFO',
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
    cache_opts['cache_type'] = app.config.get("BEAKER_CACHE_TYPE", "memory")
    if cache_opts['cache_type'] == 'file':
        beaker_dir = app.config.get(
            "BEAKER_CACHE_DIR",
            os.path.join(app.getConfigRootDirectory(), "cache"))
        cache_opts['cache.data_dir'] = os.path.join(beaker_dir, 'data')
        cache_opts['cache.lock_dir'] = os.path.join(beaker_dir, 'lock')
    app.cache = CacheManager(**parse_cache_config_options(cache_opts))


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


def setup_security_provider(app):
    """
    Set up the security provider (HSM or software). This is straight from
    `load_environment()` and should be rewritten to use Flask-style config
    settings, but this is a huge bowl of spaghetti.
    """
    try:
        flask_g.app_globals.security_provider.load_config(
            flask_g.request_context['config'])
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
    c = flask_g.request_context['config']
    c['audit'] = getAudit(c)


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

    app.config.from_object(configs[config_name])
    configs[config_name].init_app(app)

    app.config.from_envvar(CONFIG_FILE_ENVVAR, silent=True)

    if config_extra is not None:
        app.config.update(config_extra)

    mako.init_app(app)
    init_logging(app)

    with app.app_context():
        setup_cache(app)
        setup_db(app)
        set_config()       # ensure `request_context` exists
        initGlobalObject()
        generate_secret_key_file(app)
        set_defaults(app)
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
        setup_audit(app)
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

    return app

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

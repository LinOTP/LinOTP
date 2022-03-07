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

import hashlib
import importlib
import logging
import os
import secrets
import stat
import sys
import time
from datetime import datetime
from logging.config import dictConfig as logging_dictConfig
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from beaker.cache import CacheManager
from beaker.util import parse_cache_config_options
from flask_babel import Babel, gettext
from flask_jwt_extended import (
    JWTManager,
    get_jwt_identity,
    verify_jwt_in_request_optional,
)
from flask_jwt_extended.exceptions import (
    CSRFError,
    NoAuthorizationError,
    RevokedTokenError,
)
from jwt import ExpiredSignatureError
from jwt.exceptions import InvalidSignatureError

from flask import Blueprint
from flask import Config as FlaskConfig
from flask import Flask, abort, current_app
from flask import g as flask_g
from flask import jsonify, redirect, url_for
from flask.helpers import get_env

from . import __version__
from .flap import config, request, set_config, setup_mako
from .flap import tmpl_context as c
from .lib.audit.base import getAudit
from .lib.config import getLinotpConfig
from .lib.config.global_api import LinotpAppConfig
from .lib.context import request_context
from .lib.crypto.utils import init_key_partition
from .lib.error import LinotpError
from .lib.fs_utils import ensure_dir
from .lib.logs import init_logging_config, log_request_timedelta
from .lib.policy.util import parse_policies
from .lib.realm import getDefaultRealm, getRealms
from .lib.reply import sendError
from .lib.resolver import (
    closeResolvers,
    getResolverList,
    initResolvers,
    setupResolvers,
)
from .lib.security.provider import SecurityProvider
from .lib.tools.expiring_list import CustomExpiringList
from .lib.user import getUserFromRequest
from .lib.util import get_client
from .model import setup_db
from .settings import configs
from .tokens import reload_classes as reload_token_classes

log = logging.getLogger(__name__)

start_time = time.time()
this_dir = os.path.dirname(os.path.abspath(__file__))

LINOTP_CFG_DEFAULT = "linotp.cfg"  # within app.root_path


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
        """“Marker” that a string is really a relative path name."""

        pass

    def __init__(self, *args, **kwargs):
        """Initialise the LinOTP config mechanism. The `config_schema`
        parameter, which isn't part of Flask's `Config` mechanism, lets us
        associate a `ConfigSchema` object with this app (see `settings.py`);
        this can later be used to convert and verify configuration items
        as they are assigned.
        """
        self.set_schema(kwargs.pop("config_schema", None))
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
                if key.startswith("LINOTP_") and key != "LINOTP_CFG":
                    config_key = key[7:]
                    item = self.config_schema.find_item(config_key)
                    if item is not None:
                        self[config_key] = value

    def update(self, config_dict):
        """Take configuration variables from a dictionary. We don't want
        to use `dict.update()` because that won't pass the settings through
        `ExtFlaskConfig.__setitem__()`.
        """
        for key, value in config_dict.items():
            self[key] = value

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
        if (
            key.endswith(("_DIR", "_FILE"))
            and key != "ROOT_DIR"
            and value
            and value[0] != "/"
        ):
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
        root_dir = (
            super().__getitem__("ROOT_DIR")  # can't say 'self[…]' here
            if "ROOT_DIR" in self
            else "/ROOT_DIR_UNSET"
        )
        if isinstance(value, ExtFlaskConfig.RelativePathName):
            return os.path.join(root_dir, ".", value)
        if key == "BABEL_TRANSLATION_DIRECTORIES":
            # This is a Flask-Babel setting that we can't really change,
            # so it needs to be special-cased – it is a semicolon-separated
            # search path of directory names, any of which could be relative.

            return ";".join(
                [
                    os.path.join(root_dir, ".", fn) if fn[0] != "/" else fn
                    for fn in value.split(";")
                ]
            )
        return value

    def get(self, key, default=None):
        """We need to overload this so the relative-pathname hack will work
        even if people use `foo.get('bar')` instead of
        `foo['bar']`. (It turns out that the built-in `get()` method
        doesn't go through `__getitem__()` – `__getitem__()`'s mission
        in life is strictly to make the brackets do something.)
        The relative-pathname hack is just relevant for variables which contains
        a _file or _dir entry. So just those calls got handled as warning in all
        other cases it is handled as debug.
        """

        log_func = log.debug

        if "_file" in key.lower() or "_dir" in key.lower():
            log_func = log.warning

        try:
            return self[key]
        except KeyError:

            log_func(
                "Relying on `.get()` to set a default for "
                f"'{key}' violates the DRY principle. "
                "Instead, ensure that the schema contains a suitable "
                f"default (like {default!r})."
            )
            # raise LinOTPConfigKeyError(key)  # too drastic for now
            return default

    def check_directories(self):
        BASE_DIR_SETTINGS = {
            "ROOT_DIR",
            "CACHE_DIR",
            "DATA_DIR",
            "LOGFILE_DIR",
        }
        if self.config_schema is None:
            return False
        err = 0
        for key in self.config_schema.as_dict():
            if key not in BASE_DIR_SETTINGS:
                continue
            msg = ""
            dir_name = self[key]
            if os.path.exists(dir_name):
                s = os.stat(dir_name)
                if not stat.S_ISDIR(s.st_mode):
                    msg = "is not a directory"
            else:
                msg = "does not exist"
            if msg:
                print(
                    f"Error: Directory {dir_name} ({key}) {msg}",
                    file=sys.stderr,
                )
                err += 1
        if err:
            print("This is a fatal condition, aborting.", file=sys.stderr)
            sys.exit(1)


class LinOTPApp(Flask):
    """
    The main LinOTP Flask application instance
    """

    cache = None
    """Beaker cache for this app"""

    def __init__(self):
        self.cli_cmd = os.environ.get("LINOTP_CMD", "")
        self.config_class = ExtFlaskConfig  # our special `Config` class
        self.audit_obj = None  # No audit logging so far
        self.security_provider: Optional[SecurityProvider] = None
        self.enabled_controllers: List[str] = []
        """Currently activated controller names"""

        # ------------------------------------------------------------------ --

        # we create a app shared linotp config object which main purpose is
        # to syncronize the access to changes within multiple threads

        self.linotp_app_config: Optional[LinotpAppConfig] = None

        # ------------------------------------------------------------------ --

        super().__init__(
            __name__, static_folder="public", static_url_path="/static"
        )

    def _run_setup(self):
        """
        Set up the app and database context for a request. Some of this is
        intended to be done only once and could be refactored into a
        before_first_request function
        """

        l_config = getLinotpConfig()  # SQL-based configuration
        resolver_setup_done = config.get("resolver_setup_done", False)
        if resolver_setup_done is False:
            try:
                cache_dir = ensure_dir(
                    self,
                    "resolver cache",
                    "CACHE_DIR",
                    "resolvers",
                    mode=0o770,
                )
                setupResolvers(config=l_config, cache_dir=cache_dir)
                config["resolver_setup_done"] = True
            except Exception as exx:
                config["resolver_setup_done"] = False
                log.error("Failed to setup resolver: %r", exx)
                raise exx

    def check_license(self):
        """
        if we are in the setup cycle, we check for the linotpLicenseFile
        """
        if "linotpLicenseFile" in config and "license" not in config:
            license_str = ""
            filename = config.get("linotpLicenseFile", "")
            try:
                with open(filename) as f:
                    license_str = f.read()
            except IOError:
                log.error("could not open licence file: %s", filename)

            if not license_str:
                log.error("empty license file: %s", filename)
            else:
                import linotp.lib.support

                res, msg = linotp.lib.support.setSupportLicense(license_str)
                if res is False:
                    log.error(
                        "failed to load license: %s: %s", license_str, msg
                    )

                else:
                    log.info("license successfully loaded")

    def init_jwt_config(self):
        """
        Initialise the JWT authentication machinery.

        The LinOTP configuration settings don't support setting a dedicated secret
        key for JWT authentication, here we appropriate the first key from the
        `SECRET_FILE` (encKey) to use as the base for the secret key. We run this
        through PBKDF2 first, which is basically security theatre but doesn't cost
        us a lot.
        """

        with Path(self.config["SECRET_FILE"]).open("rb") as key_file:
            secret_key = key_file.read(32)
            jwt_salt = secrets.token_bytes(16)
            jwt_iterations = self.config.get("JWT_SECRET_ITERATIONS")
            jwt_key = hashlib.pbkdf2_hmac(
                "sha256",
                secret_key,
                salt=jwt_salt,
                iterations=jwt_iterations,
            )
        self.config["JWT_SECRET_KEY"] = jwt_key

        self.config["JWT_COOKIE_SECURE"] = self.config["SESSION_COOKIE_SECURE"]

        self.jwt = JWTManager(self)

        # initialize the block list holder (could be any database/memory class
        # which implements the interface
        self.jwt_blocklist = CustomExpiringList()

        # passing the function for checking blocklist to flask_jwt_extended
        @self.jwt.token_in_blacklist_loader
        def check_if_token_revoked(jwt_payload):
            jti = jwt_payload["jti"]
            return self.jwt_blocklist.item_in_list(jti)

    def start_session(self):

        # we add a unique request id to the request enviroment
        # so we can trace individual requests in the logging

        request.environ["REQUEST_ID"] = str(uuid4())
        request.environ["REQUEST_START_TIMESTAMP"] = datetime.now()

        # extract the username if request is authorized
        try:
            verify_jwt_in_request_optional()
            identity = get_jwt_identity()
            if identity is not None:
                flask_g.username = identity["username"]
                log.debug(
                    f"start_session: request session identity is {flask_g.username}"
                )
        except (
            NoAuthorizationError,
            ExpiredSignatureError,
            InvalidSignatureError,
            CSRFError,
        ) as e:
            # We do not need to do anything, authorization is checked in BaseController::jwt_check
            log.debug(
                "start_session: Unauthorized request, "
                "no request session identity set %r",
                e,
            )
        except RevokedTokenError as e:
            log.error(
                "%r : \n"
                "An already revoked jwt token was used to access a jwt protected method.\n"
                "This can be a user who saved a token and reused it, or an attacker "
                "using a stolen jwt token",
                e,
            )

        self.create_context(request, request.environ)

    def finalise_request(self, exc):
        drop_security_module()

        closeResolvers()

        # hint for the garbage collector to make the dishes
        data_objects = [
            "resolvers_loaded",
            "resolver_clazzes",
            "linotpConfig",
            "audit",
            "hsm",
        ]
        for data_obj in data_objects:
            if hasattr(c, data_obj):
                data = getattr(c, data_obj)
                del data

        log_request_timedelta(log)

    def setup_env(self):
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

        if request.path.startswith(self.static_url_path):
            return

        allocate_security_module()

    def create_context(self, request, environment):
        """
        create the request context for all controllers
        """

        linotp_config = getLinotpConfig()  # SQL-based configuration

        # make the request id available in the request context
        request_context["RequestId"] = environment["REQUEST_ID"]

        # a request local cache to get the user info from the resolver
        request_context["UserLookup"] = {}

        # a request local cache to get the resolver from user and realm
        request_context["UserRealmLookup"] = {}

        request_context["Config"] = linotp_config
        request_context["Policies"] = parse_policies(linotp_config)
        request_context["PolicyDefinitions"] = {}

        request_context["CacheManager"] = self.cache

        request_context["Path"] = request.path

        # ------------------------------------------------------------------------

        # setup the knowlege where we are

        request_context["action"] = None
        request_context["controller"] = None

        path = request.path.strip().strip("/").split("/")

        if path[0]:
            request_context["controller"] = path[0]

        request_context["action"] = "index" if len(path) == 1 else path[-1]

        # ------------------------------------------------------------------------

        initResolvers()

        client = None
        try:
            client = get_client(request=request)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r", exx)

        request_context["Client"] = client

        flask_g.audit = self.audit_obj.initialize(request, client=client)

        authUser = None
        try:
            authUser = getUserFromRequest(request)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r", exx)

        request_context["AuthUser"] = authUser
        request_context["UserLookup"] = {}

        # ------------------------------------------------------------------ --
        # get the current resolvers

        resolvers = []
        try:
            resolvers = getResolverList(config=linotp_config)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r", exx)

        request_context["Resolvers"] = resolvers

        # ------------------------------------------------------------------ --
        # get the current realms

        realms = {}
        try:
            realms = getRealms()
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r", exx)

        request_context["Realms"] = realms

        # ------------------------------------------------------------------ --

        defaultRealm = ""
        try:
            defaultRealm = getDefaultRealm(linotp_config)
        except UnicodeDecodeError as exx:
            log.error("Failed to decode request parameters %r", exx)

        request_context["defaultRealm"] = defaultRealm

        # ------------------------------------------------------------------ --
        # load the providers

        from linotp.provider import Provider_types, getProvider

        provider = {}
        for provider_type in list(Provider_types.keys()):
            provider[provider_type] = getProvider(provider_type)

        request_context["Provider"] = provider

        # ------------------------------------------------------------------ --

        # setup the SecretKey for the elliptic curve if it is not already done
        # elliptic curve are working with one partition (0) which is one
        # public / private key pair

        partition = 0
        if "SecretKey.Partition.%d" % partition not in linotp_config:
            init_key_partition(linotp_config, partition=partition)

    def getRadiusDictionaryPath(self):
        """
        get the radius dictionary path

        The dictionary file is in the same directory as this file

        :return: path to dictionary file
        """

        dict_file = os.path.join(this_dir, "dictionary")

        if not os.path.isfile(dict_file):
            log.error(
                "Radius settings setup failed - missing dictionary file: %s",
                dict_file,
            )

        return dict_file

    def getConfigRootDirectory(self):
        """
        Get root directory for local configuration files. This directory
        is used for storing files such as the DB secret key.

        An exception is thrown if the directory does not exist.
        """
        rootdir = config.get("ROOT_DIR")

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
        cache_manager = request_context["CacheManager"]
        if not cache_manager:
            import traceback

            log.warning(
                "[%s] Could not initialise cache due to missing manager",
                traceback.format_stack(None, 1),
            )

        return cache_manager

    def getRequestParams(self):
        """
        Parses the request params from the request objects body / params
        dependent on request content_type.
        """
        request_params = {}
        try:
            if request.is_json:
                request_params = request.json
            else:
                for key in request.values:
                    if key.endswith("[]"):
                        request_params[key[:-2]] = request.values.getlist(key)
                    else:
                        request_params[key] = request.values.get(key)
        except UnicodeDecodeError as exx:
            # we supress Exception here as it will be handled in the
            # controller which will return corresponding response
            log.warning("Failed to access request parameters: %r", exx)

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
            bits = ctrl_name.split(":", 2)
            while len(bits) < 3:
                bits.append("")
            ctrl_name, url_prefix, ctrl_class_name = bits
            self.enable_controller(ctrl_name, url_prefix, ctrl_class_name)

    def enable_controller(
        self, ctrl_name, url_prefix=None, ctrl_class_name=None
    ):
        """
        Initialise an individual controller and its routing

        :param ctrl_name: The name of the controller
        :param url_prefix: Alternative url prefix. Defaults to /`ctrl_name`
        :param ctrl_class_name: Name of controller class to load. Defaults to CtrlNameController
        """
        if not ctrl_name:
            raise ConfigurationError(
                "no controller module specified: {}".format(ctrl_name)
            )
        if not ctrl_class_name:
            # "foobar" => "FoobarController"
            ctrl_class_name = ctrl_name.title() + "Controller"

        mod = importlib.import_module("." + ctrl_name, "linotp.controllers")
        cls = getattr(mod, ctrl_class_name, None)
        if cls is None:
            raise ConfigurationError(
                "{} does not define the '{}' class".format(
                    ctrl_name, ctrl_class_name
                )
            )

        if not url_prefix:
            url_prefix = cls.default_url_prefix or "/" + ctrl_name

        self.logger.debug(
            "Registering {0} class at {1}".format(ctrl_class_name, url_prefix)
        )
        self.register_blueprint(cls(ctrl_name), url_prefix=url_prefix)

        self.enabled_controllers.append(ctrl_name)

    def database_needed(self) -> bool:
        """Does the app require a database?

        Whether the app needs a database depends on the command that
        was executed. Some commands such as init and config
        need to be able to run without trying to connect to databases.
        """
        cli_cmd = getattr(self, "cli_cmd", "")
        return cli_cmd not in ("init", "config")

    def setup_audit(self):
        if self.database_needed():
            self.audit_obj = getAudit()


def init_logging(app):
    """Sets up logging for LinOTP."""

    if app.config["LOGGING"] is None:
        app.config["LOGGING"] = {
            "version": 1,
            "disable_existing_loggers": True,
            "handlers": {
                "console": {
                    "level": app.config["LOGGING_CONSOLE_LEVEL"],
                    "class": "logging.StreamHandler",
                    "formatter": "linotp",
                },
                "file": {
                    "level": app.config["LOGGING_FILE_LEVEL"],
                    "class": "logging.handlers.RotatingFileHandler",
                    "filename": os.path.join(
                        app.config["LOGFILE_DIR"], app.config["LOGFILE_NAME"]
                    ),
                    "maxBytes": app.config["LOGFILE_MAX_LENGTH"],
                    "backupCount": app.config["LOGFILE_MAX_VERSIONS"],
                },
            },
            "formatters": {
                "linotp": {
                    "format": app.config["LOGFILE_FILE_LINE_FORMAT"],
                },
            },
            "loggers": {
                "linotp": {
                    "handlers": ["console", "file"],
                    "level": app.config["LOGGING_LEVEL"],
                    "propagate": True,
                },
                "sqlalchemy.engine": {
                    "handlers": ["console", "file"],
                    "level": app.config["SQLALCHEMY_LOGGING_LEVEL"],
                    "propagate": True,
                },
            },
        }

    if app.cli_cmd != "config":
        ensure_dir(app, "log", "LOGFILE_DIR", mode=0o770)
        logging_dictConfig(app.config["LOGGING"])

    app.logger = logging.getLogger(app.name)
    app.logger.info("LinOTP {} starting ...".format(__version__))


def setup_cache(app):
    """Initialise the Beaker cache for this app."""

    cache_opts = {}
    cache_opts["cache_type"] = app.config["BEAKER_CACHE_TYPE"]
    if cache_opts["cache_type"] == "file":
        beaker_dir = ensure_dir(
            app, "file-based Beaker cache", "CACHE_DIR", "beaker", mode=0o770
        )
        cache_opts["cache.data_dir"] = os.path.join(beaker_dir, "data")
        cache_opts["cache.lock_dir"] = os.path.join(beaker_dir, "lock")
    app.cache = CacheManager(**parse_cache_config_options(cache_opts))


# -------------------------------------------------------------------------- --

# linotp config


def init_linotp_config(app):
    """initialize the app global linotp config manager"""

    app.linotp_app_config = LinotpAppConfig()


# -------------------------------------------------------------------------- --

# security provider


def init_security_provider():
    """Initialize the security provider.

    the security provider is an manager for a pool of security module
    connections.

    The security provider will then provide on each request an hsm connection
    out of the pool with in the request context (flask.g).
    """
    try:

        security_provider = SecurityProvider()
        security_provider.load_config(current_app.config)

        current_app.security_provider = security_provider

    except Exception as exx:
        current_app.logger.error(
            "Failed to load security provider definition: {}".format(exx)
        )
        raise exx


def allocate_security_module():
    """Allocate a security module for the request.

    As the security provider has been initialized at application start, we
    can now fetch an security module connection from the SecurityProvider pool
    and attach this to the request context (c)

    TODO: c, which is the template context, should be replaced with the
          app context (flask.g) which holds by definition the application
          resources on a per request base

    """
    try:
        c.hsm = current_app.security_provider.getSecurityModule()
    except Exception as exx:
        log.error("Failed to get hsm connection for request!")
        raise exx


def drop_security_module():
    """Mark the request security module as free again.

    drop the current security module (c.hsm) back to the security modules pool
    of security provider
    """
    try:
        current_app.security_provider.dropSecurityModule()
    except Exception as exx:
        log.error("Failed to push hsm connection back to pool! %r", c.hsm)
        raise exx


def _configure_app(app, config_name="default", config_extra=None):
    """
    Testing the configuration mechanism is a lot easier if it can be
    invoked separately from `create_app()`, which does a lot of other
    stuff, too. Therefore we have pulled out all the configuration-related
    code from `create_app()` into this function.
    """
    app.config.from_object(configs[config_name])
    configs[config_name].init_app(app)

    # Take list of configuration files from `LINOTP_CFG` if defined,
    # otherwise from `linotp-cfg-default` in the application root
    # path if that exists, otherwise assume `LINOTP_CFG_DEFAULT`.

    root_path = Path(app.config.root_path)

    linotp_cfg_files = os.environ.get("LINOTP_CFG", None)
    linotp_cfg_default = root_path / "linotp-cfg-default"
    if linotp_cfg_files is None:
        if linotp_cfg_default.exists():
            try:
                linotp_cfg_files = linotp_cfg_default.read_text().strip()
            except OSError as ex:
                print(f"Error reading {linotp_cfg_default}: {ex!r}")
        else:
            linotp_cfg_files = LINOTP_CFG_DEFAULT

    # Read the configuration files.
    #
    # A `-` at the start of a file name (which will not be considered
    # part of the actual file name) suppresses the warning if the file
    # could not be read.

    if linotp_cfg_files:
        for fn in linotp_cfg_files.split(":"):
            warn_on_error = True
            if fn and fn[0] == "-":
                warn_on_error = False
                fn = fn[1:]
            fn = root_path / fn  # better message
            if fn.is_dir():
                fn /= "*.cfg"
            # Check `fn` itself if glob doesn't yield results
            # (e.g., when checking `/foo/linotp.cfg` but `/foo` doesn't
            # exist).
            for fn0 in sorted(
                list(fn.resolve().parent.glob(fn.name)) or [str(fn)]
            ):
                if app.config.from_pyfile(fn0, silent=True):
                    print(
                        f"Configuration loaded from {fn0!s}", file=sys.stderr
                    )
                elif warn_on_error:
                    print(
                        f"Configuration from {fn0!s} failed"
                        " (check location and permissions)",
                        file=sys.stderr,
                    )

    if config_extra is not None:
        app.config.update(config_extra)

    # Check the environment for further settings

    app.config.from_env_variables()

    if getattr(app, "cli_cmd", "") != "config":
        app.config.check_directories()


def create_app(config_name=None, config_extra=None):
    """
    Generate a new instance of the Flask app

    This generates and configures the main application instance. Testing
    environments can use `config_extra` to provide extra configuration values
    such as a temporary database URL.

    @param config_name The name of the configuration to load from settings.py
    @param config_extra An optional dict of configuration override values
    """
    app = LinOTPApp()

    # We need to do this here because the Flask CLI machinery doesn't seem
    # to pass the correct value.

    if config_name is None:
        config_name = get_env()

    _configure_app(app, config_name, config_extra)

    babel = Babel(app, configure_jinja=False, default_domain="linotp")

    # Determine which languages are available in the i18n directory.
    # Note that we always have English even without a translation file.

    app.available_languages = list(
        {"en"} | {t.language for t in babel.list_translations()}
    )

    setup_mako(app)
    init_logging(app)

    with app.app_context():
        setup_cache(app)
        setup_db(app)

        init_linotp_config(app)
        set_config()  # ensure `request_context` exists

        init_security_provider()

        app.setup_audit()

        reload_token_classes()
        app.check_license()

    app.add_url_rule("/healthcheck/status", "healthcheck", healthcheck)

    # Add pre request handlers
    app.before_first_request(init_logging_config)
    app.before_first_request(app.init_jwt_config)
    app.before_request(app.setup_env)
    app.before_request(app._run_setup)
    app.before_request(app.start_session)

    # Per controller setup and handlers
    app.setup_controllers()

    @app.route("/")
    def index():
        site_root_redirect = config["SITE_ROOT_REDIRECT"]
        if site_root_redirect:
            return redirect(site_root_redirect)

        if "selfservice" in app.enabled_controllers:
            return redirect(url_for("selfservice.index"))

        return abort(404)

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
        try:
            return request.accept_languages.best_match(
                app.available_languages, "en"
            )
        except RuntimeError as exx:
            # Working outside of request context.
            return babel.default_locale

    # Enable profiling if desired. The options are debatable and could be
    # made more configurable. OTOH, we could all have a pony.
    profiling = False
    if app.config["PROFILE"]:
        try:  # Werkzeug >= 1.0.0
            from werkzeug.middleware.profiler import ProfilerMiddleware

            profiling = True
        except ImportError:
            try:  # Werkzeug < 1.0.0
                from werkzeug.contrib.profiler import ProfilerMiddleware

                profiling = True
            except ImportError:
                log.error(
                    "PROFILE is enabled but ProfilerMiddleware could "
                    "not be imported. No profiling for you!"
                )
        if profiling:
            app.wsgi_app = ProfilerMiddleware(
                app.wsgi_app,
                profile_dir="profile",
                restrictions=[30],
                sort_by=["cumulative"],
            )
            log.info("PROFILE is enabled (do not use this in production!)")

    return app


def healthcheck():
    uptime = time.time() - start_time
    return jsonify(status="alive", version=__version__, uptime=uptime)

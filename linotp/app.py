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
from uuid import uuid4

from beaker.cache import CacheManager
from beaker.util import parse_cache_config_options
from flask import Config as FlaskConfig
from flask import Flask, abort, current_app, jsonify, redirect, request, url_for
from flask import g as flask_g
from flask_babel import Babel
from flask_jwt_extended import JWTManager
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.profiler import ProfilerMiddleware

from . import __version__
from .flap import config, setup_mako, setup_request_context
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
from .lib.util import get_client, get_log_level
from .middlewares.trusted_proxy_handler import TrustedProxyHandler
from .model import SYS_EXIT_CODE, setup_db
from .settings import ConfigSchema, configs
from .tokens import reload_classes as reload_token_classes

log = logging.getLogger(__name__)

start_time = time.time()
this_dir = os.path.dirname(os.path.abspath(__file__))

LINOTP_CFG_DEFAULT = "linotp.cfg"  # within app.root_path

ENV_PREFIX = "LINOTP_"
ENV_PREFIX_LENGTH = len(ENV_PREFIX)

AVAILABLE_CONTROLLERS = {
    "admin",
    "audit",
    "auth",
    "gettoken",
    "maintenance",
    "manage",
    "monitoring",
    "reporting",
    "selfservice",
    "system",
    "tools",
    "userservice",
    "validate",
    "tokens:/api/v2/tokens",
    "realms:/api/v2/realms",
    "resolvers:/api/v2/resolvers",
    "auditlog:/api/v2/auditlog",
}

HEALTHCHECK_ENDPOINT = "healthcheck"

START_LINOTP_COMMANDS = ["run", ""]  # we get `""` from gunicorn


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

    config_schema: ConfigSchema = None

    class RelativePathName(str):
        """“Marker” that a string is really a relative path name."""

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
        if self.config_schema is None:
            return
        for key, value in os.environ.items():
            if key.startswith(ENV_PREFIX) and key != f"{ENV_PREFIX}CFG":
                config_key = key[ENV_PREFIX_LENGTH:]
                item = self.config_schema.find_item(config_key)
                if item is not None:
                    self[config_key] = value
                    log.debug("Set %s from environment variable.", config_key)

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
            # so it needs to be special-cased - it is a semicolon-separated
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
        doesn't go through `__getitem__()` - `__getitem__()`'s mission
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
            "LOG_FILE_DIR",
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
            sys.exit(SYS_EXIT_CODE)


class LinOTPApp(Flask):
    """
    The main LinOTP Flask application instance
    """

    """Beaker cache for this app"""
    cache = None

    available_languages: list[str] = []

    def __init__(self):
        self.cli_cmd = os.environ.get("LINOTP_CMD", "")
        self.config_class = ExtFlaskConfig  # our special `Config` class
        self.audit_obj = None  # No audit logging so far
        self.security_provider: SecurityProvider | None = None
        self.enabled_controllers: list[str] = []
        """Currently activated controller names"""

        # ------------------------------------------------------------------ --

        # we create an app-wide shared linotp config object whose main purpose is
        # to synchronize the access to changes within multiple threads

        self.linotp_app_config: LinotpAppConfig | None = None

        # ------------------------------------------------------------------ --

        super().__init__(__name__, static_folder="public", static_url_path="/static")

    def setup_resolvers(self):
        """
        Set up the available resolver classes
        """
        log.debug("Setting up resolvers")
        try:
            cache_dir = ensure_dir(
                self, "resolver cache", "CACHE_DIR", "resolvers", mode=0o770
            )
            setupResolvers(config=getLinotpConfig(), cache_dir=cache_dir)
            log.debug("Setting up resolvers successful")
        except Exception as exx:
            log.error("Failed to setup resolvers: %r", exx)
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
            except OSError:
                log.error("could not open licence file: %s", filename)

            if not license_str:
                log.error("empty license file: %s", filename)
            else:
                import linotp.lib.support

                res, msg = linotp.lib.support.setSupportLicense(license_str)
                if res is False:
                    log.error("failed to load license: %s: %s", license_str, msg)

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
            jwt_iterations = self.config["JWT_SECRET_ITERATIONS"]
            jwt_key = hashlib.pbkdf2_hmac(
                "sha256",
                secret_key,
                salt=jwt_salt,
                iterations=jwt_iterations,
            )
        self.config["JWT_SECRET_KEY"] = jwt_key

        self.config["JWT_COOKIE_SECURE"] = self.config["SESSION_COOKIE_SECURE"]

        # we need to set the JWT_VERIFY_SUB to False, as we do not have a "sub" attribute in the JWT
        # https://github.com/apache/superset/issues/30995
        self.config["JWT_VERIFY_SUB"] = False

        self.jwt = JWTManager(self)

        # initialize the block list holder (could be any database/memory class
        # which implements the interface
        self.jwt_blocklist = CustomExpiringList()

        # passing the function for checking blocklist to flask_jwt_extended
        @self.jwt.token_in_blocklist_loader
        def check_if_token_revoked(*args):
            # This is called as `…(payload)` or `…(header, payload)` but we're only interested in `payload`
            jti = args[-1].get("jti")
            if jti is None:
                msg = "jti"
                raise KeyError(msg)
            return self.jwt_blocklist.item_in_list(jti)

    def start_session(self):
        """
        initialize the request metadata
        """
        if self.exclude_from_before_request_setup():
            return

        # we add a unique request id to the request environment
        # so we can trace individual requests in the logging
        request.environ["REQUEST_ID"] = str(uuid4())
        request.environ["REQUEST_START_TIMESTAMP"] = datetime.now()

        if log.isEnabledFor(logging.DEBUG):
            # check debug log level beforehand to not slow down
            # by not parsing the request params in production
            log.debug(
                "Starting Request: [Request ID: %s] [%s] %s",
                request.environ.get("REQUEST_ID"),
                request.method,
                request.path,
            )
            log.debug("Request params: %r", self.getRequestParams())

    def is_request_static(self) -> bool:
        return request.path.startswith(self.static_url_path)

    def is_healthcheck_request(self) -> bool:
        return request.path.startswith(f"/{HEALTHCHECK_ENDPOINT}")

    def exclude_from_before_request_setup(self) -> bool:
        return self.is_request_static() or self.is_healthcheck_request()

    def finalise_request(self, exc):
        if self.exclude_from_before_request_setup():
            return

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

        log.debug(
            "Finished Request: [Request ID: %s] [%s] %s",
            request.environ.get("REQUEST_ID"),
            request.method,
            request.path,
        )

    def create_context(self):
        """
        create the request context for all controllers
        """
        if self.exclude_from_before_request_setup():
            return

        setup_request_context()
        allocate_security_module()

        linotp_config = getLinotpConfig()  # SQL-based configuration

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

        # setup the knowledge where we are

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

        provider = {
            provider_type: getProvider(provider_type)
            for provider_type in Provider_types.keys()
        }

        request_context["Provider"] = provider

        # ------------------------------------------------------------------ --

        # setup the SecretKey for the elliptic curve if it is not already done
        # elliptic curve are working with one partition (0) which is one
        # public / private key pair

        partition = 0
        if f"SecretKey.Partition.{partition}" not in linotp_config:
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
            # we suppress Exception here as it will be handled in the
            # controller which will return corresponding response
            log.warning("Failed to access request parameters: %r", exx)

        return request_params

    def setup_controllers(self):
        """
        Initialise controllers and their routing

        `DISABLE_CONTROLLERS` and 'ENABLE_CONTROLLERS' are strings that
        contain space-separated list of controllers that should be made
        available.
        If an entry in this list is `foo`, this means that the Python module
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

        # if there is any Controller defined in "ENABLE_CONTROLLERS" we take
        # these as definition of available_controllers instead of the constant
        # AVAILABLE_CONTROLLERS
        enabled = self.config["ENABLE_CONTROLLERS"].strip()

        available_controllers = {controller.strip() for controller in enabled.split()}

        if "ALL" in available_controllers:
            available_controllers = available_controllers | AVAILABLE_CONTROLLERS
            available_controllers.remove("ALL")

        disabled = self.config["DISABLE_CONTROLLERS"].split()
        disable_controllers = {controller.strip() for controller in disabled}

        controllers = available_controllers - disable_controllers

        # now we have to remove duplicates in case for the mapping case
        # like 'selfservice:/my-custom-path selfservice' as this would
        # result in an flask error for duplicate blueprint registration.
        # Remark:
        # This might as well be expressed by the DISABLE_CONTROLLERS, but
        # then the gettoken controller might be forgotten

        for controller in set(controllers):
            controller_name, _, prefix = controller.partition(":")
            if prefix and controller_name in controllers:
                controllers.remove(controller_name)

        for ctrl_name in controllers:
            bits = ctrl_name.split(":", 2)
            while len(bits) < 3:
                bits.append("")
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
            msg = f"no controller module specified: {ctrl_name}"
            raise ConfigurationError(msg)
        if not ctrl_class_name:
            # "foobar" => "FoobarController"
            ctrl_class_name = ctrl_name.title() + "Controller"

        mod = importlib.import_module("." + ctrl_name, "linotp.controllers")
        cls = getattr(mod, ctrl_class_name, None)
        if cls is None:
            msg = f"{ctrl_name} does not define the '{ctrl_class_name}' class"
            raise ConfigurationError(msg)

        if not url_prefix:
            url_prefix = cls.default_url_prefix or "/" + ctrl_name

        self.logger.debug("Registering %s class at %s", ctrl_class_name, url_prefix)
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

    def check(self):
        self._check_secret_file()
        self._check_audit_keys()

    def _check_secret_file(self):
        secret_file = self.config["SECRET_FILE"]
        if not os.path.isfile(secret_file):
            print(
                f"CRITICAL: SECRET_FILE does not exist in {secret_file}. Run `linotp init enc-key` to create it.",
                file=sys.stderr,
            )
            sys.exit(SYS_EXIT_CODE)

    def _check_audit_keys(self):
        public_key = self.config["AUDIT_PUBLIC_KEY_FILE"]
        private_key = self.config["AUDIT_PRIVATE_KEY_FILE"]
        if not os.path.isfile(public_key) or not os.path.isfile(private_key):
            print(
                "CRITICAL: Audit log keypair does not exist; use `linotp init audit-keys` to generate one.",
                file=sys.stderr,
            )
            sys.exit(SYS_EXIT_CODE)


def init_logging(app: LinOTPApp):
    """Sets up logging for LinOTP."""

    if app.config["LOG_CONFIG"] is None:
        app.config["LOG_CONFIG"] = {
            "version": 1,
            "disable_existing_loggers": True,
            "handlers": {
                "console": {
                    "level": app.config["LOG_CONSOLE_LEVEL"],
                    "class": "logging.StreamHandler",
                    "formatter": "linotp_console",
                },
                "file": {
                    "level": app.config["LOG_FILE_LEVEL"],
                    "class": "logging.handlers.RotatingFileHandler",
                    "formatter": "linotp_file",
                    "filename": os.path.join(
                        app.config["LOG_FILE_DIR"], app.config["LOG_FILE_NAME"]
                    ),
                    "maxBytes": app.config["LOG_FILE_MAX_LENGTH"],
                    "backupCount": app.config["LOG_FILE_MAX_VERSIONS"],
                },
            },
            "formatters": {
                "linotp_file": {
                    "format": app.config["LOG_FILE_LINE_FORMAT"],
                },
                "linotp_console": {
                    "format": app.config["LOG_CONSOLE_LINE_FORMAT"],
                },
            },
            "loggers": {
                "linotp": {
                    "handlers": ["console", "file"],
                    "level": get_log_level(app),
                    "propagate": True,
                },
                "sqlalchemy.engine": {
                    "handlers": ["console", "file"],
                    "level": app.config["LOG_LEVEL_DB_CLIENT"],
                    "propagate": True,
                },
            },
        }

    if app.cli_cmd != "config":
        ensure_dir(app, "log", "LOG_FILE_DIR", mode=0o770)
        logging_dictConfig(app.config["LOG_CONFIG"])

    app.logger = logging.getLogger(app.name)


def setup_cache(app: LinOTPApp):
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


def init_linotp_config(app: LinOTPApp):
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
        current_app.logger.error("Failed to load security provider definition: %r", exx)
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


def _configure_app(
    app: LinOTPApp,
    config_name: str | None = None,
    config_extra: dict | None = None,
):
    """
    Testing the configuration mechanism is a lot easier if it can be
    invoked separately from `create_app()`, which does a lot of other
    stuff, too. Therefore we have pulled out all the configuration-related
    code from `create_app()` into this function.
    """

    # Use production as default environment if not specified
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "production")

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
            for fn0 in sorted(list(fn.resolve().parent.glob(fn.name)) or [str(fn)]):
                if app.config.from_pyfile(fn0, silent=True):
                    print(f"Configuration loaded from {fn0!s}", file=sys.stderr)
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


def _setup_error_handlers(app: LinOTPApp):
    """Set up Flask error handlers to handle all Exceptions."""

    @app.errorhandler(LinotpError)
    def linotp_error_handler(linotpError):
        """
        Pass LinotpError exceptions to sendError

        If Flask receives an exception which is derived from LinotpError,
        this handler will be called so that an error response can be
        returned to the user.
        """
        return sendError(linotpError)

    @app.errorhandler(HTTPException)
    def httpexception_handler(httpException):
        """
        Simply return the error response in case of an HTTPException

        Usecase: Do not trigger `default_error_handler` for e.g. 404 errors
        """
        return httpException

    @app.errorhandler(Exception)
    def default_error_handler(exception):
        """
        Default error handler

        Used when no other handler handles the Exception.
        Logs the Exception with backtrace and returns our error response.
        """
        log.exception(exception)
        return sendError(exception)


def _setup_request_handlers(app: LinOTPApp):
    """Set up request lifecycle handlers."""
    app.before_request(app.start_session)
    app.before_request(app.create_context)
    app.teardown_request(app.finalise_request)


def _setup_root_route(app: LinOTPApp):
    """Set up the root route handler."""

    @app.route("/")
    def index():
        try:
            site_root_redirect = app.config["SITE_ROOT_REDIRECT"]
            if site_root_redirect:
                return redirect(site_root_redirect)

            if "selfservice" in app.enabled_controllers:
                return redirect(url_for("selfservice.index"))

        except Exception as exc:
            log.warning("Error handling root route: %r", exc)

        return abort(404)


def _setup_profiling(app: LinOTPApp):
    """Set up profiling middleware if enabled."""
    if app.config["PROFILE"]:
        app.wsgi_app = ProfilerMiddleware(
            app.wsgi_app,
            profile_dir="profile",
            restrictions=[30],
            sort_by=["cumulative"],
        )
        log.info("PROFILE is enabled (do not use this in production!)")


def _setup_proxies(app: LinOTPApp):
    """Set up trusted proxies handler if configured."""
    if trusted_proxies := app.config["TRUSTED_PROXIES"]:
        app.wsgi_app = TrustedProxyHandler(app.wsgi_app, trusted_proxies)


def _setup_babel(app: LinOTPApp):
    """Set up Babel internationalization."""

    def get_locale():
        """Determine locale for the current request."""
        try:
            return request.accept_languages.best_match(app.available_languages, "en")
        except RuntimeError:
            # Working outside of request context.
            return babel.default_locale

    with app.app_context():
        # Determine which languages are available in the i18n directory.
        # Note that we always have English even without a translation file.
        babel = Babel(app, configure_jinja=False, default_domain="linotp")
        app.available_languages = list(
            {"en"} | {t.language for t in babel.list_translations()}
        )
        babel.init_app(app, locale_selector=get_locale)


def create_app(config_name=None, config_extra=None):
    """
    Generate a new instance of the Flask app.

    This generates and configures the main application instance. Testing
    environments can use `config_extra` to provide extra configuration values
    such as a temporary database URL.

    Args:
        config_name (str, optional): The name of the configuration to load from settings.py
        config_extra (dict, optional): Additional configuration override values

    Returns:
        LinOTPApp: The configured Flask application instance
    """
    app = LinOTPApp()

    # Load config
    _configure_app(app, config_name, config_extra)
    init_linotp_config(app)

    init_logging(app)

    if app.cli_cmd in START_LINOTP_COMMANDS:
        app.logger.info("LinOTP %s starting ...", __version__)

    # Initialize components (that need app_context)
    with app.app_context():
        setup_db(app)
        if not app.testing and app.cli_cmd not in START_LINOTP_COMMANDS:
            return app

        if not app.testing:
            init_logging_config()

        init_security_provider()
        app.setup_audit()
        reload_token_classes()
        app.check_license()

    # Setup request handlers and routes
    _setup_request_handlers(app)
    app.setup_controllers()
    _setup_root_route(app)
    _setup_error_handlers(app)
    # Setup health check endpoint
    app.add_url_rule(
        f"/{HEALTHCHECK_ENDPOINT}/status", HEALTHCHECK_ENDPOINT, healthcheck
    )

    # Initialize internationalization
    _setup_babel(app)
    # Setup mako templates
    setup_mako(app)

    # Setup middleware
    _setup_proxies(app)
    _setup_profiling(app)

    setup_cache(app)

    # Perform final checks for run command
    if app.cli_cmd in START_LINOTP_COMMANDS:
        app.check()

    # Initialize JWT configuration for non-init commands
    # if app.cli_cmd != "init":
    #     app.init_jwt_config()
    app.init_jwt_config()

    return app


def healthcheck():
    uptime = time.time() - start_time
    return jsonify(status="alive", version=__version__, uptime=uptime)

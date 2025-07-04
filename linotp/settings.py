import builtins
import json
import logging
import os
import textwrap
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import click
from flask import current_app
from flask.cli import AppGroup
from jsonschema import Draft4Validator

from .lib.security import provider
from .lib.security.pkcs11 import Pkcs11SecurityModule
from .lib.type_utils import boolean as to_boolean

logger = logging.getLogger(__name__)

basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}


# Validation functions for configuration items. The `ConfigSchema.validate`
# attribute is supposed to contain a function that takes `key` and `value`
# arguments, and raises an exception if the `value` is invalid for the item
# in question. The `key` argument is used to make the exception message
# prettier.
#
# The functions here are really factory functions; they are used in
# `ConfigItem` definitions to create the functions that do the actual
# checking. This makes argument handling easier, because we don't need to
# mix “setup” arguments with the `key` and `value` arguments used during
# the actual validation.
#
# Just to liven things up, the returned function's doc string contains
# a summary of what the function does. This is used in the `flask
# config explain` command to list the constraints that are applied to a
# configuration item.


class LinOTPConfigKeyError(KeyError):
    """Used for LinOTP configuration items with invalid names."""


class LinOTPConfigValueError(ValueError):
    """Used for out-of-range errors etc. with LinOTP configuration items."""


def check_int_in_range(min=None, max=None):
    """Factory function that will return a function that ensures that `min
    <= value <= max`. If `min` or `max` are not given, the practically
    default to “negative infinity” and “positive infinity”,
    respectively.
    """

    def f(key, value):
        result = int(value)  # Raises an exception if `value` is not an `int`
        if min is not None and result < min:
            msg = f"{key} is {result} but must be at least {min}"
            raise LinOTPConfigValueError(msg)
        if max is not None and result > max:
            msg = f"{key} is {result} but must be at most {max}"
            raise LinOTPConfigValueError(msg)

    if min is None and max is not None:
        f.__doc__ = f"value <= {max}"
    elif min is not None and max is None:
        f.__doc__ = f"value >= {min}"
    elif min is not None and max is not None:
        f.__doc__ = f"{min} <= value <= {max}"
    return f


def check_json_schema(schema: dict | None = None):
    """Factory function that will return a function that ensures that
    `value` agrees to the schema
    """
    if schema is None:
        schema = {}
    Draft4Validator.check_schema(schema)

    def f(key, value):
        # check if given schema is correct
        if Draft4Validator(schema).is_valid(value):
            print("value agrees with schema")
        else:
            msg = f"{value} does not agree with schema {schema}."
            raise LinOTPConfigValueError(msg)

    f.__doc__ = f"value should apply {schema}"
    return f


def check_membership(allowed: dict | None = None):
    """Factory function that will return a function that ensures that
    `value` is contained in `allowed` (the set of allowed values).
    """
    if allowed is None:
        allowed = {}
    allowed_values = ", ".join(repr(s) for s in sorted(allowed))

    def f(key, value):
        if value not in allowed:
            msg = f"{key} is {value} but must be one of {allowed_values}."
            raise LinOTPConfigValueError(msg)

    f.__doc__ = f"value in {{{allowed_values}}}"
    return f


def check_absolute_pathname():
    """Factory function that will return a function that ensures that
    `value` is an absolute path name. Used to check `ROOT_DIR`.
    """

    def f(key, value):
        if not value or value[0] != "/":
            msg = f"{key} must be an absolute path name but {value} is relative."
            raise LinOTPConfigValueError(msg)

    f.__doc__ = "value is an absolute path name"
    return f


class DBURI(str):
    """This ensures that DB URIs that start with `postgres://` are
    considered equivalent to DB URIs that start with `postgresql://`.
    """

    @staticmethod
    def from_string(s):
        if s.startswith("postgres://"):
            logger.warning("Rewriting DB URI '%s' to 'postgresql://'", s)
            return "postgresql://" + s.removeprefix("postgres://")
        return s


@dataclass
class ConfigItem:
    """This class represents individual configuration settings. A
    `ConfigSchema` is basically a dictionary of `ConfigItem` instances.
    """

    name: str  # Name of the item
    type: type = str  # Type of the item
    convert: Callable[[str], builtins.type] = None  # Converts strings to type
    validate: Callable[[str, Any], None] = None  # Checks if value is valid
    default: Any = None  # Default value of item
    help: str = ""  # Help message string


class ConfigSchema:
    """This class represents a complete schema of configuration settings."""

    def __init__(self, schema=None, refuse_unknown=False):
        """Start a `ConfigSchema` instance. The `schema` passed into the
        constructor should be an iterable even though we store the schema
        internally as a dictionary in order to be able to find individual
        items more efficiently. If `refuse_unknown` is `True`, any items
        that are not in the schema will not validate.
        """
        self.schema = {s.name: s for s in schema} if schema is not None else {}
        self.refuse_unknown = refuse_unknown

    def find_item(self, key):
        """Returns the `ConfigItem` instance for the configuration item
        called `key` if it exists, otherwise `None`.
        """
        return self.schema.get(key, None)

    def check_item(self, key, value):
        """Converts a new value for a configuration item to the proper type
        (according to the `ConfigItem` data structure for the item) and
        also applies the validate function if one is defined for the item.
        We're only doing the type conversion if the type of the `value`
        parameter is `str`; if people are using different types in their
        configuration files we assume that they know what they're doing.
        """

        # Refuse non-schema configuration items if `refuse_unknown` is `True`,
        # otherwise just let them through as they are.
        item = self.schema.get(key, None)
        if item is None:
            if self.refuse_unknown:
                msg = f"Unknown configuration item '{key}'"
                raise LinOTPConfigKeyError(msg)
            return value
        # Make sure path-like items are strings, not `pathlib` paths.
        if key.endswith(("_DIR", "_FILE")):
            value = str(value)
        # If `value` is `str` but the schema wants non-`str`, do a
        # conversion, either using the function provided or the type itself.
        if item.type is not str and isinstance(value, str):
            value = (
                item.convert(value) if item.convert is not None else item.type(value)
            )
        # Validate the value if a validate function is registered
        if item.validate is not None:
            item.validate(key, value)
        return value

    def as_dict(self):
        """Return the names and default values of the schema as a dictionary.
        This is useful to populate the configuration with initial values
        without having to repeat any of the defaults.
        """
        return {item.name: item.default for item in self.schema.values()}

    def items(self):
        """Return the names and schema items of the schema as a dictionary
        (generator really). Note that this is similar but not identical to the
        `.as_dict()` method.
        """
        return self.schema.items()


_config_schema = ConfigSchema(
    [
        ConfigItem(
            "ROOT_DIR",
            str,
            default="",
            # `ROOT_DIR` defaults to `app.root_path` in `init_app()` below.
            validate=check_absolute_pathname(),
            help=(
                "The directory prepended to relative directory and file "
                "names in configuration files."
            ),
        ),
        ConfigItem(
            "BACKUP_DIR",
            str,
            default="backup",
            help=(
                "Directory for backup files created via e.g."
                "`linotp backup` or `linotp audit cleanup --export` commands"
            ),
        ),
        ConfigItem(
            "BACKUP_FILE_TIME_FORMAT",
            str,
            default="%Y-%m-%d_%H-%M",
            help=(
                "String that will be appended to various backup files "
                "in order to time-stamp them. Consult the "
                "`datetime.datetime.strftime()` documentation to find "
                "out about allowable `%` placeholders."
            ),
        ),
        ConfigItem(
            "CACHE_DIR",
            str,
            default="cache",
            help=(
                "Directory for miscellaneous caches. The actual "
                "caches go into subdirectories, e.g., `resolvers` "
                "for resolver caches and `beaker` for a file-based "
                "Beaker cache, in order to avoid namespace issues."
            ),
        ),
        ConfigItem(
            "ENABLE_CONTROLLERS",
            str,
            default="ALL",
            help=(
                "List of controllers to enabled: "
                "You can specify a different URL prefix by listing the "
                "controller as `FOO:/bar`, which will register it "
                "on `/bar` instead. "
                "The value 'ALL' will enable all controllers. "
                "Remark: "
                "Be aware that DISABLE_CONTROLLERS takes precedence over ENABLE_CONTROLLERS "
                "eg.: 'DISABLE_CONTROLLERS = foo' and 'ENABLE_CONTROLLERS = foo' will "
                "result in a disabled controller foo!"
            ),
        ),
        ConfigItem(
            "DISABLE_CONTROLLERS",
            str,
            default="gettoken",
            help=(
                "List of all disabled controllers. "
                "Remark: "
                "Be aware that DISABLE_CONTROLLERS takes precedence over ENABLE_CONTROLLERS "
                "eg.: 'DISABLE_CONTROLLERS = foo' and 'ENABLE_CONTROLLERS = foo' will "
                "result in a disabled controller foo!"
            ),
        ),
        ConfigItem(
            "TOKEN_MODULES",
            str,
            default="",
            help=(
                "Token support modules to enable. If this parameter is "
                "empty, all available token modules will be loaded."
            ),
        ),
        ConfigItem(
            "ADMIN_USERNAME",
            str,
            default="",
            help=("Administrator user name for 'cloud mode'."),
        ),
        ConfigItem(
            "ADMIN_PASSWORD",
            str,
            default="",
            help=("Administrator password for 'cloud mode'."),
        ),
        ConfigItem(
            "SESSION_COOKIE_SECURE",
            bool,
            convert=to_boolean,
            default=True,  # `False` in development mode
            help=(
                "Whether the session cookie will be marked “secure”. "
                "Set this to 'false' if you're running LinOTP on HTTP "
                "only (which you really shouldn't, certainly "
                "not in production)."
            ),
        ),
        ConfigItem(
            "LOGGING_LEVEL",
            str,
            validate=check_membership(VALID_LOG_LEVELS),
            default="WARNING",
            help=(
                "Deprecation Warning: Soon to be replaced with `LOG_LEVEL`!"
                "Messages will be logged only if they are at this level "
                "or above."
            ),
        ),
        ConfigItem(
            "LOG_LEVEL",
            str,
            validate=check_membership(VALID_LOG_LEVELS),
            default="WARNING",
            help=(
                "Messages will be logged only if they are at this level "
                "or above. You can also limit the logged messages via "
                "`LOG_FILE_LEVEL` and `LOG_CONSOLE_LEVEL`. Messages will "
                "only be logged to file/console if their level is greater or equal "
                "to both `LOG_LEVEL` and `LOG_FILE_LEVEL`/`LOG_CONSOLE_LEVEL`."
            ),
        ),
        ConfigItem(
            "LOG_CONSOLE_LEVEL",
            str,
            validate=check_membership(VALID_LOG_LEVELS),
            default="DEBUG",
            help=(
                "Messages will be written to the log file only if they "
                "are at this level or above and if this level >= `LOG_LEVEL`."
                "i.e., even if `LOG_CONSOLE_LEVEL` is more relaxed than "
                "`LOG_LEVEL`, only messages at `LOG_LEVEL` or "
                "above will be logged to the console."
            ),
        ),
        ConfigItem(
            "LOG_CONSOLE_LINE_FORMAT",
            str,
            default=("%(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"),
            help=(
                "Format for individual lines in the console log. "
                "This is the log which will usually be passed to "
                "journald or the container log."
                "Refer to the Python documentation for the details on "
                "log file format strings."
            ),
        ),
        ConfigItem(
            "LOG_FILE_LEVEL",
            str,
            validate=check_membership(VALID_LOG_LEVELS),
            default="DEBUG",
            help=(
                "Messages will be written to the log file only if they "
                "are at this level or above and if this level >= `LOG_LEVEL`."
                "i.e., even if `LOG_FILE_LEVEL` is more relaxed than "
                "`LOG_LEVEL`, only messages at `LOG_LEVEL` or "
                "above will be logged to the file."
            ),
        ),
        ConfigItem(
            "LOG_FILE_DIR",
            str,
            default="logs",
            help=(
                "Directory for log files. We're using a "
                "`RotatingFileHandler` to manage log files, and the main "
                "log file is written to `LOG_FILE_DIR/LOG_FILE_NAME`."
            ),
        ),
        ConfigItem(
            "LOG_FILE_NAME",
            str,
            default="linotp.log",
            help=(
                "Name for the main log file. We're using a "
                "`RotatingFileHandler` to manage log files, and the main "
                "log file is written to `LOG_FILE_DIR/LOG_FILE_NAME`."
            ),
        ),
        ConfigItem(
            "LOG_FILE_LINE_FORMAT",
            str,
            default=(
                "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
            ),
            help=(
                "Format for individual lines in the main log file. "
                "Refer to the Python documentation for the details on "
                "log file format strings."
            ),
        ),
        ConfigItem(
            "LOG_FILE_MAX_LENGTH",
            int,
            validate=check_int_in_range(min=0),
            default=10 * 1024 * 1024,
            help=("Log files will be rotated when they reach this length (in bytes)"),
        ),
        ConfigItem(
            "LOG_FILE_MAX_VERSIONS",
            int,
            validate=check_int_in_range(min=0),
            default=10,
            help=("Up to this many old log files will be kept."),
        ),
        ConfigItem(
            "LOG_LEVEL_DB_CLIENT",
            str,
            validate=check_membership(VALID_LOG_LEVELS),
            default="WARNING",
            help=(
                "Messages from the SQLAlchemy subsystem will be logged "
                "only if they are at this level or above."
            ),
        ),
        ConfigItem(
            "LOG_CONFIG",
            dict,
            convert=json.loads,
            default=None,
            help=(
                "You can completely redefine the LinOTP logging setup by "
                "passing a configuration dictionary in `LOG_CONFIG`. Do "
                "this only if you know what you are doing. The default "
                "value of `None`  enables a basic setup based on the "
                "`LOG_FILE_*` and `LOGGING_*` parameters."
            ),
        ),
        ConfigItem(
            "BEAKER_CACHE_TYPE",
            str,
            validate=check_membership({"memory", "file"}),
            default="memory",
            help=(
                "What type of Beaker cache to use (`memory` or `file`). "
                "For `file`, the cache will be in the `CACHE_DIR/beaker` "
                "directory. "
                "If you don't know what this does, you probably don't "
                "want to mess with it."
            ),
        ),
        ConfigItem(
            "SECRET_FILE",
            str,
            default="encKey",
            help=("Contains a server-specific encryption key."),
        ),
        ConfigItem(
            "DATABASE_URI",
            DBURI,
            convert=DBURI.from_string,
            default="sqlite:///{}",
            help=("Contains uri to your database."),
        ),
        ConfigItem(
            "SQLALCHEMY_TRACK_MODIFICATIONS",
            bool,
            convert=to_boolean,
            default=False,
            help=(
                "Controls signalling support in the database framework. "
                "This requires extra memory and LinOTP doesn't use it, "
                "so it's best to leave this setting alone."
            ),
        ),
        ConfigItem(
            "AUDIT_DATABASE_URI",
            DBURI,
            convert=DBURI.from_string,
            default="SHARED",
            help=(
                "Determines the method used for audit logging. Valid "
                "values are: `OFF` (no audit logs are generated, not "
                "recommended for production use), `SHARED` (audit logs "
                "are written to a table in the main LinOTP database as "
                "specified by `DATABASE_URI`, simple but not "
                "recommended for production use), or an SQLAlchemy "
                "database URI which specifies the database to be used. "
                "You need to ensure that the database exists and is "
                "accessed with the proper credentials and permissions."
            ),
        ),
        ConfigItem(
            "AUDIT_ERROR_ON_TRUNCATION",
            bool,
            convert=to_boolean,
            default=False,
            help=(
                "If set to `True`, having to truncate audit data to"
                "fit the database schema will be considered an error."
            ),
        ),
        ConfigItem(
            "AUDIT_PUBLIC_KEY_FILE",
            str,
            default="audit-public.pem",
            help=("The public key used for the audit log."),
        ),
        ConfigItem(
            "AUDIT_PRIVATE_KEY_FILE",
            str,
            default="audit-private.pem",
            help=("The private key used for the audit log."),
        ),
        ConfigItem(
            "CUSTOM_TEMPLATES_DIR",
            str,
            default=None,
            help=(
                "Directory for custom Mako templates (in addition to the "
                "ones provided by default)."
            ),
        ),
        ConfigItem(
            "MAKO_TRANSLATE_EXCEPTIONS",
            bool,
            convert=to_boolean,
            default=False,
            help=("Whether Mako should translate exceptions."),
        ),
        ConfigItem(
            "MAKO_DEFAULT_FILTERS",
            list,
            convert=lambda s: s.split(","),
            default=["h"],
            help=(
                "Default filters applied when Mako renders variables "
                "into templates. You will definitely want `h` here "
                "because not escaping HTML can lead to subtle security "
                "issues. You can add other values separated by commas "
                "but please, please, PLEASE do that only if you know "
                "what you're doing. Or, even better, don't do it at "
                "all."
            ),
        ),
        ConfigItem(
            "BABEL_TRANSLATION_DIRECTORIES",
            str,
            default="i18n",
            help=(
                "Where LinOTP will look for `*.mo` files for "
                "translations. This is actually a PATH-type sequence of "
                "directories in a string, separated by semicolons. "
                "(Don't blame us; it's a Flask-Babel thing.)"
            ),
        ),
        ConfigItem(
            "BABEL_DOMAIN",
            str,
            default="linotp",
            help=(
                "LinOTP message catalog files are called `linotp.mo`. "
                "Tweak this setting at your own risk."
            ),
        ),
        ConfigItem(
            "HELP_URL",
            str,
            default="https://linotp.org/doc/{0}/index.html",
            help=(
                "Where the LinOTP online help may be found. A `{0}` will "
                "be replaced with the major version number of the "
                "running LinOTP instance. (If there is no `{0}` in the "
                "URL that is not a big deal.) You can change this, but "
                "if you know a better place to get LinOTP help than the "
                "default value then by all means let us know about it; "
                "we might want to offer whomever wrote it a job."
            ),
        ),
        ConfigItem(
            "SITE_ROOT_REDIRECT",
            str,
            default="",
            help=(
                "Configure an alternative URL path to get redirected "
                'to if the site root path ("/") is opened. If not '
                "configured, the user will be redirected to the "
                "selfservice controller."
            ),
        ),
        ConfigItem(
            "TRUSTED_PROXIES",
            list,
            convert=lambda s: s.split(",") if s else [],
            default=[],
            help=(
                "Comma-separated list of IP host and network addresses"
                " for proxies which are trusted to provide reliable "
                "`X-Forwarded-For` headers."
            ),
        ),
        ConfigItem(
            "GET_CLIENT_ADDRESS_FROM_POST_DATA",
            bool,
            convert=to_boolean,
            default=True,
            help=(
                "Various LinOTP API endpoints allow requests from "
                "certain IP addresses to pass a `client=` parameter "
                "in HTTP POST data that gives the “real” client address. "
                "This feature is deprecated but if you need it for "
                "your own code, you can enable it here for the time "
                "being."
            ),
        ),
        ConfigItem(
            "MAINTENANCE_VERIFY_CLIENT_ENV_VAR",
            str,
            default="",
            help=(
                "The maintenance controller can be configured to only "
                "serve responses to clients that offer a valid client "
                "certificate. If set, we will check that this variable "
                "exists before processing a request. For Apache, a "
                "useful value might be `SSL_CLIENT_S_DN_CN`."
            ),
        ),
        ConfigItem(
            "RADIUS_NAS_IDENTIFIER",
            str,
            default="LinOTP",
            help=(
                "A RADIUS identifier to support outgoing RADIUS requests "
                "like in RADIUS token or with policy forwarding server "
                "to RADIUS server. If you don't understand the previous "
                "sentence you are in good company."
            ),
        ),
        ConfigItem(
            "TLS_CA_CERTIFICATES_FILE",
            str,
            default="/etc/ssl/certs/ca-certificates.crt",
            help=(
                "The file that holds root-level CA certificates for "
                "validating the TLS certificates of remote nodes. See "
                "the OpenSSL verify(1) manual page for more information. "
                "Do not change this unless you know what you are "
                "doing."
            ),
        ),
        # Some configuration items for JWT authentication (mostly from
        # https://flask-jwt-extended.readthedocs.io/en/stable/options/).
        # We include them here to make them accessible for configuration
        # via the environment, and could add more as needed.
        ConfigItem(
            "JWT_TOKEN_LOCATION",
            str,
            default="cookies",
            help=(
                "Where the JWT authentication tokens are stored in an "
                "HTTP request or reply. Do not change this unless you "
                "know what you are doing."
            ),
        ),
        ConfigItem(
            "JWT_SESSION_COOKIE",
            bool,
            convert=to_boolean,
            default=False,
            help=(
                "Whether the JWT access cookies will be created as session "
                "cookies, which are deleted when the browser is closed. "
                "Set this to 'true' if you want sessions to not survive "
                "when the user re-opens the browser."
            ),
        ),
        ConfigItem(
            "JWT_ACCESS_TOKEN_EXPIRES",
            int,
            validate=check_int_in_range(min=0),
            default=30 * 60,  # 30 minutes
            help=(
                "How long JWT access tokens will be valid, in seconds "
                "from when they are first issued. Note that a value "
                'of "0" means "indefinitely", and that should probably '
                "be avoided."
            ),
        ),
        # Note: This is not an official Flask-JWT-Extended configuration item.
        ConfigItem(
            "JWT_ACCESS_TOKEN_REFRESH",
            int,
            validate=check_int_in_range(min=0),
            default=5 * 60,  # 5 minutes
            help=(
                "If the JWT access token of a request is less than "
                "this number of seconds away from expiring, it is "
                "automatically refreshed at the end of the request. "
                "(If the user never does anything before their access "
                "token expires, no refresh will take place.) "
                'A value of "0" means JWT access tokens will not be '
                "refreshed automatically, i.e., they will expire and "
                "users will have to re-authenticate from scratch."
            ),
        ),
        ConfigItem(
            "JWT_SECRET_ITERATIONS",
            int,
            validate=check_int_in_range(min=1),
            default=500000,
            help=(
                "Number of iterations used in the PBKDF2 function for "
                "the JWT_SECRET_KEY. Note that we're doing this only "
                "once per LinOTP run, so don't skimp. Also note that "
                "tweaking this and restarting LinOTP will invalidate "
                "all outstanding JWTs."
            ),
        ),
        ConfigItem(
            "JWT_CSRF_CHECK_FORM",
            bool,
            convert=to_boolean,
            default=True,
            help=(
                "Controls if form data should also be check for the "
                "CSRF double submit token."
                "This is usefull for sending requests which need a "
                "file to be downloaded by the user as their response"
            ),
        ),
        ConfigItem(
            "JWT_BLACKLIST_ENABLED",
            bool,
            convert=to_boolean,
            default=True,
            help=(
                "This enforces a check on bl(o)ck listed jwt tokens"
                "These or jwt tokens which are blocklisted e.g. on logout"
                "A blocklist check function should also be decorated by"
                "@jwt.token_in_blocklist_loader to check tokens in blocklist"
            ),
        ),
        ConfigItem(
            "ADMIN_REALM_NAME",
            str,
            default="linotp_admins",
            help=(
                "The name of the realm that contains the resolvers for "
                "the LinOTP administrators."
            ),
        ),
        ConfigItem(
            "ADMIN_RESOLVER_NAME",
            str,
            default="LinOTP_local_admins",
            help=(
                "The name of the internal admin resolver that"
                "is managed by the 'linotp admins' cli tool."
            ),
        ),
        ConfigItem(
            "ACTIVE_SECURITY_MODULE",
            str,
            default="default",
            help=(
                "The active security module is used to support hardware "
                "security modules (HSM) via pkcs#11. A HSM performes the "
                "encryption and decryption on the hardware itself. "
                "Therefore the key will not leave the hardware. "
                "The default security module will use no HSM. It "
                "implements a concept of a security module abstraction "
                "layer i.e. even the old encryption key stored at "
                "/etc/linotp2/encKey now is handled via a security "
                "module. In LinOTP token secrets, configuration values, and general "
                "values are protected by encryption."
                "Possible values: default, pkcs11"
            ),
        ),
        ConfigItem(
            "HSM_DEFAULT_CONFIG",
            dict,
            convert=json.loads,
            default={
                "module": "linotp.lib.security.default.DefaultSecurityModule",
                "tokenHandle": provider.TOKEN_KEY,
                "configHandle": provider.CONFIG_KEY,
                "valueHandle": provider.VALUE_KEY,
                "defaultHandle": provider.DEFAULT_KEY,
                "poolsize": 20,
                "crypted": "FALSE",
                # 'file': config['SECRET_FILE'], will be added in provider.py
            },
            help=("The default security provider configuration"),
        ),
        ConfigItem(
            "HSM_PKCS11_CONFIG",
            dict,
            convert=json.loads,
            default={
                "module": "linotp.lib.security.pkcs11.Pkcs11SecurityModule",
                "library": "libCryptoki2_64.so",
                "password": "<your password>",
                "slotid": 0,
                "configLabel": "",
                "tokenLabel": "",
                "valueLabel": "",
                "defaultLabel": "default",
                "configHandle": None,
                "tokenHandle": None,
                "valueHandle": None,
                "defaultHandle": None,
                "poolsize": 10,
            },
            validate=check_json_schema(Pkcs11SecurityModule.schema),
            help=(
                "The PKCS11 config defines the configuration for "
                "a hsm compatible with the pkcs11 api. For example you "
                "can use `SafeNet LunaSA` or `softhsm2`. This config "
                "has to be given as python dict. The following key / "
                "value pairs are available: "
                "`module` is the python module used. i.e. "
                "linotp.lib.security.pkcs11.Pkcs11SecurityModule. "
                "`library` is the PKCS11 library file (so). "
                "`password` of the PKCS11 slot aka. the "
                "smartcard PIN."
                "`slotid` is the slot where the AES keys are "
                "located. In case of the LunaSA this is the partition. "
                "You can check for the slot number by issuing the "
                "command `vtl verify`. In case of softhsm2 it is the "
                "slotid which can be checked by `softhsm2-util --shows`. "
                "`configHandle`, `valueHandle`, `tokenHandle` and "
                "`defaultHandle` are the handles of token in the hsm for "
                "a slot which holds in our case an AES key objects. "
                "If one of the parameters (configHandle, valueHandle, "
                "tokenHandle) is missing, the defaultHandle is used. "
                "`configLabel`, `valueLabel`, `tokenLabel`, and"
                "`defaultLabel` are used to refer to a token, in the hsm "
                "for a slot, by name. If a label is set, "
                "it will override the given handle entry i.e. configLabel "
                "will override configHandle. "
                "For more information check the LinOTP documenation at "
                "https://linotp.org/doc/latest/part-installation/"
                "HSM/defining_lunasa.html"
            ),
        ),
        ConfigItem(
            "PROFILE",
            bool,
            convert=to_boolean,
            default=False,
            help=(
                "Whether profiling is enabled for WSGI requests. This "
                "is only interesting for LinOTP developers. Do not use "
                "it in production or you will regret it."
            ),
        ),
    ]
)


# This will become the static `init_app()` method of the `Config` class.
# By the time this method is called, the `app` is known, and we can associate
# the `_config_schema` with the `app` without ever having to mention the
# `_config_schema` variable outside this file. We also pretend that the
# `ROOT_DIR` setting falls from the sky to match the Flask `app.root_path`,
# which is only known dynamically and therefore can't be added to the
# `ConfigItem` directly; it can of course still be overridden in explicit
# configuration or an environment variable.


def _init_app(app):
    app.config.set_schema(_config_schema)
    root_dir = _config_schema.find_item("ROOT_DIR")
    root_dir.default = app.config["ROOT_DIR"] = app.root_path


# This is equivalent to a `class Config:` definition, but the attributes
# are taken from the `_config_schema`. Devious. The advantage of this
# approach is that Flask still thinks we've written a standard `Config`
# class as per the book, when in fact we're taking advantage of the
# schema-based setup outlined above. This helps us because (a) we know
# what types our `ConfigItem` instances are supposed to have, so we can
# specify everything as strings (e.g., in environment variables) and still
# end up with `int`s in the actual settings (for an extreme - but cool -
# example, check out `LOG_CONFIG` above), and (b) it's a lot easier to
# auto-generate commented sample configuration files from the schema than
# it would be from Python code, so we save ourselves from getting into a
# situation where a traditional Flask `Config` class and the sample config
# file would have to be synchronised by hand.
#
# Don't let yourself be confused by the apparent strangeness of Flask
# using the `.from_object()` method to read configuration items from
# the likes of `Config` or `DevelopmentConfig`, which are obviously
# *classes*.  Remember that in Python, classes are objects, too, and
# you don't need to instantiate them to get at their attributes. This
# is incidentally why we need to use the three-argument `type()` trick
# in the first place; if we used a `Config.__init__()` method to copy
# the `_config_schema` defaults into `Config` object attributes, that
# wouldn't work because `Config` is actually never instantiated, so
# its `__init__()` method would never be called. The three-argument
# `type` puts the `_config_schema` dictionary entries (keys and
# default values) directly in the *class*, so they are available when
# we look at `Config` even without instantiating it first.
#
# Finally, the `staticmethod` function, for those who don't remember
# pre-2.4 versions of Python, is the same as the `@staticmethod`
# decorator. This lets us make a static method within `Config` from
# the `_init_app()` function we defined above.

_attrs = {"init_app": staticmethod(_init_app)}
_attrs.update(_config_schema.as_dict())
Config = type("Config", (object,), _attrs)


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    LOG_LEVEL = "DEBUG"
    LOG_FILE_LEVEL = LOG_LEVEL
    DATABASE_URI = "sqlite:///" + os.path.join(basedir, "linotp-dev.sqlite")


class TestingConfig(Config):
    TESTING = True
    SESSION_COOKIE_SECURE = False
    LOG_LEVEL = "DEBUG"
    DATABASE_URI = "sqlite:///" + os.path.join(basedir, "linotp-test.sqlite")


class ProductionConfig(Config):
    SESSION_COOKIE_SECURE = True
    DATABASE_URI = "sqlite:///" + os.path.join(basedir, "linotp.sqlite")


configs = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


# ----------------------------------------------------------------------
# CLI commands
# ----------------------------------------------------------------------

config_cmds = AppGroup("config", help="Show LinOTP configuration")


@config_cmds.command("show", help="Output current configuration settings.")
@click.option(
    "--modified",
    "-m",
    is_flag=True,
    help="Show only items whose values differ from their defaults.",
)
@click.option(
    "--values",
    "-V",
    is_flag=True,
    help="Show only values of items, not their names.",
)
@click.argument("items", nargs=-1)
def config_show_cmd(modified, values, items=None):
    """Show the current configuration settings."""

    schema = current_app.config.config_schema
    for k, v in sorted(current_app.config.items()):
        display = not items or k in items
        if modified and display:
            item = schema.find_item(k)
            display = item is not None and v != item.default
        if display:
            click.echo(("" if values else f"{k}=") + str(current_app.config[k]))


SAMPLE_CFG_BANNER = """# This is a sample LinOTP configuration file.
# It contains {0} configuration settings with their hard-coded
# defaults. Feel free to copy this file and uncomment and edit any of
# these (with appropriate caution). The LINOTP_CFG environment variable
# can be used to specify a list of LinOTP configuration files which
# will be read in order (the last encountered value for any configuration
# setting wins.) On many installations, a good place for your own
# configuration settings is /etc/linotp/linotp.cfg.
"""


@config_cmds.command("explain", help="Describe configuration settings in detail.")
@click.option(
    "--sample-file",
    is_flag=True,
    help='Show items in "configuration file" format.',
)
@click.option(
    "--banner/--no-banner",
    default=True,
    help='Show explanatory note at start of "configuration file"',
)
@click.argument("items", nargs=-1)
def config_explain_cmd(sample_file, banner, items=None):
    """Explain configuration settings in the schema."""

    schema = current_app.config.config_schema
    if sample_file and banner:
        print(SAMPLE_CFG_BANNER.format("all available" if not items else "some"))
    if not items:
        items = schema.as_dict().keys()
    for name in items:
        item = schema.find_item(name)
        if item is None:
            click.echo(f"No information on {name}")
        elif sample_file:
            description = f"{item.name}: {item.help}"
            print(
                textwrap.fill(description, initial_indent="# ", subsequent_indent="# ")
            )
            if item.validate is not None and hasattr(item.validate, "__doc__"):
                print(f"#\n# Constraints: {item.validate.__doc__}")
            print(f"\n## {item.name} = {item.default!r}\n")
        else:
            click.echo(f"{item.name}:")
            click.echo(f"  Type: {item.type.__qualname__}")
            if item.validate is not None and hasattr(item.validate, "__doc__"):
                click.echo(f"  Constraints: {item.validate.__doc__}")
            click.echo(f"  Default value: {item.default}")
            click.echo(f"  Current value: {current_app.config[item.name]}")
            description = f"  Description: {item.help}"
            click.echo(
                textwrap.fill(description, initial_indent="", subsequent_indent="    ")
            )

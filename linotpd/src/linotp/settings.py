
import logging
import os

basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class Config:
    # List all enabled controllers. Any controller `FOO` mentioned
    # here will be imported from `linotp3.controllers.FOO`, and a
    # blueprint named `FOO_controller` will be registered on `/FOO`.
    # You can specify a different URL prefix by listing the controller
    # as `FOO:/bar`, which will register it on `/bar` instead.

    CONTROLLERS = ("admin auth manage selfservice system "
                   "test tools maintenance validate userservice")

    # List all enabled token support modules. If this parameter is
    # empty, all available token modules will be loaded.

    TOKEN_MODULES = ""

    # We're using a `RotatingFileHandler` to manage log files. The
    # main log file is written to `LOGFILE_DIR/LOGFILE_NAME`, with one
    # message per line formatted as per `LOGFILE_FILE_LINE_FORMAT`,
    # and a new log file will be started once the current log file is
    # `LOGFILE_MAX_LENGTH` bytes long. We will keep up to
    # `LOGFILE_MAX_VERSIONS` old log files; older ones will be deleted
    # as newer ones get rotated in.

    LOGFILE_DIR = os.path.join(os.path.dirname(basedir), "logs")
    LOGFILE_FILE_LINE_FORMAT = (
        "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
    )
    LOGFILE_MAX_LENGTH = 10240
    LOGFILE_MAX_VERSIONS = 10
    LOGFILE_NAME = "linotp3.log"

    # LOGGING_FILE_LEVEL determines which messages are written to the log
    # file, while LOGGING_LEVEL determines which messages are logged in
    # general.
    #
    # Messages must clear LOGGING_LEVEL first before LOGGING_FILE_LEVEL comes
    # to bear. In other words, even if LOGGING_FILE_LEVEL is more relaxed
    # than LOGGING_LEVEL, only messages at LOGGING_LEVEL or above will be
    # logged to the file.

    LOGGING_LEVEL = logging.WARNING
    LOGGING_FILE_LEVEL = logging.INFO
    LOGGING_LEVEL_ALEMBIC = logging.DEBUG

    # You can completely redefine the logging setup by passing a
    # configuration dictionary in `LOGGING`.

    LOGGING = None

    # Directory for configuration files
    ROOT_DIR = basedir

    SECRET_FILE = os.path.join(ROOT_DIR, "encKey")

    # MAKO_TRANSLATE_EXCEPTIONS = False

    # Where the online help can be found. The `{0}` will be replaced
    # with the major version number of this LinOTP instance. (If there
    # is no `{0}` in the URL that is not a big deal.)

    HELP_URL = "https://linotp.org/doc/{0}/index.html"

    # The maintenance controller can be configured to only serve responses
    # to clients that serve a valid certificate. If set, we will check the
    # existence of this variable before serving maintenence requests.
    #
    # For apache, set this to SSL_CLIENT_S_DN_CN.
    # Default: No checking
    MAINTENANCE_VERIFY_CLIENT_ENV_VAR = None

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    LOGGING_LEVEL = logging.DEBUG
    LOGGING_FILE_LEVEL = LOGGING_LEVEL
    SQLALCHEMY_DATABASE_URI = os.getenv("LINOTP_DEV_DATABASE_URL") or \
        "sqlite:///" + os.path.join(basedir, "linotp-dev.sqlite")


class TestingConfig(Config):
    TESTING = True
    SESSION_COOKIE_SECURE = False
    LOGGING_LEVEL = logging.DEBUG
    SQLALCHEMY_DATABASE_URI = os.getenv("LINOTP_TEST_DATABASE_URL") or \
        "sqlite:///" + os.path.join(basedir, "linotp-test.sqlite")


class ProductionConfig(Config):
    SESSION_COOKIE_SECURE = True
    SQLALCHEMY_DATABASE_URI = os.getenv("LINOTP_DATABASE_URL") or \
        "sqlite:///" + os.path.join(basedir, "linotp.sqlite")


configs = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig,
}

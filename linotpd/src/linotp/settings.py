
import logging
import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # List all enabled controllers. Any controller `FOO` mentioned
    # here will be imported from `linotp3.controllers.FOO`, and a
    # blueprint named `FOO_controller` will be registered on `/FOO`.
    # You can specify a different URL prefix by listing the controller
    # as `FOO:/bar`, which will register it on `/bar` instead.

    CONTROLLERS = "admin manage system validate"

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

    ROOT_DIR = basedir

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    LOGGING_LEVEL = logging.DEBUG
    LOGGING_FILE_LEVEL = LOGGING_LEVEL
    SQLALCHEMY_DATABASE_URI = os.getenv("LINOTP_DEV_DATABASE_URL") or \
        "sqlite:///" + os.path.join(basedir, "linotp-dev.sqlite")


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv("LINOTP_TEST_DATABASE_URL") or \
        "sqlite:///" + os.path.join(basedir, "linotp-test.sqlite")


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.getenv("LINOTP_DATABASE_URL") or \
        "sqlite:///" + os.path.join(basedir, "linotp.sqlite")


configs = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig,
}

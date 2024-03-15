import functools
import logging
from datetime import datetime

from linotp.flap import request
from linotp.model import db
from linotp.model.db_logging import LoggingConfig


def init_logging_config():
    """
    Loads the persistent logging configuration from the database

    Should be called ONCE at the start of the server
    """

    config_entries = LoggingConfig.query.all()

    for config_entry in config_entries:
        logger = logging.getLogger(config_entry.name)
        logger.setLevel(config_entry.level)


# ------------------------------------------------------------------------------

# helper functions

# --------------------------------------------------------------------------


def log_request_timedelta(logger):
    """
    this function logs the time delta between the start and
    the end of the request and should be called at the end.

    :param logger: The logger that should be used
    """

    start = request.environ.get("REQUEST_START_TIMESTAMP")

    if start is None:
        return

    stop = datetime.now()
    delta_sec = (stop - start).total_seconds()

    extra = {"type": "request_timedelta", "timedelta": delta_sec}

    logger.debug("Spent %f seconds for request" % delta_sec, extra=extra)


# ------------------------------------------------------------------------------

# function decorators

# ------------------------------------------------------------------------------


def log_enter_exit(logger):
    """
    A decorator that logs entry and exit points of the function it
    decorates. By default all function arguments and return values
    are logged.

    :param logger: The logger object that should be used
    """

    enter_str = "Entered function %s"
    exit_str = "Exited function %s"

    def _inner(func):
        @functools.wraps(func)
        def log_and_call(*args, **kwargs):
            # --------------------------------------------------------------

            extra = {
                "type": "function_enter",
                "function_name": func.__name__,
                "function_args": args,
                "function_kwargs": kwargs,
            }

            logger.debug(enter_str % func.__name__, extra=extra)

            # --------------------------------------------------------------

            returnvalue = func(*args, **kwargs)

            # --------------------------------------------------------------

            extra = {
                "type": "function_exit",
                "function_name": func.__name__,
                "function_returnvalue": returnvalue,
            }

            logger.debug(exit_str % func.__name__, extra=extra)

            # --------------------------------------------------------------

            return returnvalue

            # --------------------------------------------------------------

        return log_and_call

    return _inner


# --------------------------------------------------------------------------


def log_timedelta(logger):
    """
    Decorator to log time spent in processing a function
    from its entry point to its return.

    :param logger: The logger object that should be used
    """

    def _inner(func):
        @functools.wraps(func)
        def _log_time(*args, **kwargs):
            # --------------------------------------------------------------

            start = datetime.now()
            returnvalue = func(*args, **kwargs)
            stop = datetime.now()
            delta_sec = (stop - start).total_seconds()

            extra = {
                "type": "function_timedelta",
                "function_name": func.__name__,
                "timedelta": delta_sec,
            }

            logger.debug(
                "Spent %f seconds in %s" % (delta_sec, func.__name__),
                extra=extra,
            )

            # --------------------------------------------------------------

            return returnvalue

            # --------------------------------------------------------------

        return _log_time

    return _inner


# --------------------------------------------------------------------------


def set_logging_level(name, level):
    """
    sets the logging level in the database as well as
    in the current running logger

    :param name: Name of the logger
    :param level: New level (must be integer)
    """

    # --------------------------------------------------------------------------

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # --------------------------------------------------------------------------

    config_entry = LoggingConfig.query.get(name)

    if config_entry is None:
        new_config_entry = LoggingConfig(name, level)
        db.session.add(new_config_entry)
        return

    config_entry.level = level

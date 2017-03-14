import functools
import logging

from datetime import datetime
from linotp.model.meta import Session
from linotp.model import LoggingConfig

from pylons import request

# ------------------------------------------------------------------------------


class RequestContextFilter(logging.Filter):

    """
    Adds request specific information to every record, so individual
    requests and ip addresses can be backtraced. The following data
    is added:

    * request_id    An id that is unique per request and is generated
                    at the start of every request.

    * remote_addr   The ip address from which the request originated

    """

    def filter(self, record):

        try:
            env = request.environ
        except TypeError:
            # logging is also done, when there is no request object present
            # (for example on server start). in this case an access to
            # the request thread local would raise a TypeError.
            # we set env to an empty dictionary so the values get
            # set to None. (we need them to be present, so we can
            # use request_id in the format strings without provoking
            # an error)
            env = {}

        record.request_id = env.get('REQUEST_ID')
        record.remote_addr = env.get('REMOTE_ADDR')
        record.request_path = env.get('PATH_INFO')
        as_datetime = env.get('REQUEST_START_TIMESTAMP')

        if as_datetime is not None:
            basic_time = as_datetime.strftime("%Y-%m-%dT%H:%M:%S")
            ms = ".%03d" % (as_datetime.microsecond / 1000)
            record.request_start_timestamp = basic_time + ms + "Z"

        return True

# ------------------------------------------------------------------------------

BG_COLOR_START = '\033[48;5;%dm'
BG_COLOR_STOP = '\033[0m'


class ColorFormatter(logging.Formatter):

    ORANGE = BG_COLOR_START % 166
    YELLOW = BG_COLOR_START % 178
    BLUE = BG_COLOR_START % 69
    RED = BG_COLOR_START % 160
    LAVENDER = BG_COLOR_START % 13

    LEVEL_COLORS = {
        'WARNING': YELLOW,
        'INFO': BLUE,
        'DEBUG': LAVENDER,
        'CRITICAL': ORANGE,
        'ERROR': RED
    }

    def format(self, record):
        levelname = record.levelname
        if levelname in self.LEVEL_COLORS:
            colored = self.LEVEL_COLORS[levelname] + levelname + BG_COLOR_STOP
            record.levelname = colored
        return logging.Formatter.format(self, record)

# ------------------------------------------------------------------------------


def init_logging_config():

    """
    Loads the persistent logging configuration from the database,
    sets the appropriate mappers (to enrich results with request
    ids, remote addresses, etc) and adds the handler defined in
    the global configuration.

    Should be called ONCE at the start of the server
    """

    root_logger = logging.getLogger()

    for handler in root_logger.handlers:
        filter_ = RequestContextFilter()
        handler.addFilter(filter_)

    config_entries = Session.query(LoggingConfig).all()

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

    start = request.environ.get('REQUEST_START_TIMESTAMP')

    if start is None:
        raise Exception('Request start was not registered. Profiling '
                        'not possible')

    stop = datetime.now()
    delta_sec = (stop - start).total_seconds()

    extra = {
        'type': 'request_timedelta',
        'timedelta': delta_sec
    }

    logger.debug('Spent %f seconds for request' % delta_sec, extra=extra)


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

    enter_str = 'Entered function %s'
    exit_str = 'Exited function %s'

    def _inner(func):

        @functools.wraps(func)
        def log_and_call(*args, **kwargs):

            # --------------------------------------------------------------

            extra = {
                'type': 'function_enter',
                'function_name': func.__name__,
                'function_args': args,
                'function_kwargs': kwargs
            }

            logger.debug(enter_str % func.__name__, extra=extra)

            # --------------------------------------------------------------

            returnvalue = func(*args, **kwargs)

            # --------------------------------------------------------------

            extra = {
                'type': 'function_exit',
                'function_name': func.__name__,
                'function_returnvalue': returnvalue
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
                'type': 'function_timedelta',
                'function_name': func.__name__,
                'timedelta': delta_sec
            }

            logger.debug('Spent %f seconds in %s' % (delta_sec, func.__name__),
                         extra=extra)

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

    config_entry = Session.query(LoggingConfig).get(name)

    if config_entry is None:
        new_config_entry = LoggingConfig(name, level)
        Session.add(new_config_entry)
        return

    config_entry.level = level

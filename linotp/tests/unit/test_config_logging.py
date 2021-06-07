# Unit tests for the logging configuration
#
# This tests the configuration parameters LOGGING_LEVEL, LOGGING_FILE_LEVEL,
# and LOGGING_CONSOLE_LEVEL.

import logging

import pytest

from linotp.app import init_logging


@pytest.mark.parametrize("ll,lfl,lcl,use_lvl,to_log,to_file,to_console", [
    # `ll` is `LOGGING_LEVEL`; a message must clear this to be logged at all.
    # `lfl` and `lcl` are `LOGGING_FILE_LEVEL` and `LOGGING_CONSOLE_LEVEL`;
    # messages meant for the log file or console must clear these once
    # they have cleared `LOGGING_LEVEL`.
    # `use_lvl`, which must be numeric, is the log level to be used for
    # the test message.
    # `to_log`, `to_file`, and `to_console` specify whether we expect the
    # message to show up in the log mechanism, in the log file, or on the
    # console, respectively.

    ("DEBUG", "DEBUG", "DEBUG", logging.DEBUG, True, True, True),
    ("DEBUG", "DEBUG", "WARNING", logging.DEBUG, True, True, False),
    ("DEBUG", "DEBUG", "WARNING", logging.WARNING, True, True, True),
    ("DEBUG", "WARNING", "DEBUG", logging.DEBUG, True, False, True),
    ("DEBUG", "WARNING", "DEBUG", logging.WARNING, True, True, True),
    ("DEBUG", "WARNING", "WARNING", logging.DEBUG, True, False, False),
    ("DEBUG", "WARNING", "WARNING", logging.WARNING, True, True, True),
    ("WARNING", "DEBUG", "DEBUG", logging.DEBUG, False, False, False),
    ("WARNING", "DEBUG", "DEBUG", logging.WARNING, True, True, True),
    ("INFO", "DEBUG", "WARNING", logging.DEBUG, False, False, False),
    ("INFO", "DEBUG", "WARNING", logging.INFO, True, True, False),
    ("INFO", "DEBUG", "WARNING", logging.WARNING, True, True, True),
    ("INFO", "WARNING", "DEBUG", logging.DEBUG, False, False, False),
    ("INFO", "WARNING", "DEBUG", logging.INFO, True, False, True),
    ("INFO", "WARNING", "DEBUG", logging.WARNING, True, True, True),
])
def test_logging_levels(capsys, caplog, tmp_path,
                        app, ll, lfl, lcl, use_lvl,
                        to_log, to_file, to_console):
    log_dir = tmp_path
    log_file = log_dir / app.config["LOGFILE_NAME"]
    log_file.write_text("")     # Ensure file exists

    app.config["LOGFILE_DIR"] = str(log_dir)
    app.config["LOGGING_LEVEL"] = ll
    app.config["LOGGING_FILE_LEVEL"] = lfl
    app.config["LOGGING_CONSOLE_LEVEL"] = lcl
    app.config["LOGGING"] = None
    init_logging(app)           # Enact the configuration
    caplog.clear()
    MESSAGE = "foo bar baz"
    app.logger.log(use_lvl, MESSAGE)

    if to_log:                  # Message should show up in log
        assert len(caplog.messages) == 1
        assert MESSAGE in caplog.messages[0]
    else:
        assert len(caplog.messages) == 0

    if to_file:                 # Message should show up in log file
        assert log_file.exists()
        assert MESSAGE in log_file.read_text()
    else:
        assert log_file.exists()
        assert MESSAGE not in log_file.read_text()

    captured = capsys.readouterr()
    if to_console:              # Message should show up on stderr
        assert MESSAGE in captured.err
    else:
        assert MESSAGE not in captured.err

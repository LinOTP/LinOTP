#!/usr/bin/python3
# Waits for the database to become available (or an error to occur).

import sys

from sqlalchemy import create_engine
from sqlalchemy.exc import NoSuchModuleError, OperationalError

MESSAGES_INDICATING_BOOTING_DB = (
    "name or service not known",
    "is the server running on that host",
    "the database system is starting up",
)

SUCCESS = 0
CONTINUE = 1
ABORT = 2
UNKNOWN = 3


def punt(code, message):
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(code)


database_uri = sys.argv[1]

try:
    engine = create_engine(database_uri)
    engine.connect()
except (NoSuchModuleError, OperationalError) as ex:
    err_msg = str(ex).lower()
    if any(msg in err_msg for msg in MESSAGES_INDICATING_BOOTING_DB):
        # Continue -- this might resolve soon (when the container
        # starts and is healthy)
        print(err_msg, file=sys.stderr)
        sys.exit(CONTINUE)
    if "password authentication failed" in err_msg:
        punt(ABORT, "Invalid credentials for user in LINOTP_DATABASE_URI")
    if "access denied" in err_msg:
        punt(ABORT, "Insufficient rights for user in LINOTP_DATABASE_URI")
    if "failed: fatal" in err_msg and "does not exist" in err_msg:
        punt(ABORT, "Given database name does not exist in LINOTP_DATABASE_URI")
    if "t load plugin: sqlalchemy.dialects:" in err_msg:
        punt(ABORT, "Invalid dialect in LINOTP_DATABASE_URI")
    punt(UNKNOWN, f"Unexpected Error: {err_msg}")
except Exception as ex:
    err_msg = str(ex).lower()
    punt(UNKNOWN, f"Unexpected Error: {err_msg}")

sys.exit(SUCCESS)

#!/usr/bin/python

import os

from linotp.app import create_app

app = create_app(os.getenv("LINOTP_CONFIG") or os.getenv("FLASK_ENV") or "default")

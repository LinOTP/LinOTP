#!/usr/bin/env python3

import os
from linotp.app import create_app

application = create_app("production")

## To enable the interactive debugger uncomment
## the following lines. You can find the debugger PIN in
## the apache error logfile.
## do _not_ enable this on a regular production system
## https://werkzeug.palletsprojects.com/en/0.15.x/debug/#debugger-pin
# from werkzeug.debug import DebuggedApplication
# application = DebuggedApplication(application.wsgi_app, True)

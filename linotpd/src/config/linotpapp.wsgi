#!/usr/bin/env python3

import os
from linotp.app import create_app

# We're assuming that there are distribution defaults in
# /usr/share/linotp/linotp.cfg and local adaptations in
# /etc/linotp/linotp.cfg.

cfg_files = (
    "/usr/share/linotp/linotp.cfg",
    "/etc/linotp/linotp.cfg",
)
os.environ['LINOTP_CFG'] = ":".join(cfg_files)

# Relative paths in the linotp.cfg files will be taken as
# relative to /etc/linotp

os.environ['LINOTP_ROOT_DIR'] = os.path.dirname(cfg_files[-1])

application = create_app('production')

## To enable the interactive debugger uncomment
## the following lines. You can find the debugger PIN in
## the apache error logfile.
## do _not_ enable this on a regular production system
## https://werkzeug.palletsprojects.com/en/0.15.x/debug/#debugger-pin
# from werkzeug.debug import DebuggedApplication
# application = DebuggedApplication(application.wsgi_app, True)

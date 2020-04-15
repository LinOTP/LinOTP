#!/usr/bin/env python3
import os
from linotp.app import create_app

root_dir = os.path.abspath(os.path.dirname(__file__))

conf = {
    'LOGFILE_DIR': '/var/log/linotp',
    'ROOT_DIR': root_dir,
}

# Configure from files in the same directory as this wsgi file:
# linotp.cfg - new style config
# linotp.ini - old style config
os.environ['LINOTP_CONFIG_FILE'] = os.path.join(root_dir, 'linotp.cfg')
os.environ['LINOTP_INI_FILE'] = os.path.join(root_dir, 'linotp.ini')

application = create_app('production', config_extra=conf)

## To enable the interactive debugger uncomment
## the following lines. You can find the debugger PIN in
## the apache error logfile.
## do _not_ enable this on a regular production system
## https://werkzeug.palletsprojects.com/en/0.15.x/debug/#debugger-pin
# from werkzeug.debug import DebuggedApplication
# application = DebuggedApplication(application.wsgi_app, True)

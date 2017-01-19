from linotp.lib.config import getFromConfig
from linotp.lib.base import BaseController
from linotp.lib.logs import set_logging_level
from linotp.model.meta import Session
from pylons import request
from pylons.controller.util import abort


class MaintenanceController(BaseController):

    """
    The maintenance controller is an internal interface
    for maintainers to change certain parameters (such as
    log levels) at runtime
    """

    def setLogLevel(self):

        """
        set the log level of a certain logger which is identified by
        the url parameter loggerName.

        example call:

            POST /maintenance/setLogLevel
            loggerName=linotp.lib.user
            level=10

        (sets the log level of the user library to DEBUG)
        if loggerName is omitted, the root logger is assumed.
        """

        # we check if the client cert was valid by looking for
        # the existance of an env variable. for apache this is
        # SSL_CLIENT_S_DN_CN. to support other servers we read
        # the name of the variable from the config

        env_var = getFromConfig('maintenance_verify_client_env_var', False)

        if env_var:

            client_cert = request.environ.get(env_var)

            if client_cert is None:
                abort(401)

        # ----------------------------------------------------------------------

        # if no logger name is supplied we default to '' (which translates
        # to the root logger in the python stdlib logging api)

        name = request.POST.get('loggerName', '')

        # ----------------------------------------------------------------------

        level_as_str = request.POST.get('level', '')

        if not level_as_str.isdigit():
            abort(400)

        level = int(level_as_str)

        # ----------------------------------------------------------------------

        set_logging_level(name, level)
        Session.commit()

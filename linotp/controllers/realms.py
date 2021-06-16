import logging
from pprint import pprint

from flask import current_app, g

from linotp.controllers.base import BaseController, JWTMixin
from linotp.flap import config, request, response
from linotp.lib.context import request_context
from linotp.lib.policy import PolicyException, checkPolicyPost, checkPolicyPre
from linotp.lib.realm import getRealms
from linotp.lib.reply import sendError, sendResult
from linotp.lib.user import getUserFromRequest
from linotp.lib.util import check_session, get_client
from linotp.model import db

log = logging.getLogger(__name__)


class RealmsController(BaseController, JWTMixin):
    """
    The linotp.controllers are the implementation of the web-API to talk to
    the LinOTP server.
    The RealmController is used for creating, deleting and modifying realms.

    The following is the type definition of a **Realm**:

    .. code::

        {
            "name": string,
            "entry": string,
            "userIdResolvers": [string],
            "default": boolean,
            "admin": boolean,
        }

    """

    def __init__(self, name, install_name="", **kwargs):
        super(RealmsController, self).__init__(
            name, install_name=install_name, **kwargs
        )

        self.add_url_rule("/", "realms", self.get_realms, methods=["GET"])

    def __before__(self, **params):
        """
        __before__ is called before every action

        :param params: list of named arguments
        :return: -nothing- or in case of an error a Response
                created by sendError with the context info 'before'
        """

        action = request_context["action"]

        try:

            g.audit["success"] = False
            g.audit["client"] = get_client(request)

            check_session(request)

            audit = config.get("audit")
            request_context["Audit"] = audit

            return None

        except Exception as exx:
            log.error("[__before__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(response, exx, context="before")

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """
        try:
            g.audit["administrator"] = getUserFromRequest()

            current_app.audit_obj.log(g.audit)
            db.session.commit()
            return response

        except Exception as exx:
            log.error("[__after__] unable to create a session cookie: %r", exx)
            db.session.rollback()
            return sendError(response, exx, context="after")

    def get_realms(self):
        """
        Method: GET /api/v2/realms

        Return the list of all realms visible to the logged-in administrator.

        Visible realms are determined as follows:
        - If the admin has the permission for ``scope=system, action=read``, all
        realms are visible.
        - If the admin has the permission `scope=admin` for a realm , that realm
        will be visible.

        :return:
            a JSON-RPC response with ``result`` in the following format:

            .. code::

                {
                    "status": boolean,
                    "value": [ Realm ]
                }

        :raises PolicyException:
            if the logged-in admin does not have the correct permissions to list
            realms, the exception message is serialized and returned. The
            response has status code 403.
        :raises Exception:
            if any other error occurs the exception message is serialized and
            returned. The response has status code 500.
        """

        try:
            res = checkPolicyPre("system", "getRealms")

        except PolicyException as pe:
            log.error("[get_realms] policy failed: {}".format(pe))
            db.session.rollback()
            error = sendError(None, pe.message)
            error.status_code = 403
            return error

        try:
            log.debug("[get_realms] with params".format(self.request_params))

            g.audit["success"] = True

            realms = getRealms()
            formatted_realms = [
                {
                    "name": realm["realmname"],
                    "entry": realm["entry"],
                    "userIdResolvers": realm["useridresolver"],
                    "default": bool(realm.get("default", False)),
                    "admin": bool(realm.get("admin", False)),
                }
                for realm in realms.values()
            ]

            db.session.commit()
            return sendResult(response, formatted_realms)

        except Exception as e:
            log.error("[get_realms] failed: {}".format(e))
            db.session.rollback()
            return sendError(None, e.message)

import logging
from pprint import pprint

from flask import Response, current_app, g, stream_with_context

from linotp.controllers.base import BaseController, JWTMixin
from linotp.flap import config, request, response
from linotp.lib.context import request_context
from linotp.lib.policy import PolicyException, checkPolicyPost, checkPolicyPre
from linotp.lib.realm import getRealms
from linotp.lib.reply import sendError, sendResult, sendResultIterator
from linotp.lib.user import User as RealmUser
from linotp.lib.user import (
    getUserFromParam,
    getUserFromRequest,
    getUserListIterators,
)
from linotp.lib.useriterator import iterate_resolverusers
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

        self.add_url_rule(
            "/<string:realm_name>/users",
            "users",
            self.get_users,
            methods=["GET"],
        )

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
            return sendError(exx, context="after")

    def get_realms(self):
        """
        Method: GET /api/v2/realms

        Return the list of all realms visible to the logged-in administrator.

        Visible realms are determined as follows:

        * If the admin has the permission for ``scope=system, action=read``, all
          realms are visible.
        * If the admin has the permission ``scope=admin`` for a realm , that realm
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
            error = sendError(pe.message)
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
            return sendResult(formatted_realms)

        except Exception as e:
            log.error("[get_realms] failed: {}".format(e))
            db.session.rollback()
            return sendError(e.message)

    def get_users(self, realm_name: str):
        """
        Method:  GET /api/v2/realms/<realmName>/users

        Display the list of the users in a given realm, provided the users of
        the realm are visible to the logged-in administrator.

        Visible users are determined as follows:

        * If the administrator has the permission for ``scope=admin, action=userlist``,
          for a realm, users in that realm are visible.
          This is the case no matter how the permission is defined: either by
          explicitly naming a realm, by setting all realms via a wildcard
          (realm="*"), or by implicitly giving permissions for everything in the
          admin scope by not setting any admin scope policies.

        :param <searchexpr>: limit results to those matching the searchexpr.
          Will be retrieved from the UserIdResolverClass. Example: `username=Alice`.
        :type <searchexpr>: str, optional

        :param searchTerm: limit results to those matching the searchTerm
          in at least one searchable field. Supports `*` as a wildcard operator.
        :type searchTerm: str, optional

        :param rp: limit the number of returned users, defaults to 16 if `page` is given.
        :type rp: int, optional

        :param page: request a certain page, defaults to 0 if `rp` is given.
        :type page: int, optional

        :return:
            a JSON-RPC response with ``result`` in the following format:

            .. code::

                {
                    "status": boolean,
                    "value": [ User ]
                }

        :raises PolicyException:
            if the logged-in admin does not have the correct permissions to list
            users in the given realm, the exception message is serialized and
            returned. The response has status code 403.

        :raises Exception:
            if any other error occurs the exception message is serialized and
            returned. The response has status code 500.

        """
        realm_user = RealmUser(realm=realm_name)
        try:
            policy_params = {"realm": realm_name}
            res = checkPolicyPre(
                "admin", "userlist", param=policy_params, user=realm_user
            )
        except PolicyException as exception:
            log.error(
                "[realms.get_users] admin_user is not allowed to list users in realm %s",
                realm_name,
            )
            exception_description = (
                "Admin has no rights to list users in the requested realm."
            )
            db.session.rollback()
            error = sendError(PolicyException(exception_description))
            error.status_code = 403
            return error
        except Exception as exception:
            log.error("[realms.get_users] failed: %r", exception)
            db.session.rollback()
            error = sendError(exception)
            error.status_code = 500
            return error

        param = self.request_params.copy()

        searchDict = {
            k: v for k, v in param.items() if k not in ["rp", "page"]
        }
        users_iters = getUserListIterators(searchDict, realm_user)

        g.audit["success"] = True
        g.audit["info"] = "realm: %s" % realm_name

        # default of rp=16 is set in sendResultIterator
        rp = int(param.get("rp")) if param.get("rp") else None
        page = None
        if param.get("page"):
            page = int(param.get("page"))
        elif rp is not None and rp > 0:
            # if the results are limited through `rp`, default page is 0
            page = 0

        db.session.commit()

        return Response(
            stream_with_context(
                sendResultIterator(
                    iterate_resolverusers(users_iters), rp=rp, page=page
                )
            ),
            mimetype="application/json",
        )

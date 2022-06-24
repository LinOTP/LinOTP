import logging

from flask import current_app, g

from linotp.controllers.base import BaseController, JWTMixin
from linotp.flap import request, response
from linotp.lib.context import request_context
from linotp.lib.policy import PolicyException, checkPolicyPre
from linotp.lib.realm import getRealms
from linotp.lib.reply import sendError, sendResult
from linotp.lib.resolver import getResolverList
from linotp.lib.user import getUserFromRequest
from linotp.lib.util import check_session, get_client
from linotp.model import db

log = logging.getLogger(__name__)


class ResolversController(BaseController, JWTMixin):
    """
    The linotp.controllers are the implementation of the web-API to talk to
    the LinOTP server.
    The ResolverController is used for creating, deleting and modifying resolvers, and getting users from a resolver.

    The following is the type definition of a **Resolver**:

    .. code::

        {
            "name": string,
            "entry": string,
            "type": string,
            "spec": string,
            "immutable": boolean,
            "readonly": boolean,
            "admin": boolean,
            "realms": [string]
        }
    """

    def __init__(self, name, install_name="", **kwargs):
        super(ResolversController, self).__init__(
            name, install_name=install_name, **kwargs
        )

        self.add_url_rule(
            "/", "resolvers", self.get_resolvers, methods=["GET"]
        )

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

    def get_resolvers(
        self,
    ):
        """
        Method: GET /api/v2/resolvers

        Return the list of all resolvers visible to the logged-in administrator.

        Visible resolvers are determined as follows:
        - If the admin has the permission for ``scope=system, action=read``, all
        resolvers are visible.
        - If the admin has the permission `scope=admin` for a realm , the
        resolvers in that realm will be visible.

        :return:
            a JSON-RPC response with ``result`` in the following format:

            .. code::

                {
                    "status": boolean,
                    "value": [ Resolver ]
                }

        :raises PolicyException:
            if the logged-in admin does not have the correct permissions to list
            resolvers, the exception message is serialized and returned. The
            response has status code 403.
        :raises Exception:
            if any other error occurs the exception message is serialized and
            returned. The response has status code 500.
        """

        try:
            # gets translated into system/read
            checkPolicyPre("system", "getResolvers")

        except PolicyException as pe:
            log.error("[get_resolvers] policy failed: %r", pe)
            db.session.rollback()
            error = sendError(None, pe)
            error.status_code = 403
            return error

        try:
            resolvers = getResolverList()

            # in the returned list of resolvers, we rename the name of the
            # resolver from "resolvername" to "name", and set "realms" to an
            # empty list if it is not set.
            for resolver_entry, description in resolvers.items():
                resolvers[resolver_entry]["name"] = description["resolvername"]
                del resolvers[resolver_entry]["resolvername"]
                resolvers[resolver_entry].setdefault("realms", [])

            # generate a list of all realms containing the resolver and add
            # it to the resolvers dictionary
            for realm_name, values in getRealms().items():
                for resolver in values["useridresolver"]:
                    resolver_name = resolver.split(".")[3]
                    resolvers[resolver_name]["realms"].append(realm_name)

            g.audit["success"] = True
            db.session.commit()

            # return a list of the resolvers
            return sendResult(response, list(resolvers.values()), 1)

        except Exception as ex:
            log.error("[getResolvers] error getting resolvers: %r", ex)
            db.session.rollback()
            return sendError(response, ex)

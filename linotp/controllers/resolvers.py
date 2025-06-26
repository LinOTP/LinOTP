import logging
from math import ceil

from flask import current_app, g

from linotp.controllers.base import BaseController
from linotp.lib.context import request_context
from linotp.lib.policy import PolicyException, checkPolicyPre
from linotp.lib.reply import sendError, sendResult
from linotp.lib.resolver import get_resolver, get_resolvers
from linotp.lib.user import User as RealmUser
from linotp.lib.user import getUserFromRequest
from linotp.model import db
from linotp.model.resolver import Resolver, User

log = logging.getLogger(__name__)


class UserNotFoundException(Exception):
    pass


class ResolversController(BaseController):
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

    And the following is the type definition of a **User**:

    .. code::

        {
            "userId": string;
            "givenName": string;
            "surname": string;
            "email": string;
            "mobile": string;
            "phone": string;
            "username": string;
            "resolverName": string;
            "resolverClass": string;
        }
    """

    def __init__(self, name, install_name="", **kwargs):
        super().__init__(name, install_name=install_name, **kwargs)

        self.add_url_rule("/", "resolvers", self.get_resolvers, methods=["GET"])
        self.add_url_rule(
            "/<string:resolver_name>/users",
            "users",
            self.get_users,
            methods=["GET"],
        )
        self.add_url_rule(
            "/<string:resolver_name>/users/<string:user_id>",
            "user",
            self.get_user,
            methods=["GET"],
        )

    @staticmethod
    def __after__(response):
        """
        __after__ is called after every action

        :param response: the previously created response - for modification
        :return: return the response
        """

        action = request_context["action"]

        try:
            g.audit["administrator"] = getUserFromRequest()

            current_app.audit_obj.log(g.audit)
            db.session.commit()
            return response

        except Exception as exx:
            log.error("[__after__::%r] exception %r", action, exx)
            db.session.rollback()
            return sendError(exx)

    def get_resolvers(self):
        """
        Method: GET /api/v2/resolvers

        Return the list of all resolvers visible to the logged-in administrator.

        Visible resolvers are determined as follows:

        * If the admin has the permission for ``scope=system, action=read``, all
          resolvers are visible.
        * If the admin has the permission ``scope=admin`` for a realm , the
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
            error = sendError(pe)
            error.status_code = 403
            return error

        try:
            resolvers = [resolver.as_dict() for resolver in get_resolvers()]

            g.audit["success"] = True
            db.session.commit()

            # return a list of the resolvers
            return sendResult(resolvers)

        except Exception as ex:
            log.error("[getResolvers] error getting resolvers: %r", ex)
            db.session.rollback()
            return sendError(ex)

    def get_users(self, resolver_name):
        """
        Method:  GET /api/v2/resolvers/<resolverName>/users

        Display the list of the users in a given resolver, provided the users of
        the resolver are visible to the logged-in administrator.

        Visible users are determined as follows:

        * If the administrator has the permission for ``scope=admin, action=userlist``,
          for a certain realm, users of all resolvers in that realm are visible.
          This is the case no matter how the permission is defined: either by
          explicitly naming a realm, by setting all realms via a wildcard
          (realm="*"), or by implicitly giving permissions for everything in the
          admin scope by not setting any admin scope policies.
        * If the resolver is not in any realm yet, the users are also visible if
          the administrator has permissions for all realms as described in the
          previous point (either via wildcard or implicitly).

        Should the ``pageSize`` parameter be defined, the list of users
        is truncated to the given length. By default, the first page is
        returned. Setting the ``page`` parameter allows retrieving other
        pages.

        :param resolverName: name of the resolver
        :type resolverName: str

        :param <searchexpr>: limit results to those matching the searchexpr.
          Will be retrieved from the UserIdResolverClass. Example: `username=Alice`.
        :type <searchexpr>: str, optional

        :param searchTerm: limit results to those matching the searchTerm
          in at least one searchable field. Supports `*` as a wildcard operator.
        :type searchTerm: str, optional

        :param sortBy: sort the output by column, defaults to 'username'
        :type sortBy: str, optional

        :param sortOrder: 'asc' or 'desc', defaults to 'asc'
        :type sortOrder: str, optional

        :param pageSize: limit the number of returned users, defaults to 50
          (unless another value is specified in the configuration). Setting it to
          0 returns all users.
        :type pageSize: int, optional

        :param page: request a certain page, defaults to 0
        :type page: int, optional

        :return:
            a JSON-RPC response with ``result`` in the following format:

            .. code::

                {
                    "status": boolean,
                    "value": {
                        "page": number,
                        "pageSize": number,
                        "totalPages": number,
                        "totalRecords": number,
                        "pageRecords": [ User ]
                    }
                }

        :raises PolicyException:
            if the logged-in admin does not have the correct permissions to list
            users in the given resolver, the exception message is serialized and
            returned. The response has status code 403.

        :raises Exception:
            if any other error occurs the exception message is serialized and
            returned. The response has status code 500.

        """

        try:
            resolver: Resolver = get_resolver(resolver_name)
        except Exception as exception:
            log.error(
                "[get_users] cannot find resolver %s to retrieve its users",
                resolver_name,
            )
            db.session.rollback()
            error = sendError(exception)
            error.status_code = 500
            return error

        try:
            checkPolicyPre(
                "admin",
                "userlist",
                user=RealmUser(resolver_config_identifier=resolver.spec),
            )
        except PolicyException:
            log.error(
                "[get_users] user is not allowed to list users in resolver %s",
                resolver_name,
            )
            exception_description = (
                "Admin has no rights to list users in the requested resolver."
            )
            db.session.rollback()
            error = sendError(PolicyException(exception_description))
            error.status_code = 403
            return error
        except Exception as exception:
            log.error("[get_users] failed: %r", exception)
            db.session.rollback()
            error = sendError(exception)
            error.status_code = 500
            return error

        try:
            page = int(self.request_params.get("page", 0))
            page_size = self.request_params.get("pageSize", None)

            search_dictionary = {"username": "*"}
            search_dictionary.update(self.request_params)
            search_dictionary = {
                k: v
                for k, v in search_dictionary.items()
                if k not in ["page", "pageSize", "sortOrder", "sortBy"]
            }

            users = resolver.get_users(search_dictionary)
            log.debug("[get_users] page: %s, page_size: %s", page, page_size)

            # convert to dict
            user_dicts = [user.as_dict() for user in users]

            # sort users
            reverse = self.request_params.get("sortOrder", "asc") == "desc"
            sort_key = self.request_params.get("sortBy", "username")
            try:
                user_dicts = sorted(
                    user_dicts,
                    key=lambda user_dict: user_dict[sort_key] or "",
                    reverse=reverse,
                )
            except KeyError as exx:
                raise KeyError(
                    f"users can't be sorted by parameter {sort_key}"
                ) from exx
            total_pages = 1
            total_records = len(users)

            # return only one page and its metadata
            if page_size:
                page_size = int(page_size)
                start = page_size * page
                end = start + page_size
                records = user_dicts[start:end]
                total_pages = ceil(total_records / page_size)
            else:
                records = user_dicts
                page_size = total_records

            res = {
                "page": page,
                "pageSize": page_size,
                "totalPages": total_pages,
                "totalRecords": total_records,
                "pageRecords": records,
            }

            g.audit["success"] = True

            db.session.commit()
            return sendResult(res)

        except Exception as exception:
            log.error("[get_users] failed: %r", exception)
            db.session.rollback()
            error = sendError(exception)
            error.status_code = 500
            return error

    def get_user(self, resolver_name, user_id):
        """
        Method:  GET /api/v2/resolvers/<resolverName>/users/<userId>

        Display the requested user, provided it is visible to the logged-in
        administrator.

        A visible user is determined as follows:

        * If the administrator has the permission for ``scope=admin, action=userlist``,
          for a certain realm, users of all resolvers in that realm are visible.
          This is the case no matter how the permission is defined: either by
          explicitly naming a realm, by setting all realms via a wildcard
          (realm="*"), or by implicitly giving permissions for everything in the
          admin scope by not setting any admin scope policies.
        * If the resolver is not in any realm yet, the user is also visible if
          the administrator has permissions for all realms as described in the
          previous point (either via wildcard or implicitly).

        :param resolverName: name of the resolver
        :type resolverName: str

        :param userId: ID of the user within the resolver
        :type userId: str

        :return:
            a JSON-RPC response with ``result`` in the following format:

            .. code::

                {
                    "status": boolean,
                    "value": User
                }

        :raises PolicyException:
            if the logged-in admin does not have the correct permissions to list
            users in the given resolver, the exception message is serialized and
            returned. The response has status code 403.

        :raises UserNotFoundException:
            if the user is not found, the exception message is serialized and
            returned with status code 404.

        :raises Exception:
            if any other error occurs the exception message is serialized and
            returned with status code 500.
        """

        try:
            resolver: Resolver = get_resolver(resolver_name)
        except Exception as exception:
            log.error(
                f"[get_user] cannot find resolver {resolver_name} to retrieve its users",
            )
            db.session.rollback()
            error = sendError(exception)
            error.status_code = 500
            return error

        try:
            checkPolicyPre(
                "admin",
                "userlist",
                user=RealmUser(resolver_config_identifier=resolver.spec),
            )
        except PolicyException:
            log.error(
                f"[get_user] user is not allowed to list users in resolver {resolver_name}"
            )
            exception_description = (
                "Admin has no rights to list users in the requested resolver."
            )
            db.session.rollback()
            error = sendError(PolicyException(exception_description))
            error.status_code = 403
            return error
        except Exception as exception:
            log.error(f"[get_user] failed: {exception}")
            db.session.rollback()
            error = sendError(exception)
            error.status_code = 500
            return error

        try:
            user_dict = resolver.configuration_instance.getUserInfo(user_id)
            if not user_dict:
                message = f"Could not find a user with ID {user_id} in resolver {resolver_name}."
                raise UserNotFoundException(message)
            user_dict["userid"] = user_id
            result = User.from_dict(resolver.name, resolver.type, user_dict).as_dict()

            g.audit["success"] = True

            db.session.commit()
            return sendResult(result)

        except UserNotFoundException as user_not_found_exception:
            log.error(f"[get_user] failed: {user_not_found_exception}")
            db.session.rollback()
            error = sendError(user_not_found_exception)
            error.status_code = 404
            return error

        except Exception as exception:
            log.error(f"[get_user] failed: {exception}")
            db.session.rollback()
            error = sendError(exception)
            error.status_code = 500
            return error

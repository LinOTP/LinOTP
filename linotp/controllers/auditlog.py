import logging

from flask import current_app, g

from linotp.controllers.base import BaseController, JWTMixin
from linotp.flap import request, response
from linotp.lib.audit.iterator import AuditQuery
from linotp.lib.context import request_context
from linotp.lib.policy import PolicyException, checkPolicyPre
from linotp.lib.reply import sendError, sendResult
from linotp.lib.user import getUserFromRequest
from linotp.model import db

log = logging.getLogger(__name__)


class UserNotFoundException(Exception):
    pass


class AuditlogController(BaseController, JWTMixin):
    """
    The linotp.controllers are the implementation of the web-API to talk to
    the LinOTP server.
    The AuditLogController is used for querying audit log entries.

    The following is the type definition of an **AuditEntry**:

    .. code::

        {
            "id": number
            "timestamp": date,
            "serial": string,
            "action": string,
            "actionDetail": string,
            "success": boolean,
            "tokenType": string,
            "user": string,
            "realm": string,
            "administrator": string,
            "info": string,
            "linotpServer": string,
            "client": string,
            "logLevel": string,
            "clearanceLevel": number,
            "signatureCheck": boolean
        }

    """

    def __init__(self, name, install_name="", **kwargs):
        super(AuditlogController, self).__init__(
            name, install_name=install_name, **kwargs
        )

        self.add_url_rule(
            "/", "auditlog", self.get_audit_entries, methods=["GET"]
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
            return sendError(response, exx, context="after")

    def get_audit_entries(self):
        """
        Method: GET /api/v2/auditLog

        Return a paginated list of the audit log entries.

        The audit log visibility is determined as follows:

        * If no audit policy is defined, all audit log entries are visible to every admin.
        * Otherwise, only the admins with the policy ``scope=audit, action=view`` can view
          audit log entries.

        :param pageSize: limit the number of returned entries, defaults to 15
          (unless another value is specified in the configuration). Setting it to
          0 returns all entries.
        :type pageSize: int, optional

        :param page: request a certain page, defaults to 0
        :type page: int, optional

        :param sortOrder: ascending (`asc`) or descending (`desc`) order of entries, defaults to `desc`
        :type page: string, optional

        :param id: filter for a specific id. Leading or closing `*` can be used as a wildcard operator
        :type id: int, optional

        :param timestamp: filter for a specific timestamp. Leading or closing `*` can be used as a wildcard operator
        :type timestamp: str, optional

        :param action: filter for a specific action. Leading or closing `*` can be used as a wildcard operator
        :type action: str, optional

        :param actionDetail: filter for a specific actionDetail. Leading or closing `*` can be used as a wildcard operator
        :type actionDetail: str, optional

        :param success: filter for a specific success.
        :type success: boolean, optional

        :param serial: filter for a specific serial. Leading or closing `*` can be used as a wildcard operator
        :type serial: str, optional

        :param tokenType: filter for a specific tokenType. Leading or closing `*` can be used as a wildcard operator
        :type tokenType: str, optional

        :param user: filter for a specific username. Leading or closing `*` can be used as a wildcard operator
        :type user: str, optional

        :param realm: filter for a specific realm. Leading or closing `*` can be used as a wildcard operator
        :type realm: str, optional

        :param administrator: filter for a specific administrator username. Leading or closing `*` can be used as a wildcard operator
        :type administrator: str, optional

        :param info: filter for a specific info. Leading or closing `*` can be used as a wildcard operator
        :type info: str, optional

        :param linotpServer: filter for a specific linotpServer. Leading or closing `*` can be used as a wildcard operator
        :type linotpServer: str, optional

        :param client: filter for a specific client. Leading or closing `*` can be used as a wildcard operator
        :type client: str, optional

        :param logLevel: filter for a specific logLevel. Leading or closing `*` can be used as a wildcard operator
        :type logLevel: str, optional

        :param clearanceLevel: filter for a specific clearanceLevel. Leading or closing `*` can be used as a wildcard operator
        :type clearanceLevel: str, optional

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
                        "pageRecords": [ AuditEntry ]
                    }
                }

        :raises PolicyException:
            if the logged-in admin does not have the correct permissions to list
            audit log entries, the exception message is serialized and returned. The
            response has status code 403.

        :raises Exception:
            if any other error occurs the exception message is serialized and
            returned. The response has status code 500.
        """

        try:
            checkPolicyPre("audit", "view")
        except PolicyException as pe:
            log.error("[getAuditEntries] policy failed: %r", pe)
            db.session.rollback()
            error = sendError(None, pe)
            error.status_code = 403
            return error

        try:
            search_dict = self._get_search_dict_from_request_params()

            audit_obj = current_app.audit_obj
            audit_query = AuditQuery(search_dict, audit_obj)

            entries = [
                audit_query.audit_obj.row2dictApiV2(rowproxy)
                for rowproxy in audit_query.get_query_result()
            ]

            result = {
                "page": audit_query.page - 1,
                "pageSize": len(entries),
                "totalPages": audit_query.get_total_pages(),
                "totalRecords": audit_query.get_total(),
                "pageRecords": entries,
            }

            g.audit["success"] = True
            db.session.commit()

            # return a list of the audit log entries
            return sendResult(result)

        except Exception as ex:
            log.error("[getAuditEntries] error getting audit entries: %r", ex)
            db.session.rollback()
            return sendError(response, ex)

    def _get_search_dict_from_request_params(self):
        request_param_to_audit_query_param_mapping = {
            "id": "number",
            "timestamp": "date",
            "action": "action",
            "actionDetail": "action_detail",
            "success": "success",
            "serial": "serial",
            "tokenType": "tokentype",
            "user": "user",
            "realm": "realm",
            "administrator": "administrator",
            "info": "info",
            "linotpServer": "linotp_server",
            "client": "client",
            "logLevel": "log_level",
            "clearanceLevel": "clearance_level",
        }
        search_params = {
            request_param_to_audit_query_param_mapping[k]: v
            for k, v in self.request_params.items()
            if k in request_param_to_audit_query_param_mapping
        }

        # convert given `success` boolean to corresponding string `0` or `1`
        # because it's the type of AuditTable.success
        if "success" in search_params:
            success = search_params["success"].lower()
            if success == "true":
                search_params["success"] = "1"
            elif success == "false":
                search_params["success"] = "0"

        # we defer from request_params.get("sortOrder", "desc")
        # because when `sortOrder` is an empty parameter in the request,
        # it's an empty string `""` in request_params
        sort_order = self.request_params.get("sortOrder")
        search_params["sortorder"] = (
            sort_order if sort_order in ["asc", "desc"] else "desc"
        )

        sort_by = request_param_to_audit_query_param_mapping.get(
            self.request_params.get("sortBy"), "number"
        )
        search_params["sortname"] = sort_by

        search_params["page"] = int(self.request_params.get("page", 0)) + 1
        search_params["rp"] = int(self.request_params.get("pageSize", 15))
        if search_params["rp"] == 0:
            # return all results by not passing page nor rp
            del search_params["page"]
            del search_params["rp"]

        # replace wildcard operator `*` by `%`
        for k, v in search_params.items():
            if not isinstance(v, str):
                continue
            search_params[k] = v.replace("*", "%")

        return search_params

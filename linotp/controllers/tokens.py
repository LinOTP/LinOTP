import json
import logging
from datetime import datetime

from flask import current_app, g

from linotp.controllers.base import BaseController, JWTMixin
from linotp.flap import request, response
from linotp.lib.context import request_context
from linotp.lib.policy import PolicyException, checkPolicyPre
from linotp.lib.reply import sendError, sendResult
from linotp.lib.tokeniterator import TokenIterator
from linotp.lib.user import getUserFromParam, getUserFromRequest
from linotp.lib.util import check_session, get_client
from linotp.model import db

log = logging.getLogger(__name__)


class TokensController(BaseController, JWTMixin):
    """
    The linotp.controllers are the implementation of the web-API to talk to
    the LinOTP server.
    The TokenController is used for listing, creating, deleting and modifying
    tokens.

    The following is the type definition of a **Token**:

    .. code::

        {
            "id": number,
            "description": string,
            "serial": string,
            "type": string,
            "creationDate": date,
            "isActive": boolean,
            "realms": [string],
            "tokenConfiguration": {
                "countWindow": number,
                "syncWindow": number,
                "otpLength": number,
                "otpCounter": number,
            },
            "userInfo": {
                "id": string,
                "username": string,
                "description": string,
                "idResolverInfo": {
                    "name": string,
                    "class": string
                }
            },
            "usageCounters": {
                "loginAttempts": number,
                "maxLoginAttempts": number,
                "maxSuccessfulLoginAttempts": number,
                "lastSuccessfulLoginAttempts": date,
                "failedLoginAttempts": number,
                "maxFailedLoginAttempts": number,
                "lastAuthenticationMatch": date
            },
            "validityPeriod": {
                "start": date,
                "end": date,
            }
        }
    """

    def __init__(self, name, install_name="", **kwargs):
        super(TokensController, self).__init__(
            name, install_name=install_name, **kwargs
        )

        self.add_url_rule("/", "tokens", self.get_tokens, methods=["GET"])

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

    def get_tokens(self):
        """
        Method: GET /api/v2/tokens

        Display the list of all tokens visible to the logged-in administrator.

        Should the ``pageSize`` parameter be defined, the list of tokens
        is truncated to the given length. By default, the first page is
        returned. Setting the ``page`` parameter allows retrieving other
        pages.

        :param pageSize: limit the number of returned tokens, defaults to None (no limit)
        :type pageSize: int, optional
        :param page: request a certain page, defaults to 0
        :type page: int, optional
        :param sortBy: sort the output by column, defaults to 'serial'
        :type sortBy: str, optional
        :param sortOrder: 'asc' or 'desc', defaults to 'asc'
        :type sortOrder: str, optional
        :param searchTerm: limit entries to those partially matching the searchTerm
        :type searchTerm: str, optional
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
                        "pageRecords": [ Token ]
                    }
                }

        :raises PolicyException:
            if the logged-in admin does not have the correct permissions to list tokens,
            the exception message is serialized and returned
        :raises Exception:
            if any other error occurs the exception message is serialized and returned
        """

        field_map = {
            "id": "LinOtp.TokenId",
            "description": "LinOtp.TokenDesc",
            "serial": "LinOtp.TokenSerialnumber",
            "type": "LinOtp.TokenType",
            "creationDate": "LinOtp.CreationDate",
            "isActive": "LinOtp.Isactive",
            "realms": "LinOtp.RealmNames",
            "hashLib": "hashlib",
            "timeWindow": "timeWindow",
            "timeShift": "timeShift",
            "timeStep": "timeStep",
            "countWindow": "LinOtp.CountWindow",
            "syncWindow": "LinOtp.SyncWindow",
            "otpLength": "LinOtp.OtpLen",
            "otpCounter": "LinOtp.Count",
            "userId": "User.userid",
            "username": "User.username",
            "userDescription": "User.description",
            "resolverName": "LinOtp.IdResolver",
            "resolverClass": "LinOtp.IdResClass",
            "loginAttempts": "count_auth",
            "maxLoginAttempts": "count_auth_max",
            "successfulLoginAttempts": "count_auth_success",
            "maxSuccessfulLoginAttempts": "count_auth_success_max",
            "lastSuccessfulLoginAttempt": "LinOtp.LastAuthSuccess",
            "failedLoginAttempts": "LinOtp.FailCount",
            "maxFailedLoginAttempts": "LinOtp.MaxFail",
            "lastAuthenticationMatch": "LinOtp.LastAuthMatch",
            "validityStart": "validity_period_start",
            "validityEnd": "validity_period_end",
        }

        # use for the sort & filter names
        reverse_map = {v: k for k, v in field_map.items()}

        param = self.request_params
        try:
            page = int(param.get("page", 0)) + 1
            page_size = param.get("pageSize")
            sort_by = reverse_map.get(param.get("sortBy"), "serial")
            sort_order = param.get("sortOrder", "asc")
            search_term = param.get("searchTerm", None)

            ### Check permissions ###

            logged_in_admin = getUserFromParam(param)

            # Check policies for listing (showing) tokens
            check_result = checkPolicyPre(
                "admin", "show", param, user=logged_in_admin
            )

            # If they aren't active, we are allowed to show tokens from all
            # realms:
            filterRealm = ["*"]

            # If they are active, restrict the result to the tokens in the
            # realms that the admin is allowed to see:
            if check_result["active"] and check_result["realms"]:
                filterRealm = check_result["realms"]

            log.info(
                "[get_tokens] admin {} may view tokens the following realms: {}".format(
                    check_result["admin"], filterRealm
                )
            )

            ### End permissions' check ###

            tokens = TokenIterator(
                logged_in_admin,
                None,
                page,
                page_size,
                search_term,
                sort_by,
                sort_order,
                filterRealm,
                [],
            )

            g.audit["success"] = True
            g.audit["info"] = "realm: {}".format(filterRealm)

            # put in the result
            result = {}

            info = tokens.getResultSetInfo()
            result["page"] = int(info["page"]) - 1
            result["pageSize"] = info["pagesize"]
            result["totalPages"] = info["pages"]
            result["totalRecords"] = info["tokens"]

            # now row by row
            lines = []
            for token in tokens:
                _parse_tokeninfo(token)
                token_info = token["LinOtp.TokenInfo"]

                formatted_token = {
                    "id": token[field_map["id"]],
                    "description": token[field_map["description"]],
                    "serial": token[field_map["serial"]],
                    "type": token[field_map["type"]].lower(),
                    "creationDate": token[field_map["creationDate"]],
                    "isActive": token[field_map["isActive"]],
                    "realms": token[field_map["realms"]],
                    "tokenConfiguration": {
                        "hashLib": token_info.get(field_map["hashLib"], None),
                        "timeWindow": token_info.get(
                            field_map["timeWindow"], None
                        ),
                        "timeShift": token_info.get(
                            field_map["timeShift"], None
                        ),
                        "timeStep": token_info.get(
                            field_map["timeStep"], None
                        ),
                        "countWindow": token[field_map["countWindow"]],
                        "syncWindow": token[field_map["syncWindow"]],
                        "otpLength": token[field_map["otpLength"]],
                        "otpCounter": token[field_map["otpCounter"]],
                    },
                    "userInfo": {
                        "userId": token[field_map["userId"]],
                        "username": token[field_map["username"]],
                        "userDescription": token[field_map["userDescription"]],
                        "idResolverInfo": {
                            "resolverName": token[field_map["resolverName"]],
                            "resolverClass": token[field_map["resolverClass"]],
                        },
                    },
                    "usageData": {
                        "loginAttempts": token_info.get(
                            field_map["loginAttempts"], None
                        ),
                        "maxLoginAttempts": token_info.get(
                            field_map["maxLoginAttempts"], None
                        ),
                        "successfulLoginAttempts": token_info.get(
                            field_map["successfulLoginAttempts"], None
                        ),
                        "maxSuccessfulLoginAttempts": token_info.get(
                            field_map["maxSuccessfulLoginAttempts"], None
                        ),
                        "lastSuccessfulLoginAttempt": token[
                            field_map["lastSuccessfulLoginAttempt"]
                        ],
                        "failedLoginAttempts": token[
                            field_map["failedLoginAttempts"]
                        ],
                        "maxFailedLoginAttempts": token[
                            field_map["maxFailedLoginAttempts"]
                        ],
                        "lastAuthenticationMatch": token[
                            field_map["lastAuthenticationMatch"]
                        ],
                    },
                    "validityPeriod": {
                        "validityStart": token_info.get(
                            field_map["validityStart"], None
                        ),
                        "validityEnd": token_info.get(
                            field_map["validityEnd"], None
                        ),
                    },
                }
                lines.append(formatted_token)
            result["pageRecords"] = lines

            db.session.commit()
            return sendResult(response, result)

        except PolicyException as pe:
            log.exception("[get_tokens] policy failed: {}".format(pe))
            db.session.rollback()
            error = sendError(None, pe)
            error.status_code = 403
            return error

        except Exception as e:
            log.exception("[get_tokens] failed: {}".format(e))
            db.session.rollback()
            return sendError(None, e)


# HELPERS - to be refactored away at a later point


def _parse_tokeninfo(tok):
    """
    Parse TokenInfo to JSON and format validity period date fields to isoformat
    """

    token_info = tok["LinOtp.TokenInfo"]

    if token_info:
        info = json.loads(token_info)
    else:
        info = {}

    for field in ["validity_period_end", "validity_period_start"]:
        if field in info:
            date = datetime.strptime(info[field], "%d/%m/%y %H:%M")
            info[field] = date.isoformat()

    tok["LinOtp.TokenInfo"] = info

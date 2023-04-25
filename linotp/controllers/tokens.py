import json
import logging
from datetime import datetime, timezone
from difflib import get_close_matches

from flask import current_app, g

from linotp.controllers.base import BaseController, JWTMixin
from linotp.flap import request, response
from linotp.lib.context import request_context
from linotp.lib.policy import PolicyException, checkPolicyPre
from linotp.lib.reply import sendError, sendResult
from linotp.lib.tokeniterator import TokenIterator
from linotp.lib.type_utils import DEFAULT_TIMEFORMAT
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

    Note: If a Token has no user, ``userInfo`` will be ``None``
    """

    def __init__(self, name, install_name="", **kwargs):
        super(TokensController, self).__init__(
            name, install_name=install_name, **kwargs
        )

        self.add_url_rule("/", "tokens", self.get_tokens, methods=["GET"])
        self.add_url_rule(
            "/<string:serial>",
            "token_by_serial",
            self.get_token_by_serial,
            methods=["GET"],
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

    def get_tokens(self):
        """
        Method: GET /api/v2/tokens

        Display the list of all tokens visible to the logged-in administrator.

        Should the ``pageSize`` parameter be defined, the list of tokens
        is truncated to the given length. By default, the first page is
        returned. Setting the ``page`` parameter allows retrieving other
        pages.

        :param pageSize: limit the number of returned tokens, defaults to 50
          (unless another value is specified in the configuration). Setting it to
          0 returns all tokens.
        :type pageSize: int, optional

        :param page: request a certain page, defaults to 0
        :type page: int, optional

        :param sortBy: sort the output by column, defaults to 'serial'
        :type sortBy: str, optional

        :param sortOrder: 'asc' or 'desc', defaults to 'asc'
        :type sortOrder: str, optional

        :param searchTerm: limit entries to those partially matching the searchTerm
        :type searchTerm: str, optional

        :param userId: limit the results to the tokens owned by the users with this user ID
        :type userId: str, optional

        :param resolverName: limit the results to the tokens owned by users in this resolver
        :type resolverName: str, optional

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
            return an HTTP 403 error response

        :raises Exception:
            if any other error occurs the exception message is serialized and returned in
            an HTTP 500 error response

        """

        param = self.request_params
        try:
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

            page = int(param.get("page", 0)) + 1
            page_size = param.get("pageSize")
            sortParameterNameMapping = {
                "serial": "TokenSerialnumber",
                "isActive": "Isactive",
                "type": "TokenType",
                "failedLogins": "FailCount",
                "description": "TokenDesc",
                "userId": "Userid",
                "resolver": "IdResolver",
            }
            try:
                sort_key = param.get("sortBy") or "serial"
                sort_by = sortParameterNameMapping[sort_key]
            except KeyError:
                error_msg = f"Tokens can't be sorted by {sort_key}."
                potential_sort_params = get_close_matches(
                    sort_key, sortParameterNameMapping.keys()
                )
                if potential_sort_params:
                    error_msg += (
                        f" Did you mean any of {potential_sort_params}?"
                    )
                raise KeyError(error_msg)
            sort_order = param.get("sortOrder", "asc")
            search_term = param.get("searchTerm", None)
            user_id = param.get("userId", None)
            resolver_name = param.get("resolverName", None)

            if page_size is not None:
                page_size = int(page_size)

            if page_size == 0:
                # Retrieve all available tokens
                page = None

            token_iterator_params = {
                "user_id": user_id,
                "resolver_name": resolver_name,
            }

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
                token_iterator_params,
            )

            g.audit["success"] = True
            g.audit["info"] = "realm: {}".format(filterRealm)

            # put in the result
            result = {}

            info = tokens.getResultSetInfo()
            result["page"] = info["page"] - 1
            result["pageSize"] = info["pagesize"]
            result["totalPages"] = info["pages"]
            result["totalRecords"] = info["tokens"]

            # now row by row
            lines = []
            for token in tokens:
                formatted_token = TokenAdapter(token).to_JSON_format()
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

    def get_token_by_serial(self, serial):
        """
        Method: GET /api/v2/tokens/<serial>

        Display all the information on a single token.

        :param serial: the unique token serial
        :type serial: string

        :return:
            a JSON-RPC response with ``result`` in the following format:

            .. code::

                {
                    "status": boolean,
                    "value": Token
                }

        :raises PolicyException:
            if the logged-in admin does not have the correct permissions to view the token,
            return an HTTP 403 error response

        :raises Exception:
            if any other error occurs the exception message is serialized and returned in
            an HTTP 500 error response
        """

        param = self.request_params
        try:
            user = getUserFromParam(param)
            check_result = checkPolicyPre("admin", "show", param, user=user)

            # realms:
            filter_realm = ["*"]

            # If they are active, restrict the result to the tokens in the
            # realms that the admin is allowed to see:
            if check_result["active"] and check_result["realms"]:
                filter_realm = check_result["realms"]

            tokens = TokenIterator(user, serial, filterRealm=filter_realm)

            result_count = tokens.getResultSetInfo()["tokens"]

            if result_count > 1:
                raise Exception(
                    "Multiple tokens found with serial {}".format(serial)
                )

            formatted_token = {}

            if result_count == 1:
                token = next(tokens)
                formatted_token = TokenAdapter(token).to_JSON_format()

            g.audit["success"] = True
            g.audit["info"] = "realm: {}".format(filter_realm)

            db.session.commit()
            return sendResult(response, formatted_token)

        except PolicyException as pe:
            log.exception("[get_token_by_serial] policy failed: {}".format(pe))
            db.session.rollback()
            error = sendError(None, pe)
            error.status_code = 403
            return error

        except Exception as e:
            log.exception("[get_token_by_serial] failed: {}".format(e))
            db.session.rollback()
            return sendError(None, e)


class TokenAdapter:
    """
    Data class to hold a token representation based on the one returned by the
    TokenIterator, but transforming some of the fields.

    The goal is not to have to repeat ourselves across all endpoint functions
    and keep the returned data structures in a consistent format.
    """

    def __init__(self, linotp_token) -> None:
        """
        Create a Token object from a linotp_token dictionary provided by
        LinOTP's token iterator.

        It reformats the date strings to ISO 8601, transforms the token type to
        a lowercase string, and defaults unset keys to None.
        """

        # fill out self.token_info:
        if linotp_token["LinOtp.TokenInfo"]:
            self._token_info = json.loads(linotp_token["LinOtp.TokenInfo"])
        else:
            self._token_info = {}

        # general token information
        self.id = linotp_token["LinOtp.TokenId"]
        self.description = linotp_token["LinOtp.TokenDesc"]
        self.serial = linotp_token["LinOtp.TokenSerialnumber"]
        self.type = linotp_token["LinOtp.TokenType"].lower()

        self.creation_date = _parse_date_string(
            linotp_token["LinOtp.CreationDate"]
        )

        self.is_active = linotp_token["LinOtp.Isactive"]
        self.realms = linotp_token["LinOtp.RealmNames"]

        # token configuration
        self.hash_lib = self._token_info.get("hashlib", None)
        self.time_window = self._token_info.get("timeWindow", None)
        self.time_shift = self._token_info.get("timeShift", None)
        self.time_step = self._token_info.get("timeStep", None)
        self.count_window = linotp_token["LinOtp.CountWindow"]
        self.sync_window = linotp_token["LinOtp.SyncWindow"]
        self.otp_length = linotp_token["LinOtp.OtpLen"]
        self.otp_counter = linotp_token["LinOtp.Count"]

        # information on the token owner
        self.user_id = linotp_token["User.userid"]
        self.username = linotp_token["User.username"]
        self.user_description = linotp_token["User.description"]
        self.resolver_name = linotp_token["LinOtp.IdResolver"].split(".")[-1]
        self.resolver_class = linotp_token["LinOtp.IdResolver"].split(".")[0]

        # usage data
        self.login_attempts = self._token_info.get("count_auth", None)
        self.max_login_attempts = self._token_info.get("count_auth_max", None)
        self.successful_login_attempts = self._token_info.get(
            "count_auth_success", None
        )
        self.max_successful_login_attempts = self._token_info.get(
            "count_auth_success_max", None
        )
        self.last_successful_login_attempt = _parse_date_string(
            linotp_token["LinOtp.LastAuthSuccess"]
        )
        self.failed_login_attempts = linotp_token["LinOtp.FailCount"]
        self.max_failed_login_attempts = linotp_token["LinOtp.MaxFail"]
        self.last_authentication_match = _parse_date_string(
            linotp_token["LinOtp.LastAuthMatch"]
        )

        # validity period
        # the following two dates are not stored in DEFAULT_TIMEFORMAT and must
        # be parsed differently than the remaining date strings.
        for field in ["validity_period_end", "validity_period_start"]:
            if field in self._token_info:
                date = datetime.strptime(
                    self._token_info[field], "%d/%m/%y %H:%M"
                )
                self._token_info[field] = date.replace(tzinfo=timezone.utc)

        self.validity_start = self._token_info.get(
            "validity_period_start", None
        )
        self.validity_end = self._token_info.get("validity_period_end", None)

    def to_JSON_format(self):
        """
        Return a JSON-compatible dictionary representation of the Token.

        Some attributes are related to each other and grouped by "topic",
        namely: tokenConfiguration, userInfo, usageData, and validityPeriod.
        """
        return {
            "id": self.id,
            "description": self.description,
            "serial": self.serial,
            "type": self.type,
            "creationDate": _stringify_date(self.creation_date),
            "isActive": self.is_active,
            "realms": self.realms,
            "tokenConfiguration": {
                "hashLib": self.hash_lib,
                "timeWindow": self.time_window,
                "timeShift": self.time_shift,
                "timeStep": self.time_step,
                "countWindow": self.count_window,
                "syncWindow": self.sync_window,
                "otpLength": self.otp_length,
                "otpCounter": self.otp_counter,
            },
            "userInfo": {
                "userId": self.user_id,
                "username": self.username,
                "userDescription": self.user_description,
                "idResolverInfo": {
                    "resolverName": self.resolver_name,
                    "resolverClass": self.resolver_class,
                },
            }
            if self.user_id
            else None,
            "usageData": {
                "loginAttempts": self.login_attempts,
                "maxLoginAttempts": self.max_login_attempts,
                "successfulLoginAttempts": self.successful_login_attempts,
                "maxSuccessfulLoginAttempts": self.max_successful_login_attempts,
                "lastSuccessfulLoginAttempt": _stringify_date(
                    self.last_successful_login_attempt
                ),
                "failedLoginAttempts": self.failed_login_attempts,
                "maxFailedLoginAttempts": self.max_failed_login_attempts,
                "lastAuthenticationMatch": _stringify_date(
                    self.last_authentication_match
                ),
            },
            "validityPeriod": {
                "validityStart": _stringify_date(self.validity_start),
                "validityEnd": _stringify_date(self.validity_end),
            },
        }


### Utils ###


def _parse_date_string(date_string):
    """
    Takes the datetime strings generated by get_vars() in linotp/model/token.py
    and parses them according to the same format used there, so that we can
    obtain a datetime object, which is then returned in the UTC timezone.
    If the passed string is empty, return None.
    """
    return (
        datetime.strptime(date_string, DEFAULT_TIMEFORMAT).replace(
            tzinfo=timezone.utc
        )
        if date_string
        else None
    )


def _stringify_date(date):
    """
    Takes the datetime object and returns it in isoformat. If it is None, return
    None instead.
    """
    return date.isoformat() if date else None

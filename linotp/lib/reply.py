#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""create responses"""

import base64
import io
import json
import logging
import urllib.error
import urllib.parse
import urllib.request

import qrcode
from flask import Response, current_app, g
from flask import request as flask_request
from qrcode.image.pure import PyPNGImage

from linotp.lib.config import getLinotpConfig
from linotp.lib.context import request_context
from linotp.lib.error import LinotpError
from linotp.lib.policy import is_auth_return
from linotp.lib.util import (
    deep_update,
    get_api_version,
    get_version,
    get_version_number,
)

optional = True
required = False

LINOTP_ERRORS = [707]

standard_http_errors = {
    "400": "Bad Request",
    "401": "Unauthorized",
    "403": "Forbidden",
    "404": "Not Found",
    "410": "Gone",
    "500": "Internal Server Error",
    "501": "Not Implemented",
    "502": "Bad Gateway",
    "503": "Service Unavailable",
}

resp = """
<html>
<head>
<title>%s %s</title>
</head>
<body>
<h1>%s %s</h1>
%s
<br>
<br>
</body>
</html>
"""

log = logging.getLogger(__name__)


def _get_httperror_code_from_params() -> str | None:
    """
    Extract an httperror parameter from the client request

    :return: The httperror parameter from the requests params, making sure it is
        a valid integer. If the value is contained in params then it will be
        returned. If it is an invalid value '500' will be returned instead.
        This also applies if httperror was set without a value (empty string).
        If httperror was not set or it cannot be determined if it was set, then
        we assume it was NOT set and return None.
    :rtype: string or None
    """
    httperror = None
    try:
        request_params = current_app.getRequestParams()
        httperror = request_params.get("httperror", None)
    except UnicodeDecodeError as exx:
        log.error(
            "Could not extract 'httperror' from params because some "
            "parameter contains invalid Unicode. Trying to extract "
            "directly from query_string. Exception: %r",
            exx,
        )
        from urllib.parse import parse_qs

        params = parse_qs(flask_request.query_string)
        if b"httperror" in params:
            httperror_list = params[b"httperror"]
            if len(httperror_list) > 1:
                log.warning(
                    "Parameter 'httperror' specified multiple times. "
                    "Using last value '%r'. All values: %r",
                    httperror_list[-1],
                    httperror_list,
                )
            httperror = httperror_list[-1]
    except Exception as exx:
        log.error(
            "Exception while extracting 'httperror' from params. "
            "Falling back to default LinOTP behaviour httperror=None. "
            "Exception %r",
            exx,
        )
        httperror = None
    if httperror is not None:
        try:
            httperror = str(int(httperror))
        except ValueError as value_error:
            log.warning(
                "'%r' is not a valid integer. Using '500' as fallback. ValueError %r",
                httperror,
                value_error,
            )
            httperror = "500"
    return httperror


def sendError(exception: Exception | str, id: int = 1):
    """
    sendError - return a HTML or JSON error result document

    Default LinOTP behaviour in case of error is to try to always send a '200
    OK' HTTP response that contains an error code and description in the body
    (JSON data).  Some clients prefer a different HTTP status code, because
    it allows response filtering without parsing the body. If the client
    sends 'httperror=<INT>' in the request this will be honoured (in case of
    error) and that HTTP status will be set. If 'httperror' is set without a
    value (or an invalid value) status 500 will be used.
    If you would like this to happen only in some error conditions but not
    all you can set 'linotp.errors' in the LinOTP Config. Then the HTTP
    status defined by 'httperror' will ONLY be sent when the error that
    occurs in LinOTP matches one of the errors defined in 'linotp.errors'. In
    other cases '200 OK' with error code and description in the body will be
    returned.
    If 'linotp.errors' is unset all errors will cause responses with HTTP
    status 'httperror'.
    For example:
      Setup 1:
        * The client sends httperror=777 in the request
        * linotp.errors=233,567
        Case 1.1: An exception is raised in LinOTP that has errId 233.
          - LinOTP will return a response with HTTP status 777.
        Case 1.2: An exception is raised with errId 555
          - LinOTP will return a response with HTTP status 200.
      Setup 2:
        * The client sends httperror (empty) in the request
        * linotp.errors=233,567
        Case 2.1: An exception is raised in LinOTP that has errId 233.
          - LinOTP will return a response with HTTP status 500.
        Case 2.2: An exception is raised with errId 555
          - LinOTP will return a response with HTTP status 200.
      Setup 3:
        * The client sends httperror (empty) in the request
        * linotp.errors is not set
        Case 3.1: An exception is raised in LinOTP that has errId 233.
          - LinOTP will return a response with HTTP status 500.
        Case 3.2: An exception is raised with errId 555
          - LinOTP will return a response with HTTP status 500.
      Setup 4:
        * NO httperror in request
        * linotp.errors=233,567 (or is unset, does not matter)
        Case 4.1: An exception is raised in LinOTP that has errId 233.
          - LinOTP will return a response with HTTP status 200.
        Case 4.2: An exception is raised with errId 555
          - LinOTP will return a response with HTTP status 200.

    :param response:  the pylon response object
    :type  response:  response object
    :param exception: should be a linotp exception (see linotp.lib.error.py) or a free text error
    :type  exception: exception or str
    :param id:        id value, for future versions
    :type  id:        int

    :return:     json rendered string result
    :rtype:      string

    """
    ret = ""
    errId = -311

    # handle the different types of exception:
    ## Exception, LinOtpError, str/unicode
    if hasattr(exception, "__class__") is True and isinstance(exception, Exception):
        errDesc = str(exception)
        if isinstance(exception, LinotpError):
            errId = exception.getId()

    elif isinstance(exception, str):
        errDesc = str(exception)

    else:
        errDesc = f"{exception!r}"

    # check if we have an additional request parameter 'httperror'
    # which triggers the error to be delivered as HTTP Error
    error_code = _get_httperror_code_from_params()

    send_custom_http_status = False
    if error_code is not None:
        # Client wants custom HTTP status
        linotp_errors = getLinotpConfig().get("linotp.errors", None)
        if not linotp_errors:
            # Send custom HTTP status in every error case
            send_custom_http_status = True
        else:
            # Only send custom HTTP status in defined error cases
            if str(errId) in linotp_errors.split(","):
                send_custom_http_status = True
            else:
                send_custom_http_status = False

    if send_custom_http_status:
        # Send HTML response with HTTP status 'httperror'

        # Always set a reason, when no standard one found (e.g. custom HTTP
        # code like 444) use 'LinOTP Error'
        reason = "LinOTP Error"
        if error_code in standard_http_errors:
            reason = standard_http_errors[error_code]
        code = error_code
        status = f"{error_code} {reason}"
        desc = f"[{get_version()}] {errId}: {errDesc}"
        ret = resp % (code, status, code, status, desc)

        return Response(response=ret, status=code, mimetype="text/html")

    else:
        # Send JSON response with HTTP status 200 OK
        res = {
            "jsonrpc": get_api_version(),
            "result": {
                "status": False,
                "error": {
                    "code": errId,
                    "message": errDesc,
                },
            },
            "version": get_version(),
            "versionNumber": get_version_number(),
            "id": id,
        }
        data = json.dumps(res, indent=3)
        return Response(response=data, status=200, mimetype="application/json")


def sendResult(obj, id=1, opt=None, status=True):
    """
    sendResult - return an json result document

    :param obj:      simple result object like dict, string or list
    :type  obj:      dict or list or string/unicode
    :param  id:      id value, for future versions
    :type   id:      int
    :param opt:      optional parameter, which allows to provide more detail
    :type  opt:      None or simple type like dict, list or string/unicode

    :return:     json rendered string result
    :rtype:      string

    """

    res = {
        "jsonrpc": get_api_version(),
        "result": {
            "status": status,
            "value": obj,
        },
        "version": get_version(),
        "versionNumber": get_version_number(),
        "id": id,
    }

    if opt is not None and len(opt) > 0:
        res["detail"] = opt

    data = json.dumps(res, indent=3)

    return Response(response=data, status=200, mimetype="application/json")


def sendResultIterator(
    obj, id=1, opt=None, rp=None, page=None, request_context_copy=None
):
    """
    sendResultIterator - return an json result document in a streamed mode
                         which requires a request context to be avaliable

    :param obj: iterator of generator object like dict, string or list
    :param  id: id value, for future versions
    :param opt: optional parameter, which allows to provide more detail
    :param rp: results per page
    :param page: number of page

    :return: generator of response data (yield)
    """

    # establish the request context within the pylons middleware

    api_version = get_api_version()
    linotp_version = get_version()

    res = {
        "jsonrpc": api_version,
        "result": {
            "status": True,
            "value": "[DATA]",
        },
        "version": linotp_version,
        "id": id,
    }

    err = {
        "jsonrpc": api_version,
        "result": {
            "status": False,
            "error": {},
        },
        "version": linotp_version,
        "id": id,
    }

    start_at = 0
    stop_at = 0
    if page is not None:
        rp = int(rp) if rp else 16
        try:
            start_at = int(page) * rp
            stop_at = start_at + rp
        except ValueError as exx:
            err["result"]["error"] = {
                "code": 9876,
                "message": f"{exx!r}",
            }
            log.error("failed to convert paging request parameters: %r", exx)
            yield json.dumps(err)
            # finally we signal end of error result
            return

    typ = f"{type(obj)}"
    if "generator" not in typ and "iterator" not in typ:
        raise Exception(f"no iterator method for object {obj!r}")

    res = {
        "jsonrpc": api_version,
        "result": {
            "status": True,
            "value": "[DATA]",
        },
        "version": linotp_version,
        "id": id,
    }
    if page:
        res["result"]["page"] = int(page)

    if opt is not None and len(opt) > 0:
        res["detail"] = opt

    surrounding = json.dumps(res)
    prefix, postfix = surrounding.split('"[DATA]"')

    # first return the opening
    yield prefix + " ["

    sep = ""
    counter = 0
    for next_one in obj:
        # next_one = json.dumps(next_entry)
        # are we running in paging mode?
        if page is not None:
            if counter >= start_at and counter < stop_at:
                res = f"{sep}{next_one}\n"
                sep = ","
                yield res
            if counter >= stop_at:
                # stop iterating if we reached the last one of the page
                break
        else:
            # no paging - no limit
            res = f"{sep}{next_one}\n"
            sep = ","
            yield res
        counter = counter + 1

    # we add the amount of queried objects
    total = f'"queried" : {counter}'
    postfix = f", {total} {postfix}"

    # last return the closing
    yield "] " + postfix


def sendCSVResult(obj, flat_lines=False, filename="linotp-tokendata.csv"):
    """
    returns a CSV document of the input data (like in /admin/show)

    :param obj: The data, that gets serialized as CSV
    :type obj: JSON object
    :param flat_lines: If True the object only contains a list of the
                         dict { 'cell': ..., 'id': ... }
                       as in all the flexigrid functions.
    'type flat_lines: boolean
    """
    delim = "'"
    seperator = ";"
    content_type = "application/force-download"

    output = ""
    if not flat_lines:
        headers_printed = False
        data = obj.get("data", [])

        for row in data:
            # Do the header
            if not headers_printed:
                for k in list(data[0].keys()):
                    output += f"{delim}{k}{delim}{seperator} "
                output += "\n"
                headers_printed = True

            for val in list(row.values()):
                if isinstance(val, str):
                    value = val.replace("\n", " ")
                else:
                    value = val
                output += f"{delim}{value}{delim}{seperator} "
            output += "\n"
    else:
        for row in obj:
            for elem in row.get("cell", []):
                output += f"'{elem}'{seperator} "

            output += "\n"

    response = Response(response=output, status=200, mimetype=content_type)
    response.headers["Content-disposition"] = f"attachment; filename={filename}"

    return response


def json2xml(json_obj, line_padding=""):
    if isinstance(json_obj, list):
        return "\n".join(
            f"{line_padding}<value>{json2xml(sub_elem, line_padding)}</value>"
            for sub_elem in json_obj
        )

    if isinstance(json_obj, dict):
        return "\n".join(
            f"{line_padding}<{tag_name}>{json2xml(sub_obj, line_padding)}</{tag_name}>"
            for tag_name, sub_obj in json_obj.items()
        )

    return f"{line_padding}{json_obj}"


def sendXMLResult(obj, id=1, opt=None):
    """
    send the result as an xml format
    """

    xml_options = ""
    if opt:
        xml_options = "\n<options>" + json2xml(opt) + "</options>"
    xml_object = json2xml(obj)

    res = f"""<?xml version="1.0" encoding="UTF-8"?>
<jsonrpc version="2.0">
    <result>
        <status>True</status>
        <value>{xml_object}</value>
    </result>
    <version>{get_version()}</version>
    <id>{id}</id>{xml_options}
</jsonrpc>"""

    return Response(response=res, status=200, mimetype="text/xml")


def sendXMLError(exception, id=1):
    if not hasattr(exception, "getId"):
        errId = -311
        errDesc = str(exception)
    else:
        errId = exception.getId()
        errDesc = exception.getDescription()
    res = f'<?xml version="1.0" encoding="UTF-8"?>\
            <jsonrpc version="{get_api_version()}">\
            <result>\
                <status>False</status>\
                <error>\
                    <code>{errId}</code>\
                    <message>{errDesc}</message>\
                </error>\
            </result>\
            <version>{get_version()}</version>\
            <id>{id}</id>\
            </jsonrpc>'
    return Response(response=res, status=200, mimetype="text/xml")


def sendQRImageResult(data, param=None, id=1, typ="html"):
    """
    method
        sendQRImageResult

    arguments
        param    - the paramters of the request
        id       -
        html     - print qrcode wrapped by html or not

    """

    width = 0
    alt = None
    ret = None

    if param is None:
        param = {}

    if "qr" in param:
        typ = param.get("qr")
        del param["qr"]

    if "width" in param:
        width = param.get("width")
        del param["width"]

    if "alt" in param:
        alt = param.get("alt")
        del param["alt"]

    img_data = data
    if isinstance(data, dict):
        img_data = data.get("value", "")

    if typ in ["img", "embed"]:
        content_type = "text/html"
        ret = create_img(img_data, width, alt)

    elif typ in ["png"]:
        content_type = "image/png"
        ret = create_png(img_data)

    else:
        content_type = "text/html"
        ret = create_html(img_data, width, param)

    return Response(response=ret, status=200, mimetype=content_type)


def create_png(data, alt=None):
    """"""

    img = qrcode.make(data, image_factory=PyPNGImage)

    with io.BytesIO() as output:
        img.save(output)
        o_data = output.getvalue()

    return o_data


def create_img_src(data):
    """
    _create_img - create the qr image data

    :param data: input data that will be munched into the qrcode
    :type  data: string
    :param width: image width in pixel
    :type  width: int

    :return: <img/> taged data
    :rtype:  string
    """

    o_data = create_png(data)
    data_uri = base64.b64encode(o_data).decode()
    ret_img_src = f"data:image/png;base64,{data_uri}"

    return ret_img_src


def create_img(data, width=0, alt=None, img_id="challenge_qrcode"):
    """
    _create_img - create the qr image data

    :param data: input data that will be munched into the qrcode
    :type  data: string
    :param width: image width in pixel
    :type  width: int

    :return: <img/> taged data
    :rtype:  string
    """
    width_str = ""
    alt_str = ""

    img_src = create_img_src(data)

    if width != 0:
        width_str = f" width={int(width)} "

    if alt is not None:
        val = urllib.parse.urlencode({"alt": alt})
        alt_str = f" alt={val[len('alt=') :]} "

    ret_img = f'<img id="{img_id}" {alt_str} {width_str} src="{img_src}"/>'

    return ret_img


def create_html(data, width=0, alt=None, list_id="challenge_data"):
    """
    _create_html - create the qr image data embeded in html tag

    :param data: input data that will be munched into the qrcode
    :type  data: string
    :param width: image width in pixel
    :type  width: int

    :return: <img/> taged data
    :rtype:  string
    """
    alt_str = ""
    img = create_img(data, width=width, alt=data)

    if alt is not None:
        if isinstance(alt, str):
            alt_str = f"<p>{alt}</p>"
        elif isinstance(alt, dict):
            list_items = [
                f'<li> {key}: <span class="{key}">{value}</span> </li>'
                for key, value in alt.items()
            ]
            alt_str = f'<ul id="{list_id}">{"".join(list_items)}</ul>'
        elif isinstance(alt, list):
            list_items = [f"<li> {item} </li>" for item in alt]
            alt_str = f'<ul id="{list_id}">{"".join(list_items)}</ul>'

    ret_html = f"<html><body><div>{img}{alt_str}</div></body></html>"

    return ret_html


def sendCSVIterator(obj, headers=True):
    delim = '"'
    output = ""

    typ = f"{type(obj)}"
    if "generator" not in typ and "iterator" not in typ:
        raise Exception(f"no iterator method for object {obj!r}")

    try:
        for row in obj:
            row = json.loads(row)
            # do the header
            if headers:
                for key in row:
                    output += f"{delim}{key}{delim},"
                output += "\n"
                yield str(output)
                headers = False

            output = ""
            for val in list(row.values()):
                if isinstance(val, str):
                    value = val.replace("\n", " ")
                    output += f"{delim}{value}{delim}, "
                elif isinstance(val, int):
                    value = f"{val:d}"
                    output += f"{value}, "
                else:
                    output += f"{delim}{value}{delim}, "
                # output += "%s%s%s, " % (delim, value, delim)
            output += "\n"
            yield str(output)

    except Exception as exx:
        log.debug("error when iterating result for csv output")
        raise exx


def validate_transactions(response: Response) -> bool:
    """
    Returns `False` if there are transactions and none
    of them is validated.
    Otherwise returns `True`.
    """
    resp_json = response.json
    transactions = resp_json.get("detail", {}).get("transactions", {})
    if transactions:
        valid_transactions = {
            k: v
            for k, v in transactions.items()
            if v.get("status", "") == "closed" and v.get("valid_tan", False)
        }
        if not valid_transactions:
            return False

    return True


def was_login_successful(response: Response) -> bool:
    resp_json = response.json
    login_successful = resp_json.get("result", {}).get("value", False)
    # since result["value"] can also be a dict,
    # e.g. {"value": false, "failcount": 0},
    # we need to make this comparison:
    if isinstance(login_successful, dict):
        login_successful = login_successful.get("value")

    if not validate_transactions(response):
        # With no valid transaction,
        # the login was not successful.
        # This is needed because of how check_status works
        login_successful = False

    return login_successful


def get_details_for_response(response: Response) -> dict:
    """Returns details-dict when policy
        detail_on_success/detail_on_fail is set

    Args:
        login_successful (bool): flag wether login was successful
        user (User): User to check policy on. E.g. check if logged in admin has access to given User

    Returns:
        dict: dict with keys [realm, user, is_linotp_admin, tokentype, serial] or [error]
    """
    res = {}
    user = request_context.get("RequestUser")
    login_successful = was_login_successful(response)

    if is_auth_return(success=login_successful, user=user):
        if login_successful:
            realm = user.realm if user else None
            admin_realm = current_app.config["ADMIN_REALM_NAME"]

            # user info
            if not user:
                res["user"] = None
            else:
                try:
                    user_info = {
                        k: v if v else None
                        for k, v in user.info.items()
                        if k != "cryptpass"
                    }
                except Exception:
                    log.warning("No attributes found to return for user %s", user.login)
                    user_info = {"username": user.login}
                res["user"] = user_info
            # realm info
            res["realm"] = realm
            res["is_linotp_admin"] = (
                realm.lower() == admin_realm.lower() if realm else None
            )
            # token info
            res["tokentype"] = request_context.get("TokenType")
            res["serial"] = request_context.get("TokenSerial")
        else:
            res["error"] = g.audit.get("action_detail")

    return res


def apply_detail_policies(response: Response):
    """
    If policies detail_on_success/detail_on_fail is set,
    we extend the response with the corresponding details
    """
    resp_json = response.json
    if not resp_json:
        return

    additional_details = get_details_for_response(response)
    if not additional_details:
        return

    # Update existing `detail` with additional_details
    resp_json = deep_update(resp_json, {"detail": additional_details})
    # And overwrite them in the original response
    response.set_data(json.dumps(resp_json, indent=3).encode())


# eof#######################################################

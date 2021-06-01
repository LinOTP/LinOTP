# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
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
from flask import Response, current_app, jsonify
from flask import request as flask_request

from linotp.flap import request
from linotp.flap import tmpl_context as c
from linotp.lib.context import request_context, request_context_safety
from linotp.lib.error import LinotpError
from linotp.lib.util import get_api_version, get_version

optional = True
required = False

LINOTP_ERRORS = [707]

httpErr = {
        '400': 'Bad Request',
        '401': 'Unauthorized',
        '403': 'Forbidden',
        '404': 'Not Found',
        '410': 'Gone',
        '500': 'Internal Server Error',
        '501': 'Not Implemented',
        '502': 'Bad Gateway',
        '503': 'Service Unavailable',
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


def _get_httperror_from_params(request):
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
        httperror = request_params.get('httperror', None)
    except UnicodeDecodeError as exx:
        log.exception("Could not extract 'httperror' from params because some "
                "parameter contains invalid Unicode. Trying to extract "
                "directly from query_string. Exception: %r", exx)
        from urllib.parse import parse_qs
        params = parse_qs(flask_request.query_string)
        if b'httperror' in params:
            httperror_list = params[b'httperror']
            if len(httperror_list) > 1:
                log.warning("Parameter 'httperror' specified multiple times. "
                        "Using last value '%r'. All values: %r",
                        httperror_list[-1], httperror_list)
            httperror = httperror_list[-1]
    except Exception as exx:
        log.exception("Exception while extracting 'httperror' from params. "
                "Falling back to default LinOTP behaviour httperror=None. "
                "Exception %r", exx)
        httperror = None
    if httperror is not None:
        try:
            httperror = str(int(httperror))
        except ValueError as value_error:
            log.warning("'%r' is not a valid integer. Using '500' as "
                    "fallback. ValueError %r", httperror, value_error)
            httperror = '500'
    return httperror


def sendError(_response, exception, id=1, context=None):
    '''
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

    remark for 'context' parameter:
     the 'context' is especially required to catch errors from the _before_
     methods. The return of a _before_ must be of type response and
     must have the attribute response._exception set, to stop further
     processing, which otherwise will have ugly results!!

    :param response:  the pylon response object
    :type  response:  response object
    :param exception: should be a linotp exception (s. linotp.lib.error.py)
    :type  exception: exception
    :param id:        id value, for future versions
    :type  id:        int
    :param context:   default is None or 'before'
    :type  context:   string

    :return:     json rendered sting result
    :rtype:      string

    '''
    ret = ''
    errId = -311

    ## handle the different types of exception:
    ## Exception, LinOtpError, str/unicode
    if hasattr(exception, '__class__') is True \
    and isinstance(exception, Exception):
        errDesc = str(exception)
        if isinstance(exception, LinotpError):
            errId = exception.getId()

    elif isinstance(exception, str):
        errDesc = str(exception)

    else:
        errDesc = "%r" % exception

    ## check if we have an additional request parameter 'httperror'
    ## which triggers the error to be delivered as HTTP Error
    httperror = _get_httperror_from_params(request)

    send_custom_http_status = False
    if httperror is not None:
        # Client wants custom HTTP status
        linotp_errors = c.linotpConfig.get('linotp.errors', None)
        if not linotp_errors:
            # Send custom HTTP status in every error case
            send_custom_http_status = True
        else:
            # Only send custom HTTP status in defined error cases
            if str(errId) in linotp_errors.split(','):
                send_custom_http_status = True
            else:
                send_custom_http_status = False

    if send_custom_http_status:
        # Send HTML response with HTTP status 'httperror'

        # Always set a reason, when no standard one found (e.g. custom HTTP
        # code like 444) use 'LinOTP Error'
        reason = httpErr.get(httperror, 'LinOTP Error')
        code = httperror
        status = "%s %s" % (httperror, reason)
        desc = '[%s] %d: %s' % (get_version(), errId, errDesc)
        ret = resp % (code, status, code, status, desc)

        response = Response(response=ret, status=code, mimetype= 'text/html')

        if context in ['before', 'after']:
            response._exception = exception

        return response

    else:
        # Send JSON response with HTTP status 200 OK
        res = { "jsonrpc": get_api_version(),
                "result" :
                    {"status": False,
                        "error": {
                            "code"    :   errId,
                            "message" :   errDesc,
                            },
                    },
                 "version": get_version(),
                 "id": id
            }
        data = json.dumps(res, indent=3)
        response = Response(response=data, status=200, mimetype= 'application/json')

        if context in ['before', 'after']:
            response._exception = exception

        return response


def sendResult(response, obj, id=1, opt=None, status=True):
    '''
        sendResult - return an json result document

        :param response: the pylons response object
        :type  response: response object
        :param obj:      simple result object like dict, sting or list
        :type  obj:      dict or list or string/unicode
        :param  id:      id value, for future versions
        :type   id:      int
        :param opt:      optional parameter, which allows to provide more detail
        :type  opt:      None or simple type like dict, list or string/unicode

        :return:     json rendered sting result
        :rtype:      string

    '''

    res = { "jsonrpc": get_api_version(),
            "result": { "status": status,
                        "value": obj,
                      },
           "version": get_version(),
           "id": id }

    if opt is not None and len(opt) > 0:
        res["detail"] = opt

    data = json.dumps(res, indent=3)

    return Response(response=data, status=200, mimetype= 'application/json')


def sendResultIterator(obj, id=1, opt=None, rp=None, page=None,
                       request_context_copy=None):
    '''
        sendResultIterator - return an json result document in a streamed mode
                             which requires a request context to be avaliable

        :param obj: iterator of generator object like dict, string or list
        :param  id: id value, for future versions
        :param opt: optional parameter, which allows to provide more detail
        :param rp: results per page
        :param page: number of page

        :return: generator of response data (yield)
    '''


    # establish the request context within the pylons middleware

    api_version = get_api_version()
    linotp_version = get_version()

    res = {"jsonrpc": api_version,
            "result": {"status": True,
                       "value": "[DATA]",
                      },
           "version": linotp_version,
           "id": id}

    err = {"jsonrpc": api_version,
            "result":
                {"status": False,
                 "error": {},
                },
            "version": linotp_version,
            "id": id
        }


    start_at = 0
    stop_at = 0
    if page:
        if not rp:
            rp = 16
        try:
            start_at = int(page) * int(rp)
            stop_at = start_at + int(rp)
        except ValueError as exx:
            err['result']['error'] = {
                            "code": 9876,
                            "message": "%r" % exx,
                            }
            log.exception("failed to convert paging request parameters: %r"
                          % exx)
            yield json.dumps(err)
            # finally we signal end of error result
            return

    typ = "%s" % type(obj)
    if 'generator' not in typ and 'iterator' not in typ:
        raise Exception('no iterator method for object %r' % obj)

    res = {"jsonrpc": api_version,
            "result": {"status": True,
                       "value": "[DATA]",
                      },
           "version": linotp_version,
           "id": id}
    if page:
        res['result']['page'] = int(page)

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
        counter = counter + 1
        # are we running in paging mode?
        if page:
            if counter >= start_at and counter < stop_at:
                res = "%s%s\n" % (sep, next_one)
                sep = ','
                yield res
            if counter >= stop_at:
                # stop iterating if we reached the last one of the page
                break
        else:
            # no paging - no limit
            res = "%s%s\n" % (sep, next_one)
            sep = ','
            yield res

    # we add the amount of queried objects
    total = '"queried" : %d' % counter
    postfix = ', %s %s' % (total, postfix)

    # last return the closing
    yield "] " + postfix


def sendCSVResult(response, obj, flat_lines=False,
                  filename="linotp-tokendata.csv"):
    '''
    returns a CSV document of the input data (like in /admin/show)

    :param response: The pylons response object
    :param obj: The data, that gets serialized as CSV
    :type obj: JSON object
    :param flat_lines: If True the object only contains a list of the
                         dict { 'cell': ..., 'id': ... }
                       as in all the flexigrid functions.
    'type flat_lines: boolean
    '''
    delim = "'"
    seperator = ';'
    content_type = "application/force-download"

    output = ""
    if not flat_lines:

        headers_printed = False
        data = obj.get("data", [])

        for row in data:
            # Do the header
            if not headers_printed:
                for k in list(data[0].keys()):
                    output += "%s%s%s%s " % (delim, k, delim, seperator)
                output += "\n"
                headers_printed = True

            for val in list(row.values()):
                if isinstance(val, str):
                    value = val.replace("\n", " ")
                else:
                    value = val
                output += "%s%s%s%s " % (delim, value, delim, seperator)
            output += "\n"
    else:
        for l in obj:
            for elem in l.get("cell", []):
                output += "'%s'%s " % (elem, seperator)

            output += "\n"

    response = Response(response=output, status=200, mimetype=content_type)
    response.headers['Content-disposition'] = (
        'attachment; filename=%s' % filename)

    return response


def json2xml(json_obj, line_padding=""):
    result_list = list()

    json_obj_type = type(json_obj)

    if json_obj_type is list:
        for sub_elem in json_obj:
            result_list.append("%s<value>" % line_padding)
            result_list.append(json2xml(sub_elem, line_padding))
            result_list.append("%s</value>" % line_padding)

        return "".join(result_list)

    if json_obj_type is dict:
        for tag_name in json_obj:
            sub_obj = json_obj[tag_name]
            result_list.append("%s<%s>" % (line_padding, tag_name))
            result_list.append(json2xml(sub_obj, "" + line_padding))
            result_list.append("%s</%s>" % (line_padding, tag_name))

        return "".join(result_list)

    return "%s%s" % (line_padding, json_obj)


def sendXMLResult(_response, obj, id=1, opt=None):
    """
    send the result as an xml format
    """

    res = '<?xml version="1.0" encoding="UTF-8"?>\
            <jsonrpc version="%s">\
            <result>\
                <status>True</status>\
                <value>%s</value>\
            </result>\
            <version>%s</version>\
            <id>%s</id>\
            </jsonrpc>' % (get_api_version(), obj, get_version(), id)
    xml_options = ""
    if opt:
        xml_options = "\n<options>" + json2xml(opt) + "</options>"
    xml_object = json2xml(obj)

    res = """<?xml version="1.0" encoding="UTF-8"?>
<jsonrpc version="2.0">
    <result>
        <status>True</status>
        <value>%s</value>
    </result>
    <version>%s</version>
    <id>%s</id>%s
</jsonrpc>""" % (xml_object, get_version(), id, xml_options)

    return Response(response=res, status=200, mimetype='text/xml')


def sendXMLError(_response, exception, id=1):

    if not hasattr(exception, "getId"):
        errId = -311
        errDesc = str(exception)
    else:
        errId = exception.getId()
        errDesc = exception.getDescription()
    res = '<?xml version="1.0" encoding="UTF-8"?>\
            <jsonrpc version="%s">\
            <result>\
                <status>False</status>\
                <error>\
                    <code>%s</code>\
                    <message>%s</message>\
                </error>\
            </result>\
            <version>%s</version>\
            <id>%s</id>\
            </jsonrpc>' % (get_api_version(), errId, errDesc, get_version(), id)
    return Response(response=res, status=200, mimetype='text/xml')


def sendQRImageResult(response, data, param=None, id=1, typ='html'):
    '''
    method
        sendQRImageResult

    arguments
        response - the pylon response object
        param    - the paramters of the request
        id       -
        html     - print qrcode wrapped by html or not

    '''

    width = 0
    alt = None
    ret = None

    if param is None:
        param = {}

    if 'qr' in param:
        typ = param.get('qr')
        del param['qr']

    if 'width' in param:
        width = param.get('width')
        del param['width']

    if 'alt' in param:
        alt = param.get('alt')
        del param['alt']

    img_data = data
    if isinstance(data, dict):
        img_data = data.get('value', "")

    if typ in ['img', 'embed']:
        content_type = 'text/html'
        ret = create_img(img_data, width, alt)

    elif typ in ['png']:
        content_type = 'image/png'
        ret = create_png(img_data)
        response.content_length = len(ret)

    else:
        content_type = 'text/html'
        ret = create_html(img_data, width, param)

    return Response(response=ret, status=200, mimetype=content_type)


def create_png(data, alt=None):
    '''

    '''

    img = qrcode.make(data)

    with io.BytesIO() as output:
        img.save(output)
        o_data = output.getvalue()

    return o_data


def create_img_src(data):
    '''
        _create_img - create the qr image data

        :param data: input data that will be munched into the qrcode
        :type  data: string
        :param width: image width in pixel
        :type  width: int

        :return: <img/> taged data
        :rtype:  string
    '''

    o_data = create_png(data)
    data_uri = base64.b64encode(o_data).decode()
    ret_img_src = 'data:image/png;base64,%s' % data_uri

    return ret_img_src


def create_img(data, width=0, alt=None, img_id="challenge_qrcode"):
    '''
        _create_img - create the qr image data

        :param data: input data that will be munched into the qrcode
        :type  data: string
        :param width: image width in pixel
        :type  width: int

        :return: <img/> taged data
        :rtype:  string
    '''
    width_str = ''
    alt_str = ''

    img_src = create_img_src(data)

    if width != 0:
        width_str = " width=%d " % (int(width))

    if alt is not None:
        val = urllib.parse.urlencode({'alt': alt})
        alt_str = " alt=%r " % (val[len('alt='):])

    ret_img = ('<img id="%s" %s  %s  src="%s"/>' %
               (img_id, alt_str, width_str, img_src))

    return ret_img


def create_html(data, width=0, alt=None, list_id="challenge_data"):
    '''
        _create_html - create the qr image data embeded in html tag

        :param data: input data that will be munched into the qrcode
        :type  data: string
        :param width: image width in pixel
        :type  width: int

        :return: <img/> taged data
        :rtype:  string
    '''
    alt_str = ''
    img = create_img(data, width=width, alt=data)

    if alt is not None:
        if isinstance(alt, str):
            alt_str = '<p>%s</p>' % alt
        elif isinstance(alt, dict):
            alta = []
            for k in list(alt.keys()):
                alta.append('<li> %s: <span class="%s">%s</span> </li>' % (k, k, alt.get(k)))
            alt_str = '<ul id="%s">%s</ul>' % ( list_id, " ".join(alta))
        elif isinstance(alt, list):
            alta = []
            for k in alt:
                alta.append('<li> %s </li>' % (k))


    ret_html = '<html><body><div>%s%s</div></body></html>' % (img , alt_str)

    return ret_html


def sendCSVIterator(obj, headers=True):
    delim = '"'
    output = ""

    typ = "%s" % type(obj)
    if 'generator' not in typ and 'iterator' not in typ:
        raise Exception('no iterator method for object %r' % obj)

    try:
        for row in obj:
            row = json.loads(row)
            # do the header
            if headers:
                for key in row:
                    output += "%s%s%s," % (delim, key, delim)
                output += "\n"
                yield str(output)
                headers = False

            output = ""
            for val in list(row.values()):
                if isinstance(val, str):
                    value = val.replace("\n", " ")
                    output += "%s%s%s, " % (delim, value, delim)
                elif isinstance(val, int):
                    value = '%d' % val
                    output += "%s, " % (value)
                else:
                    output += "%s%s%s, " % (delim, value, delim)
                # output += "%s%s%s, " % (delim, value, delim)
            output += "\n"
            yield str(output)

    except Exception as exx:
        log.debug('error when iterating result for csv output')
        raise exx

#eof#######################################################

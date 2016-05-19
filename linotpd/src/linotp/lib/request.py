# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

" support redirecting requests to remote systems on base of policy defintion "

import logging

# this is needed for the http request
import json
import copy
import httplib2
import urllib
import urlparse

# this is needed for the radius request
import pyrad.packet
from pyrad.client import Client
from pyrad.dictionary import Dictionary

log = logging.getLogger(__name__)


class RemoteRequest(object):
    """
    Request is the class to handle the forwarding of request
    to external, remote sources and servers. Supported is currently either
    requests to a Radius server or requests to an remote LinOTP server via
    http. The forwarding server defintion is done in the forward policy, where
    a server is defined in the URI format.

     action:
         forward_server= http://localhost:5001/validate/check

    for defining a radius server connection is as well required to define
    the password for the symetric connection, the secret. The secret could
    be provided as an additional parameter to the radius server url.

    action:
        forward_server= radius://localhost:1812/?secret=shared_secret
    """

    def __init__(self, server, env=None):
        """
        build up the request class
        - by parsing the server definition
        - by preserving the context/config info

        :param servers: the server description from the policy definition
        :param env: the environment definition, for accessing for example the
                    radius dict
        :return: tuple of status as boolean and reply as dict with detail info
        """

        self.env = {}
        if env:
            self.env = env

        self.server = server

    @staticmethod
    def parse_url(url):
        parsed = urlparse.urlparse(url)
        url_info = {'scheme': parsed.scheme,
                    'netloc': parsed.netloc,
                    'port': parsed.port,
                    'hostname': parsed.hostname,
                    'path': parsed.path,
                    'params': parsed.params,
                    'query': parsed.query,
                    'fragment': parsed.fragment,
                    'secret': parsed.password,
                    'url': url}

        if not parsed.query:
            _path, _sep, query = parsed.path.partition('?')
        else:
            query = parsed.query

        query_parts = query.split('&')
        q = {}
        for query_part in query_parts:
            if '=' in query:
                key, value = query_part.split('=')
            else:
                key = query
                value = ''
            # only add if key is not an empty strings
            if key.strip():
                q[key.strip()] = value.strip()

        url_info['query_params'] = q
        return url_info


class HttpRequest(RemoteRequest):
    """
    HTTP request forwarding handler
    """

    def do_request(self, user, password, options=None):
        """
        run the http request against the remote host

        :param user: the requesting user (required)
        :param password: the password which should be checked on the remote
                            host
        :param options: dict which provides additional request parameter. e.g
                        for challenge response

        :return: Tuple of (success, and reply=remote response)
        """
        log.debug("do_request")

        params = {}
        params['pass'] = password.encode("utf-8")
        params['user'] = user.login

        if user.realm:
            params['realm'] = user.realm

        for key, value in options.items():
            params[key] = value.encode("utf-8")

        server_config = RemoteRequest.parse_url(self.server)
        query_params = server_config.get("query_params", {})
        ssl_verify = (query_params.get("verify_ssl_certificate", '').lower()
                      == "true")

        res = False
        reply = {}
        content = None

        try:
            # prepare the url
            request_url = "%(scheme)s://%(netloc)s%(path)s" % server_config

            # prepare the submit and receive headers
            headers = {"Content-type": "application/x-www-form-urlencoded",
                       "Accept": "text/plain", 'Connection': 'close'}

            data = urllib.urlencode(params)
            # submit the request
            try:
                # is httplib compiled with ssl?
                ns = not ssl_verify
                http = httplib2.Http(disable_ssl_certificate_validation=ns)

            except TypeError as exx:
                # not so on squeeze:
                # TypeError: __init__() got an unexpected keyword argument
                # 'disable_ssl_certificate_validation'

                log.warning("httplib2 'disable_ssl_certificate_validation'"
                            " attribute error: %r", exx)
                # so we run in fallback mode
                http = httplib2.Http()

            (resp, content) = http.request(request_url,
                                           method="POST",
                                           body=data,
                                           headers=headers)
            if resp.status not in [200]:
                raise Exception("Http Status not ok (%s)", resp.status)

            result = json.loads(content)
            status = result.get('result', {}).get('status', False)
            log.debug("Status: %r", status)

            if status == True:
                if result.get('result', {}).get('value', False) is True:
                    res = True

            # in case of a remote challenge respone transaction
            if "detail" in result:
                reply = copy.deepcopy(result.get("detail", {}))
                res = False

        except Exception as exx:
            log.exception("Error %r getting response from "
                          "remote Server (%r):%r", exx, request_url, content)


        return res, reply


class RadiusRequest(RemoteRequest):
    """
    Radius request forwarding handler
    """

    def do_request(self, user, password, options=None):
        """
        run the radius request against the remote host

        :param user: the requesting user (required)
        :param password: the password which should be checked on the remote
                            host
        :param options: dict which provides additional request parameter. e.g
                        for challenge response

        :return: Tuple of (success, and reply=remote response)
        """
        log.debug("do_request")

        reply = {}
        res = False

        server_config = RemoteRequest.parse_url(self.server)
        radiusServer = server_config['netloc']
        radiusUser = user.login

        # Read the secret - from the parameter list :-)
        query_params = server_config.get("query_params", {})
        secret = query_params.get("secret", '')
        radiusSecret = secret

        # here we also need to check for radius.user
        log.debug(" checking OTP len:%s on radius server: %s,"
                  "  user: %s", len(password), radiusServer, radiusUser)

        try:
            # pyrad does not allow to set timeout and retries.
            # it defaults to retries=3, timeout=5

            if ':' in radiusServer:
                r_server, _sep, r_authport = radiusServer.partition(':')
                r_authport = int(r_authport)
            else:
                r_server = radiusServer
                r_authport = 1812

            nas_identifier = self.env.get("radius.nas_identifier", "LinOTP")
            r_dict = self.env.get("radius.dictfile", "/etc/linotp2/dictionary")

            log.debug("NAS Identifier: %r, Dictionary: %r",
                      nas_identifier, r_dict)

            log.debug("constructing client object with server: %r, port: %r,"
                      " secret: %r", r_server, r_authport, radiusSecret)

            srv = Client(server=r_server,
                         authport=r_authport,
                         secret=radiusSecret.encode('utf-8'),
                         dict=Dictionary(r_dict))

            req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                User_Name=radiusUser.encode('utf-8'),
                                NAS_Identifier=nas_identifier.encode('utf-8'))

            req["User-Password"] = req.PwCrypt(password)
            if "transactionid" in options or 'state' in options:
                req["State"] = str(options.get('transactionid',
                                               options.get('state')))

            response = srv.SendPacket(req)

            if response.code == pyrad.packet.AccessChallenge:
                opt = {}
                for attr in response.keys():
                    opt[attr] = response[attr]
                res = False
                log.debug("challenge returned %r ", opt)
                # now we map this to a linotp challenge
                if "State" in opt:
                    reply["transactionid"] = opt["State"][0]

                if "Reply-Message" in opt:
                    reply["message"] = opt["Reply-Message"][0]

            elif response.code == pyrad.packet.AccessAccept:
                log.info("Radiusserver %s granted "
                         "access to user %s.", r_server, radiusUser)
                res = True
            else:
                log.warning("Radiusserver %s"
                            "rejected access to user %s.",
                            r_server, radiusUser)
                res = False

        except Exception as ex:
            log.exception("Error contacting radius Server: %r", ex)

        return (res, reply)

### eof #######################################################################

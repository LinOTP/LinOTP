# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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

from linotp.lib.context import request_context as context

log = logging.getLogger(__name__)


class Request(object):
    """
    Request is the class to handle the forwarding of request
    to external, remote sources and servers. Supported is currently either
    requests to a Radius server or requests to an remote LinOTP server via
    http. The forwarding server defintion is done in the forward policy, where
    a list of servers is defined in the URI format. Parameters in URI defintion
    of the policy could contain multiple server defintions, which are separated
    via ';'
     action = http://localhost:5001/validate/check;\
              http://127.0.0.1:5001/validate/check
    """

    def __init__(self, servers):
        """
        build up the request class
        - by parsing the server definition

        :param servers: the server description from the policy definition
        :return: tuple of status as boolean and reply as dict with detail info
        """

        self.sysconfig = context['SystemConfig']
        self.config = {}

        # split the servers along the ';'
        for server in servers.split(';'):
            parsed = urlparse.urlparse(server)
            self.config[parsed.hostname] = {'scheme': parsed.scheme,
                                            'netloc': parsed.netloc,
                                            'port': parsed.port,
                                            'hostname': parsed.hostname,
                                            'path': parsed.path,
                                            'params': parsed.params,
                                            'query': parsed.query,
                                            'fragment': parsed.fragment,
                                            'secret': parsed.password,
                                            'url': server}
        self.hsm = context['hsm']

    @staticmethod
    def get_server_params(server_config):
        """
        helper method to extract the parameter key, value dict
        from the server url parameter

        :param server_config:
        """
        # parameters in the policy server url may overwrite request params
        params = {}
        url = server_config.get('url')
        if '?' in url:
            add_param = urlparse.parse_qs(url.split('?')[1])
            for key, value in add_param.items():
                params[key] = value[0]
        return params


class HttpRequest(Request):
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

        verify_key = "remote.verify_ssl_certificate"
        ssl_verify = (str(self.sysconfig.get(verify_key, False))
                      .lower().strip() == 'true')

        params = {}
        params['pass'] = password.encode("utf-8")
        params['user'] = user.login
        params['realm'] = user.realm

        for key, value in options.items():
            params[key] = value.encode("utf-8")

        for server in self.config.keys():
            server_config = self.config[server]

            request_url = "%(scheme)s://%(netloc)s%(path)s" % server_config

            # parameters in the policy server url may overwrite request params
            params.update(Request.get_server_params(server_config))

            res = False
            reply = {}

            try:
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
                status = result['result']['status']
                log.debug("Request to %s returned status %r" %
                          (request_url, status))

                if status is True:
                    if result['result']['value'] is True:
                        res = True

                if "detail" in result:
                    reply = copy.deepcopy(result["detail"])
                    res = False

                # we break the servers loop if one request ended up here
                break

            except Exception as exx:
                log.exception("Error getting response from remote server "
                              "for url %r. Exception was %r", request_url, exx)

        return res, reply


class RadiusRequest(Request):
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

        reply = {}
        res = False

        for server in self.config.keys():
            server_config = self.config[server]
            radiusServer = server_config['netloc']
            radiusUser = user.login

            # Read the secret!!! - currently in plain text
            radiusSecret = server_config['secret']

            # here we also need to check for radius.user
            log.debug("Checking OTP len:%s on radius server %s,"
                      "User: %s", len(password), radiusServer, radiusUser)

            try:
                # pyrad does not allow to set timeout and retries.
                # it defaults to retries=3, timeout=5

                server = radiusServer.split(':')
                r_server = server[0]
                r_authport = 1812
                nas_identifier = self.sysconfig.get("radius.nas_identifier",
                                                    "LinOTP")
                r_dict = self.sysconfig.get("radius.dictfile",
                                            "/etc/linotp2/dictionary")

                if len(server) >= 2:
                    r_authport = int(server[1])
                log.debug("Radius: NAS Identifier: %r, "
                          "Dictionary: %r", nas_identifier, r_dict)

                log.debug("Radius: constructing client object "
                          "with server: %r, port: %r, secret: %r",
                          r_server, r_authport, radiusSecret)

                srv = Client(server=r_server,
                             authport=r_authport,
                             secret=radiusSecret,
                             dict=Dictionary(r_dict))

                req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                           User_Name=radiusUser.\
                                                     encode('ascii'),
                                           NAS_Identifier=nas_identifier.\
                                                          encode('ascii'))

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
                    log.debug("Radius: challenge returned %r ", opt)
                    # now we map this to a linotp challenge
                    if "State" in opt:
                        reply["transactionid"] = opt["State"][0]

                    if "Reply-Message" in opt:
                        reply["message"] = opt["Reply-Message"][0]

                elif response.code == pyrad.packet.AccessAccept:
                    log.info("Radius: Server %s granted "
                             "access to user %s.", r_server, radiusUser)
                    res = True
                else:
                    log.warning("Radius: Server %s"
                                "rejected access to user %s.",
                                r_server, radiusUser)
                    res = False

                # we break the servers look if one request ended up here
                break

            except Exception as ex:
                log.exception("Error contacting "
                              "radius Server: %r", ex)

        return (res, reply)

### eof #######################################################################

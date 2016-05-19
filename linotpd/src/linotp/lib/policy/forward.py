# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
""" policy processing """

import logging

import urlparse
import urllib

from linotp.lib.crypt import encryptPin
from linotp.lib.crypt import decryptPin

from linotp.lib.request import HttpRequest
from linotp.lib.request import RadiusRequest

log = logging.getLogger(__name__)


class ForwardServerPolicy(object):

    Path_index = 2
    Query_index = 4

    @staticmethod
    def prepare_forward(actions):

        if "forward_server=" not in actions:
            return actions

        result_actions = []
        for action in actions.split(','):
            if "forward_server=" in action.strip():
                action = ForwardServerPolicy._transform_action(action)
            result_actions.append(action)

        return ", ".join(result_actions)

    @staticmethod
    def _transform_action(action):
        """
        transform the action, especialy the secret parameter of the url
        """
        servers = []
        name, _sep, values = action.partition('=')
        for value in values.split(' '):
            # decompose the server url to identify, if there is a secret inside
            parsed_server = urlparse.urlparse(value)

            # the urlparse has a bug,, where in elder versions, the
            # path is not split from the query
            if not parsed_server.query:
                path, _sep, query = parsed_server.path.partition('?')
            else:
                path = parsed_server.path
                query = parsed_server.query

            # in gereal url parsing allows mutiple entries per key
            # but we support here only one
            params = urlparse.parse_qs(query)
            for key, entry in params.items():
                params[key] = entry[0]

            # finally we found the query parameters
            if 'secret' in params:
                secret = params['secret']
                params['encsecret'] = encryptPin(secret)
                del params['secret']

            # build the server url with the encrypted param:
            # as the named tuple is not updateable, we have to convert this
            # into an list to make the update and then back to a tuple to
            # create an url from this
            parsed_list = list(parsed_server[:])
            parsed_list[ForwardServerPolicy.Path_index] = path.strip()
            parsed_list[ForwardServerPolicy.Query_index] = \
                                                urllib.urlencode(params)
            server_url = urlparse.urlunparse(tuple(parsed_list))

            servers.append(server_url)

        ret = '='.join([name, ' '.join(servers)])
        return ret

    @staticmethod
    def do_request(servers, env, user, passw, options):
        """
        make the call to the foreign server
        """
        log.debug("start request to foreign server: %r" % servers)

        for server in servers.split(' '):
            parsed_server = urlparse.urlparse(server)

            # the urlparse has a bug,, where in elder versions, the
            # path is not split from the query
            if not parsed_server.query:
                path, _sep, query = parsed_server.path.partition('?')
            else:
                path = parsed_server.path
                query = parsed_server.query

            # finally we found the query parameters
            params = urlparse.parse_qs(query)
            for key, entry in params.items():
                params[key] = entry[0]

            if 'encsecret' in params:
                params['secret'] = decryptPin(params['encsecret'])
                del params['encsecret']

            parsed_list = list(parsed_server[:])
            parsed_list[ForwardServerPolicy.Path_index] = path.strip()
            parsed_list[ForwardServerPolicy.Query_index] = \
                                                urllib.urlencode(params)
            server_url = urlparse.urlunparse(tuple(parsed_list))

            if 'radius://' in server_url:
                rad = RadiusRequest(server=server_url, env=env)
                res, opt = rad.do_request(user, passw, options)
                return res, opt
            elif 'http://' in server_url or 'https://' in server_url:
                http = HttpRequest(server=server_url, env=env)
                res, opt = http.do_request(user, passw, options)
                return res, opt

#eof###########################################################################

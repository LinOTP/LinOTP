# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2018 KeyIdentity GmbH
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
'''
'''

import requests as http_requests
from urlparse import urlparse
import os

class ProviderBase(object):

    @staticmethod
    def load_proxy(configDict):
        """
        return the proxy defintion from the configuartion

        :param configDict:
        :return: the proxy definition dict like {https: 'https_proxy' ..}
        """

        if 'proxy' not in configDict:
            return None

        proxy_conf = configDict['proxy']

        # verify the url scheme
        parsed_url = urlparse(proxy_conf)
        if parsed_url.scheme not in ['http', 'https']:
            raise http_requests.exceptions.InvalidSchema(proxy_conf)

        if parsed_url.path and parsed_url.path != '/':
            raise http_requests.exceptions.InvalidSchema(proxy_conf)

        if not proxy_conf:
            return None

        proxy = {}
        if proxy_conf.startswith('https:'):
            proxy['https'] = proxy_conf
        else:
            proxy['http'] = proxy_conf

        return proxy

    @staticmethod
    def load_server_url(configDict, server_url_key='server_url'):
        """
        return the server url

        :param configDict:
        :return: return the validated server url
        """
        server_url = configDict[server_url_key]

        parsed_url = urlparse(server_url)
        if parsed_url.scheme not in ['http', 'https']:
            raise http_requests.exceptions.InvalidSchema(server_url)

        return server_url

    @staticmethod
    def load_server_cert(configDict):
        """
        return the server certificate from the configuration

        :param configDict:
        :return: return the validated server certificate reference
        """

        server_cert = configDict.get('server_certificate')

        if not server_cert:
            return server_cert

        # server cert can be a string (file location, cert dir)
        # None or not present (cert gets fetched from local trust
        # store) or False (no certificate verification)

        if (not os.path.isfile(server_cert) and
           not os.path.isdir(server_cert)):
            raise IOError("server certificate verification could not"
                          " be made as certificate could not be found"
                          " %r" % server_cert)

        return server_cert

    @staticmethod
    def load_client_cert(configDict, client_cert_key='access_certificate'):
        """
        return the client certificate from the configuration
        
        :param configDict:
        :return: return the validated client certificate reference
        """

        client_cert = configDict.get(client_cert_key)
        if client_cert and not os.path.isfile(client_cert):
            raise IOError("required authenticating client"
                          " cert could not be found %r" %
                          client_cert)

        return client_cert

    @staticmethod
    def load_timeout(configDict, timeout_default=None):
        """
            simple timeout or timeout tuple

        timeout could come with capital letter
        and could be a
         - simple timeout (float) or
         - a tuple of connection and request timeout (float)

        :param configDict: the configuration dictionary
        :param timeout_default: a fallback for the timeout
        :return: None, a float or a tuple of connection and network timeout
        """

        if 'timeout' in configDict or 'Timeout' in configDict:
            timeout = configDict.get('timeout', configDict.get('Timeout'))

            if ',' in timeout:

                conection_timeout, request_timeout = timeout.split(',')
                return (float(conection_timeout), float(request_timeout))

            else:
                return float(timeout)

        else:

            return timeout_default

# eof #

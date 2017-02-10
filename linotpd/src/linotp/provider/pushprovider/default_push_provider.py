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
'''
* implementation of the KeyIdentity PushProvider
'''


import os
import logging
import requests
from urlparse import urlparse

from linotp.provider import provider_registry
from linotp.provider.pushprovider import IPushProvider

#
# set the default connection and request timeouts
#

DEFAULT_TIMEOUT = (3, 5)

log = logging.getLogger(__name__)


@provider_registry.class_entry('DefaultPushProvider')
@provider_registry.class_entry('linotp.provider.DefaultPushProvider')
@provider_registry.class_entry('linotp.lib.pushprovider.'
                               'DefaultPushProvider')
class DefaultPushProvider(IPushProvider):
    """
    Send a push notification to the default push notification proxy (PNP).
    """

    def __init__(self):

        self.push_server_url = None
        self.client_cert = None
        self.server_cert = None
        self.proxy = None
        self.timeout = DEFAULT_TIMEOUT

        IPushProvider.__init__(self)

    def loadConfig(self, configDict):
        """
        Loads the configuration for this push notification provider

        :param configDict: A dictionary that contains all configuration entries
                          you defined (e.g. in the linotp.ini file)

        {
            "push_url":
                the push provider target url,
            "access_certificate":
                the client_certificate
            "server_certificate":
                server verification certificate
            "proxy": '
                the proxy url
            "timeout":
                the http timeout value
        }
        """
        try:

            #
            # define the request calling endpoint
            #

            # verify the url scheme
            parsed_url = urlparse(configDict['push_url'])
            if parsed_url.scheme not in ['http', 'https']:
                raise requests.exceptions.InvalidSchema(configDict['push_url'])

            self.push_server_url = configDict['push_url']

            #
            # for authentication on the pnp we require a client certificate
            #

            self.client_cert = configDict['access_certificate']
            if not os.path.isfile(self.client_cert):
                raise IOError("required authenticating client"
                              " cert could not be found %r" %
                              self.client_cert)

            #
            # default is no server verification, but if provided
            # it must be either a file or directory reference
            #

            server_cert = configDict.get('server_certificate')

            # server cert can be a string (file location, cert dir)
            # None or not present (cert gets fetched from local trust
            # store) or False (no certificate verification)

            if server_cert:

                if (not os.path.isfile(server_cert) and
                   not os.path.isdir(server_cert)):
                    raise IOError("server certificate verification could not"
                                  " be made as certificate could not be found"
                                  " %r" % server_cert)

            self.server_cert = server_cert

            #
            # timeout could come with capital letter
            # and could be a
            # - simple timeout (float)
            # - or  a tuple of connection and request timeout (float)
            #

            if 'timeout' in configDict or 'Timeout' in configDict:
                timeout = configDict.get('timeout', configDict.get('Timeout'))

                #
                # simple timeout or timeout tuple
                #

                if ',' in timeout:
                    conection_timeout, request_timeout = timeout.split(',')
                    timeout = (float(conection_timeout),
                               float(request_timeout))
                else:
                    self.timeout = float(timeout)

            #
            # we support proxy configuration, whereby here 'requests'
            # distinguishes between http and https proxies, which are provided
            # in a dicitionary to the request api
            #

            if 'proxy' in configDict:

                # verify the url scheme
                parsed_url = urlparse(configDict['proxy'])
                if parsed_url.scheme not in ['http', 'https']:
                    raise requests.exceptions.InvalidSchema(configDict['proxy'])

                if parsed_url.path and parsed_url.path != '/':
                    raise requests.exceptions.InvalidSchema(configDict['proxy'])

                self.proxy = DefaultPushProvider.get_proxy_definition(
                                    configDict.get('proxy'))

        except KeyError as exx:
            log.error('Missing Configuration entry %r', exx)
            raise exx

    def push_notification(self, message, gda):
        """
        Sends out the push notification message.

        :param message: The push notification message / challenge
        :param gda: the gda - global device identifier

        :return: A tuple of success and result message
        """

        if not self.push_server_url:
            raise Exception("Missing Server Push Url configuration!")

        if not self.client_cert:
            raise Exception("Missing Access Certificate configuration!")

        if not message:
            raise Exception("No message to submit!")

        if not gda:
            raise Exception("Missing target description!")

        (success,
         result_message) = self._http_push(message=message, gda=gda)

        return success, result_message

    @staticmethod
    def get_proxy_definition(proxy_url=None):

        # requests is using a dict for the proxy defintion
        proxy = None
        if proxy_url:
            proxy = {}
            if proxy_url.startswith('https:'):
                proxy['https'] = proxy_url
            else:
                proxy['http'] = proxy_url

        return proxy

    def _http_push(self, message, gda):
        """
        push the notification over http by calling the requests POST api

        :param message: the notification message
        :param gda: the global device identifier
        :return: tuple with response status and content / reason
        """

        params = {}
        params['challenge'] = message
        params['gda'] = gda

        #
        # using **args for the timeout parameter
        #

        pparams = {}
        if self.timeout:
            pparams['timeout'] = self.timeout

        try:
            http_session = requests.Session()

            if self.proxy:
                http_session.proxies.update(self.proxy)

            #
            # we check if the client certificate exists, which is
            # referenced as a filename
            #

            if self.client_cert and os.path.isfile(self.client_cert):
                http_session.cert = self.client_cert

            server_cert = self.server_cert
            if server_cert is not None:
                # Session.post() doesn't like unicode values in Session.verify
                if isinstance(server_cert, unicode):
                    server_cert = server_cert.encode('utf-8')

                http_session.verify = server_cert

            response = http_session.post(self.push_server_url,
                                         data=params,
                                         **pparams)

            result = ''
            if not response.ok:
                result = response.reason
            else:
                result = response.content

        finally:
            log.debug("leaving push notification provider")

        return response.ok, result


def main():
    """

    main here - for the interactive test :-)

    """
    import argparse

    usage = "Interactive test for the pushtoken provider"

    parser = argparse.ArgumentParser(usage)

    parser.add_argument("-c", "--client_cert", help="client certificate",
                        required=True)

    parser.add_argument("-u", "--url", help="Provider URL", required=True)

    parser.add_argument("-m", '--message', help="message", required=True)
    parser.add_argument("-g", '--gda', help="target token info (gda)",
                        required=True)

    # not required parameters

    parser.add_argument("-s", '--server_certificates',
                        help="directory of trusted server certificates")
    parser.add_argument("-p", "--proxy",
                        help="the proxy URL")
    parser.add_argument("-t", "--timeout",
                        help="Connection timeout and request timeouts")

    args = vars(parser.parse_args())

    #
    # now prepare the DefaultPushProvider
    # configuration and request parameters
    #

    message = args['message']
    gda = args['gda']

    configDict = {}
    configDict['push_url'] = args['url']
    configDict['access_certificate'] = args['client_cert']

    if 'timeout' in args:
        configDict['timeout'] = args.get('timeout')

    if 'proxy' in args:
        configDict['proxy'] = args.get('proxy')

    if 'server_certificates' in args:
        configDict['server_certificate'] = args.get('server_certificates')

    #
    # execute the request
    #

    try:
        push_provider = DefaultPushProvider()
        push_provider.loadConfig(configDict)
        res, resp = push_provider.push_notification(message=message, gda=gda)
        print "Result: %r" % res
        print "Response: %r" % resp

    except Exception as exx:
        log.error('Failed to push the notification (%r): %r',
                  exx, configDict)

if __name__ == '__main__':

    #
    # in main() we parse the arguments from the command line to support
    # command line connection testing
    #

    main()


# eof

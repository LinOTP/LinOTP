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
* implementation of the KeyIdentity PushProvider
'''


import hashlib
import logging
import os
import requests
import time
from urlparse import urlparse
from functools import partial

from linotp.provider import provider_registry
from linotp.provider.pushprovider import IPushProvider

from linotp.lib.remote_service import RemoteServiceList

#
# set the default connection and request timeouts
#

DEFAULT_TIMEOUT = (3, 5)

log = logging.getLogger(__name__)


@provider_registry.class_entry('DefaultPushProvider')
@provider_registry.class_entry('linotp.provider.DefaultPushProvider')
@provider_registry.class_entry('linotp.lib.pushprovider.DefaultPushProvider')
class DefaultPushProvider(IPushProvider):
    """
    Send a push notification to the default push notification proxy (PNP).
    """
    _remote_services = {}

    def __init__(self):

        self.push_server_urls = None
        self.client_cert = None
        self.server_cert = None
        self.proxy = None
        self.timeout = DEFAULT_TIMEOUT
        self.remote_services = None

        IPushProvider.__init__(self)

    @classmethod
    def get_or_create_remote_services(cls, urls, garbage_collect_timeout=120):
        """
        Create a session per unique set of connections.

        On each access to the list we purge entries that haven't been accesses within
        `garbage_collect_timeout`

        :parm urls: urls within the service, used to retrieve and construct
                    a new RemoteServiceList
        :param garbage_collect_timeout: timeout in seconds after which to
                                        remove entries from the cache
        """

        # start by hashing all urls so we have a way to refer to a configuration
        m = hashlib.md5()
        for u in urls:
            m.update(u)

        h = m.hexdigest()

        # get the current time once
        now = time.time()

        # cleanup the dict of existing cache entries based on the given timeout
        for key in cls._remote_services.keys():
            ts, _ = cls._remote_services[key]
            if ts + garbage_collect_timeout < now:
                del cls._remote_services[key]

        # search for the entry we are looking for
        item = cls._remote_services.get(h)
        if not item:
            # if no entry was found create a new session and store it within the cache
            log.debug('Cache miss. Creating new entry for hash %s', h)
            session = requests.Session()
            rs = RemoteServiceList(
                failure_threshold=2, # after two failures try next service
                recovery_timeout=30, # after 30 seconds retry a failed service
                # mark services a failed if a requests.ConnectionError occured
                expected_exception=requests.ConnectionError,
            )
            for url in urls:
                rs.append(partial(session.post, url))
            item = (now, rs)
            cls._remote_services[h] = item
        else:
            # update the access time to the current time if the entry already existed
            log.debug('Cache hit. Updating timestamp of %s', h)
            _, rs = item
            cls._remote_services[h] = (now, rs)

        # return only the actual RemoteServiceList
        _, rs = item
        return rs

    @staticmethod
    def _validate_url(url):
        """
        Validate that a URLs scheme is http or https.

        :param url: The url as string that should be validated
        """
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ['http', 'https']:
            raise requests.exceptions.InvalidSchema(url)

    def loadConfig(self, configDict):
        """
        Loads the configuration for this push notification provider

        :param configDict: A dictionary that contains all configuration entries
                          you defined (e.g. in the linotp.ini file)

        {
            "push_url":
                the push provider target url or a list of those,
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
            # define the request calling endpoint(s)
            # we support lists and single values (for compatibility)
            #
            push_server_urls = []
            push_url = configDict['push_url']
            if isinstance(push_url, (list, tuple)):
                # verify the url scheme of all entries
                for url in configDict['push_url']:
                    self._validate_url(url)
                    push_server_urls.append(url)
            else:
                self._validate_url(push_url)
                push_server_urls = [push_url]

            #
            # retrieve of create a new session
            # this is required to propagate failover information between multiple
            # push notification requests
            #
            self.remote_services = self.get_or_create_remote_services(push_server_urls)

            #
            # for authentication on the challenge service we can use a
            # client certificate
            #

            self.client_cert = configDict.get('access_certificate')

            if self.client_cert and not os.path.isfile(self.client_cert):
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

                if (
                    not os.path.isfile(server_cert) and
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
                    raise requests.exceptions.InvalidSchema(
                                                        configDict['proxy'])

                if parsed_url.path and parsed_url.path != '/':
                    raise requests.exceptions.InvalidSchema(
                                                        configDict['proxy'])

                self.proxy = DefaultPushProvider.get_proxy_definition(
                                    configDict.get('proxy'))

        except KeyError as exx:
            log.error('Missing Configuration entry %r', exx)
            raise exx

    def push_notification(self, challenge, gda, transactionId):
        """
        Sends out the push notification message.

        :param challenge: The push notification message / challenge
        :param gda: the gda - global device identifier
        :param transactionId: The push notification transaction reference

        :return: A tuple of success and result message
        """

        if not self.remote_services or len(self.remote_services) == 0:
            raise Exception("Missing Server Push Url configurations!")

        if not challenge:
            raise Exception("No challenge to submit!")

        if not gda:
            raise Exception("Missing target description!")

        (success,
         result_message) = self._http_push(challenge,
                                           gda,
                                           transactionId)

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

    def _http_push(self, challenge, gda, transactionId):
        """
        push the notification over http by calling the requests POST api

        :param message: the notification message
        :param gda: the global device identifier
        :return: tuple with response status and content / reason
        """

        # ----------------------------------------------------------------- --

        # Challenge Service expectes the following document

        # {"challenge": {
        #    "transactionId": "string",
        #    "gda": "string",
        #    "challenge": "string" }
        # }

        params = {}
        params['transactionId'] = transactionId
        params['gda'] = gda
        params['challenge'] = challenge

        json_challenge = {"challenge": params}

        #
        # using **args for the timeout parameter
        #

        pparams = {}
        if self.timeout:
            pparams['timeout'] = self.timeout

        try:
            # submitting the json body requires the correct HTTP headers
            # with contenttype declaration:

            headers = {
                'Content-type': 'application/json',
                'Accept': 'text/plain'}

            if self.proxy:
                pparams['proxies'] = self.proxy

            #
            # we check if the client certificate exists, which is
            # referenced as a filename
            #

            if self.client_cert and os.path.isfile(self.client_cert):
                pparams['cert'] = self.client_cert

            server_cert = self.server_cert
            if server_cert is not None:
                # Session.post() doesn't like unicode values in Session.verify
                if isinstance(server_cert, unicode):
                    server_cert = server_cert.encode('utf-8')

                pparams['verify'] = server_cert

            #
            # Call out to our list of services
            #
            response = self.remote_services.call_first_available(
                                            json=json_challenge,
                                            headers=headers,
                                            **pparams)

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

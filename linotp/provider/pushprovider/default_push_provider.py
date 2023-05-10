# -*- coding: utf-8 -*-
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

"""
* implementation of the KeyIdentity PushProvider
"""

import logging
import os
from urllib.parse import urlparse

import requests
from requests.exceptions import (
    ConnectionError,
    ConnectTimeout,
    ReadTimeout,
    Timeout,
    TooManyRedirects,
)

from linotp.lib.resources import AllResourcesUnavailable, ResourceScheduler
from linotp.provider import provider_registry
from linotp.provider.config_parsing import ConfigParsingMixin
from linotp.provider.pushprovider import IPushProvider

log = logging.getLogger(__name__)


@provider_registry.class_entry("DefaultPushProvider")
@provider_registry.class_entry("linotp.provider.DefaultPushProvider")
@provider_registry.class_entry("linotp.lib.pushprovider.DefaultPushProvider")
class DefaultPushProvider(IPushProvider, ConfigParsingMixin):
    """
    Send a push notification to the default push notification proxy (PNP).
    """

    def __init__(self):
        self.push_server_urls = None
        self.client_cert = None
        self.server_cert = None
        self.proxy = None
        self.timeout = DefaultPushProvider.DEFAULT_TIMEOUT

        IPushProvider.__init__(self)

    @staticmethod
    def _validate_url(url):
        """
        Validate that a URLs scheme is http or https.

        :param url: The url as string that should be validated
        """
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ["http", "https"]:
            raise requests.exceptions.InvalidSchema(url)

    def loadConfig(self, configDict):
        """
        Loads the configuration for this push notification provider

        :param configDict: A dictionary that contains all configuration entries
                          you defined (e.g. in a linotp.cfg file)

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
            push_url = configDict["push_url"]
            if isinstance(push_url, (list, tuple)):
                # verify the url scheme of all entries
                for url in configDict["push_url"]:
                    self._validate_url(url)
                    push_server_urls.append(url)
            else:
                self._validate_url(push_url)
                push_server_urls = [push_url]

            self.push_server_urls = push_server_urls

            #
            # for authentication on the challenge service we can use a
            # client certificate
            #

            self.client_cert = configDict.get("access_certificate")

            if self.client_cert and not os.path.isfile(self.client_cert):
                raise IOError(
                    "required authenticating client"
                    " cert could not be found %r" % self.client_cert
                )

            # server cert can be a string (file location, cert dir)
            # None or not present (cert gets fetched from local trust
            # store) or False (no certificate verification)

            self.server_cert = self.load_server_cert(
                configDict, server_cert_key="server_certificate"
            )

            #
            # timeout could come with capital letter
            # and could be a
            # - simple timeout (float)
            # - or  a tuple of connection and request timeout (float)
            #

            if "timeout" in configDict or "Timeout" in configDict:
                timeout = configDict.get("timeout", configDict.get("Timeout"))

                #
                # simple timeout or timeout tuple
                #

                if "," in timeout:
                    connection_timeout, request_timeout = list(
                        map(float, timeout.split(","))
                    )

                    # validate inputs, we do not allow values <= 0
                    if connection_timeout <= 0:
                        raise ValueError(connection_timeout)
                    if request_timeout <= 0:
                        raise ValueError(request_timeout)

                    self.timeout = (connection_timeout, request_timeout)
                else:
                    timeout = float(timeout)
                    if timeout <= 0:
                        raise ValueError(timeout)

                    self.timeout = timeout

            #
            # we support proxy configuration, whereby here 'requests'
            # distinguishes between http and https proxies, which are provided
            # in a dicitionary to the request api
            #

            if "proxy" in configDict:
                # verify the url scheme
                parsed_url = urlparse(configDict["proxy"])
                if parsed_url.scheme not in ["http", "https"]:
                    raise requests.exceptions.InvalidSchema(
                        configDict["proxy"]
                    )

                if parsed_url.path and parsed_url.path != "/":
                    raise requests.exceptions.InvalidSchema(
                        configDict["proxy"]
                    )

                self.proxy = DefaultPushProvider.get_proxy_definition(
                    configDict.get("proxy")
                )

        except KeyError as exx:
            log.error("Missing Configuration entry %r", exx)
            raise exx

    def push_notification(self, challenge, gda, transactionId):
        """
        Sends out the push notification message.

        :param challenge: The push notification message / challenge
        :param gda: the gda - global device identifier
        :param transactionId: The push notification transaction reference

        :return: A tuple of success and result message
        """

        if not self.push_server_urls:
            raise Exception("Missing Server Push Url configurations!")

        if not challenge:
            raise Exception("No challenge to submit!")

        if not gda:
            raise Exception("Missing target description!")

        (success, result_message) = self._http_push(
            challenge, gda, transactionId
        )

        return success, result_message

    @staticmethod
    def get_proxy_definition(proxy_url=None):
        # requests is using a dict for the proxy defintion
        proxy = None
        if proxy_url:
            proxy = {}
            if proxy_url.startswith("https:"):
                proxy["https"] = proxy_url
            else:
                proxy["http"] = proxy_url

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
        params["transactionId"] = transactionId
        params["gda"] = gda
        params["challenge"] = challenge

        json_challenge = {"challenge": params}

        #
        # using **args for the timeout parameter
        #

        pparams = {}
        if self.timeout:
            pparams["timeout"] = self.timeout

        # submitting the json body requires the correct HTTP headers
        # with contenttype declaration:

        headers = {"Content-type": "application/json", "Accept": "text/plain"}

        if self.proxy:
            pparams["proxies"] = self.proxy

        #
        # we check if the client certificate exists, which is
        # referenced as a filename
        #

        if self.client_cert and os.path.isfile(self.client_cert):
            pparams["cert"] = self.client_cert

        # ------------------------------------------------------------------ --

        # set server certificate validation policy

        if self.server_cert is False:
            pparams["verify"] = False

        if self.server_cert:
            pparams["verify"] = self.server_cert

        # ------------------------------------------------------------------ --

        # schedule all resources

        res_scheduler = ResourceScheduler(
            tries=2, uri_list=self.push_server_urls
        )

        # ------------------------------------------------------------------ --

        # location to preserve the last exception, so we can report this if
        # every resource access failed

        last_exception = None

        # ------------------------------------------------------------------ --

        # iterate through all resources

        for uri in next(res_scheduler):
            try:
                response = requests.post(
                    uri, json=json_challenge, headers=headers, **pparams
                )

                if not response.ok:
                    result = response.reason
                else:
                    result = response.content

                return response.ok, result

            except (
                Timeout,
                ConnectTimeout,
                ReadTimeout,
                ConnectionError,
                TooManyRedirects,
            ) as exx:
                log.error("resource %r not available!", uri)

                # mark the url as blocked

                res_scheduler.block(uri, delay=30)

                # and preserve the exception, so that we are able to raise this
                # when no resources are available at all

                last_exception = exx

        # ------------------------------------------------------------------ --

        # if we reach here, no resource has been availabel

        log.error("non of the resources %r available!", self.push_server_urls)

        if last_exception:
            log.error("Last Exception was %r", last_exception)
            raise last_exception

        raise AllResourcesUnavailable(
            "non of the resources %r available!" % self.push_server_urls
        )


def main():
    """

    main here - for the interactive test :-)

    """
    import argparse

    usage = "Interactive test for the pushtoken provider"

    parser = argparse.ArgumentParser(usage)

    parser.add_argument(
        "-c", "--client_cert", help="client certificate", required=True
    )

    parser.add_argument("-u", "--url", help="Provider URL", required=True)

    parser.add_argument("-m", "--message", help="message", required=True)
    parser.add_argument(
        "-g", "--gda", help="target token info (gda)", required=True
    )

    # not required parameters

    parser.add_argument(
        "-s",
        "--server_certificates",
        help="directory of trusted server certificates",
    )
    parser.add_argument("-p", "--proxy", help="the proxy URL")
    parser.add_argument(
        "-t", "--timeout", help="Connection timeout and request timeouts"
    )

    args = vars(parser.parse_args())

    #
    # now prepare the DefaultPushProvider
    # configuration and request parameters
    #

    message = args["message"]
    gda = args["gda"]

    configDict = {}
    configDict["push_url"] = args["url"]
    configDict["access_certificate"] = args["client_cert"]

    if "timeout" in args:
        configDict["timeout"] = args.get("timeout")

    if "proxy" in args:
        configDict["proxy"] = args.get("proxy")

    if "server_certificates" in args:
        configDict["server_certificate"] = args.get("server_certificates")

    #
    # execute the request
    #

    try:
        push_provider = DefaultPushProvider()
        push_provider.loadConfig(configDict)
        res, resp = push_provider.push_notification(message=message, gda=gda)
        print("Result: %r" % res)
        print("Response: %r" % resp)

    except Exception as exx:
        log.error("Failed to push the notification (%r): %r", exx, configDict)


if __name__ == "__main__":
    #
    # in main() we parse the arguments from the command line to support
    # command line connection testing
    #

    main()

# eof

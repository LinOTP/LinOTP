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
'''
* implementation of the KeyIdentity PushProvider
'''


import os
import logging
import tempfile
import requests

from linotp.provider import provider_registry
from linotp.provider.pushprovider import IPushProvider

log = logging.getLogger(__name__)


@provider_registry.class_entry('KeyIdentityPushProvider')
@provider_registry.class_entry('linotp.provider.KeyIdentityPushProvider')
@provider_registry.class_entry('linotp.lib.pushprovider.'
                               'KeyIdentityPushProvider')
class KeyIdentityPushProvider(IPushProvider):
    """
    Send a push notification to the KeyIdentity Push Notification Proxy (PNP).
    """

    def __init__(self):
        self.push_server_url = None
        self.client_cert = None
        self.server_cert = None
        self.proxy = None
        self.timeout = 3

        # from beaker we can take the app_conf['cache_dir'] else fallback
        self.chache_dir = '/tmp'
        IPushProvider.__init__(self)

    def loadConfig(self, configDict):
        """
        Loads the configuration for this push notification provider

        :param configDict: A dictionary that contains all configuration entries
                          you defined (e.g. in the linotp.ini file)

        {
            "url": "test2pnp.keyidentiy.com",
            "access_certificate": "secret_cert",
            "server_certificate":"server_cert"
        }
        """
        try:
            self.push_server_url = configDict['push_url']
            self.client_cert = configDict['access_certificate']
            self.server_cert = configDict.get('server_certificate')

            self.timeout = configDict.get('Timeout', 3)

        except KeyError as exx:
            log.error('Missing Configuration enty %r', exx)
            raise exx

    def push_notification(self, message, token_info=None, gda=None):
        """
        Sends out the push notification message.

        :param message: The push notification message / challenge
        :param token_info: the token info, which contains target token
                           descriptor

        :return: A tuple of success and result message
        """

        if not self.push_server_url:
            raise Exception("Missing Server Push Url configuration!")

        if not self.client_cert:
            raise Exception("Missing Access Certificate configuration!")

        if not message:
            raise Exception("No message to submit!")

        if token_info:
            target_info = token_info.get('gda', None)

        if gda:
            target_info = gda

        if not target_info:
            raise Exception("Missing target description!")

        (success,
         result_message) = KeyIdentityPushProvider._http_push(
             push_server_url=self.push_server_url,
             message=message,
             target_info=target_info,
             caching_dir=self.chache_dir,
             client_cert=self.client_cert,
             server_cert=self.server_cert)

        return success, result_message

    @staticmethod
    def _http_push(push_server_url, message, target_info,
                   client_cert, caching_dir='/tmp', server_cert=None):
        """
        push the notification over http
        """

        params = {}
        params['message'] = message
        params['gda'] = target_info

        cert_file = None
        try:
            http_session = requests.Session()

            if client_cert:
                # the underlying implementation in liburl / ssl
                # requires a file name, thus we have to create one
                # in a temporary directory
                cert_file = tempfile.NamedTemporaryFile(mode='w+b',
                                                        dir=caching_dir,
                                                        delete=False)
                cert_file.write(client_cert)
                cert_file.close()
                http_session.cert = cert_file.name

            if server_cert:
                http_session.verify = server_cert
            else:
                http_session.verify = False

            response = http_session.post(push_server_url,
                                         data=params)

            result = ''
            if not response.ok:
                result = response.reason
            else:
                result = response.content

        finally:
            # cleanup the certificate file
            if cert_file:
                os.remove(cert_file.name)

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
    parser.add_argument("-t", '--target_info', help="target token info (gda)",
                        required=False)

    parser.add_argument("-s", '--server_certificates',
                        help="directory of trusted server certificates",
                        required=False)

    args = vars(parser.parse_args())

    push_server_url = args['url']
    message = args['message']
    target_info = args['target_info']
    client_cert = args['client_cert']
    server_cert = args.get('server_certificates', None)

    # in Linotp the certificates are saved in config as string value (enc)
    # so this KeyIdentityPushProvider api requires the client cert as
    # string value

    with open(client_cert, 'r') as cert_file:
        client_cert_data = cert_file.read()

    # call the _http_push api

    resp = KeyIdentityPushProvider._http_push(push_server_url,
                                              message,
                                              target_info,
                                              client_cert_data,
                                              server_cert)

    print resp

if __name__ == '__main__':

    main()


# eof

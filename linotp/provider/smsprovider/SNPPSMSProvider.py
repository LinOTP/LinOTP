# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#
#    This file is part of LinOTP smsprovider.
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


""" the SMS Provider Interface """
from linotp.provider.smsprovider import ISMSProvider
from linotp.provider import provider_registry
from linotp.provider import ProviderNotAvailable

try:
    from snpplib import SNPP
    SNPP_SUPPORT = True
except ImportError as exx:
    SNPP_SUPPORT = False

import logging

log = logging.getLogger(__name__)


@provider_registry.class_entry('SNPPSMSProvider')
@provider_registry.class_entry('linotp.provider.smsprovider.SNPPSMSProvider')
@provider_registry.class_entry('smsprovider.SNPPSMSProvider.SNPPSMSProvider')
@provider_registry.class_entry('smsprovider.SNPPSMSProvider')
class SNPPSMSProvider(ISMSProvider):

    def __init__(self):
        if not SNPP_SUPPORT:
            raise RuntimeError("SNPP Error: no snpp library installed")

        self.config = {}


    def getConfigDescription(self):
        """
        """
        iface = {'server': "server address",
                 'port': "server port number - default:444",
                 'username': 'connection username',
                 'password': 'connection password',
                 'subject': 'message subject',
                 }

        return iface


    def loadConfig(self, configDict):
        """
        load the provider configuration from the config dict
        """
        self.config = configDict

        self.server = str(self.config['server'])
        self.port = int(self.config.get('port', 444))
        self.username = self.config.get('username', None)
        self.password = self.config.get('password', None)
        self.subject = self.config.get('subject', None)


    def _submitMessage(self, phone, message):
        """
        submit the message to the SNPP Server
        """

        result = True

        # setup the configuration
        if not self.config:
            raise Exception("missing configuration!")

        try:
            client = SNPP(None, None, 1)
            log.debug("connecting to %r:%r", self.server, self.port)
            client.connect(self.server, self.port)
            log.debug("connected!")

        except Exception as exx:
            log.exception("Failed to connect to server")
            raise ProviderNotAvailable("Failed to connect to server %r" % exx)

        try:
            log.debug("login with %s %s", self.username, self.password)
            if self.username != None:
                client.login(self.username, self.password)

            client.pager(phone)

            if self.subject != None:
                client.subject(self.subject)

            client.message(message)
            client.send()

        except Exception as exx:
            log.exception(exx)
            result = False

        finally:
            try:
                client.quit()
            except Exception as exx:
                log.exception(exx)

            client.close()

        return result


def main(phone, message, config):

    print("SNPPSMSProvider - class load test ")

    sms_pro = SNPPSMSProvider()
    sms_pro.loadConfig(config)
    print(config)
    sms_pro.submitMessage(phone, message)


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.DEBUG)

    # for commandline testing
    parser = argparse.ArgumentParser()
    parser.add_argument("--phone", help="target phone number")
    parser.add_argument("--message", help="target message")
    parser.add_argument("--server", help="server address")
    parser.add_argument("--port", help="port number")
    parser.add_argument("--password", help="login password")
    parser.add_argument("--username", help="login username")
    parser.add_argument("--subject", help="message subject")

    args = parser.parse_args()

    config = {}
    attrs = ['phone', 'message', 'subject',
             'server', 'port', 
             'username', 'password']

    for key in attrs:
        try:
            val = getattr(args, key)
            if val:
                config[key] = val
        except:
            pass

    phone = config['phone']
    message = config['message']

    main(phone, message, config)

    print("... done!")

# eof

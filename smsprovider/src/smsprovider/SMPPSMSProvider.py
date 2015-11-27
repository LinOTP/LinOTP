# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#


""" the SMS Provider Interface """
from smsprovider.SMSProvider import ISMSProvider

import smpplib
import logging

log = logging.getLogger(__name__)


class SMPPSMSProvider(ISMSProvider):

    def __init__(self):
        self.config = {}

    def getConfigDescription(self):
        """
        """
        iface = {'server': "server address",
                 'port': "server port number - default:5100",
                 'system_id': ('Identifies the ESME system requesting to bind '
                               ' as a transmitter with the MC. This field must'
                               ' contain the Short ID (shortcode)'),
                 'password': 'connection password',
                 'source_addr': 'source address (for replying to an sms)',
                 'system_type': ('optional: The service_type parameter can be '
                                 'used to indicate the SMS Application service'
                                 ' associated with the message. Specifying the'
                                 ' service_type allows the ESME to avail of '
                                 'enhanced messaging services such as "replace'
                                 'by service_type" or to control the '
                                 'teleservice used on the air interface.'),
                 'source_addr_npi': ('Numbering Plan Indicator for source '
                                     'address.'),         
                 'dest_addr_npi': ('Numbering Plan Indicator for dest '
                                     'address.'),
                 }

        return iface

    def submitMessage(self, phone, message):
        """
        submit the message to the SMPP Server
        """

        # setup the configuration
        if not self.config:
            raise Exception("missing configuration!")

        client = smpplib.client.Client(self.server, self.port)
        client.connect()
        log.debug("connected to %r:%r" % (self.server, self.port))

        try:
            log.debug("binding to system_id %r (system_type %r)" %
                      (self.system_id, self.system_type))
            client.bind_transceiver(system_id=self.system_id,
                                    password=self.password,
                                    system_type=self.system_type)

            client.send_message(
                            source_addr_ton=smpplib.command.SMPP_TON_INTL,
                            source_addr=self.source_addr,
                            dest_addr_ton=smpplib.command.SMPP_TON_INTL,
                            destination_addr=phone,
                            short_message=message,
                            source_addr_npi=self.source_addr_npi,
                            dest_addr_npi=self.dest_addr_npi)

            log.debug("message %r submitted to %r" % (message, phone))

        except Exception as exx:
            log.exception(exx)

        finally:
            client.unbind()
            client.disconnect()

        return True

    def loadConfig(self, configDict):
        self.config = configDict

        self.server = self.config['server']
        self.port = int(self.config.get('port', 5100))
        self.system_id = self.config['system_id']
        self.password = self.config['password']
        self.source_addr = self.config['source_addr']
        self.system_type = self.config.get('system_type', '')
        self.source_addr_npi = int(self.config.get('source_addr_npi', 0))
        self.dest_addr_npi = int(self.config.get('dest_addr_npi', 0))

def main(phone, message, config):

    print "SMPPSMSProvider - class load test "

    sms_pro = SMPPSMSProvider()
    sms_pro.loadConfig(config)
    print config
    sms_pro.submitMessage(phone, message)


if __name__ == "__main__":
    import argparse
    # for commandline testing
    parser = argparse.ArgumentParser()
    parser.add_argument("phone", help="target phone number")
    parser.add_argument("message", help="greeting message")
    parser.add_argument("server", help="server address")
    parser.add_argument("port", help="port number")
    parser.add_argument("system_id", help="user name or system ID")
    parser.add_argument("password", help="password")
    parser.add_argument("system_type", help="type of service")
    parser.add_argument("source_addr", help="name of sending phone")
    parser.add_argument("source_addr_npi", help="type of source addr")
    parser.add_argument("dest_addr_npi", help="type of destination addr")

    args = parser.parse_args()

    config = {
          args.server.split('=')[0]: args.server.split('=', 1)[1],
          args.port.split('=')[0]: args.port.split('=', 1)[1],
          args.system_id.split('=')[0]: args.system_id.split('=', 1)[1],
          args.password.split('=')[0]: args.password.split('=', 1)[1],
          args.system_type.split('=')[0]: args.system_type.split('=', 1)[1],
          args.source_addr.split('=')[0]: args.source_addr.split('=', 1)[1],
          args.source_addr_npi.split('=')[0]: args.source_addr_npi.split('=', 1)[1],
          args.dest_addr_npi.split('=')[0]: args.dest_addr_npi.split('=', 1)[1],
        }

    main(args.phone.split('=', 1)[1], args.message.split('=', 1)[1], config)

    print("... done!")

## eof ########################################################################

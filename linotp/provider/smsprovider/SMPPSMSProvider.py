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
    import smpplib

    SMPP_SUPPORT = True
except ImportError as exx:
    SMPP_SUPPORT = False

import logging

log = logging.getLogger(__name__)


@provider_registry.class_entry("SMPPSMSProvider")
@provider_registry.class_entry("linotp.provider.smsprovider.SMPPSMSProvider")
@provider_registry.class_entry("smsprovider.SMPPSMSProvider.SMPPSMSProvider")
@provider_registry.class_entry("smsprovider.SMPPSMSProvider")
class SMPPSMSProvider(ISMSProvider):
    def __init__(self):
        if not SMPP_SUPPORT:
            raise RuntimeError("SMPP Error: no smpp library installed")

        self.config = {}

        # limit provider to only support iso latin 1 encoding
        self.target_encoding = "ISO8859-1"

    def getConfigDescription(self):
        """"""
        iface = {
            "server": "server address",
            "port": "server port number - default:5100",
            "system_id": (
                "Identifies the ESME system requesting to bind "
                " as a transmitter with the MC. This field must"
                " contain the Short ID (shortcode)"
            ),
            "password": "connection password",
            "source_addr": "source address (for replying to an sms)",
            "system_type": (
                "optional: The service_type parameter can be "
                "used to indicate the SMS Application service"
                " associated with the message. Specifying the"
                " service_type allows the ESME to avail of "
                'enhanced messaging services such as "replace'
                'by service_type" or to control the '
                "teleservice used on the air interface."
            ),
            "source_addr_npi": (
                "Numbering Plan Indicator for source " "address."
            ),
            # 'dest_addr_npi': ('Numbering Plan Indicator for dest '
            #                    'address.'),
            "source_addr_ton": (
                "Type of number of the ESME source " "address"
            ),
            # 'dest_addr_ton': ('Type of number of the ESME destination'
            #                   ' address'),
            # 'registered_delivery': ('delivery receipt required'),
            # 'target_encoding': ('the encoding of the sms on the '
            #                     'target side - default is iso8859-15')
        }

        return iface

    def _submitMessage(self, phone, message):
        """
        submit the message to the SMPP Server
        """

        result = True

        # setup the configuration
        if not self.config:
            raise Exception("missing configuration!")

        try:
            client = smpplib.client.Client(self.server, self.port)
            client.connect()
            log.debug("connected to %r:%r", self.server, self.port)

        except Exception as exx:
            log.exception("Failed to connect to server")
            raise ProviderNotAvailable("Failed to connect to server %r" % exc)

        try:
            log.debug(
                "binding to system_id %r (system_type %r)",
                self.system_id,
                self.system_type,
            )

            # transform the arguments from unicode down to string / byte array
            password = self.password.encode(self.target_encoding, "ignore")
            system_id = self.system_id.encode(self.target_encoding, "ignore")
            system_type = self.system_type.encode(
                self.target_encoding, "ignore"
            )

            client.bind_transceiver(
                system_id=system_id, password=password, system_type=system_type
            )

            # transform the arguments from unicode down to string / byte array
            source_addr = self.source_addr.encode(
                self.target_encoding, "ignore"
            )
            destination_addr = phone.encode(self.target_encoding, "ignore")
            short_message = message.encode(self.target_encoding, "ignore")

            # according to spec messages should not be longer than 160 chars
            if len(short_message) <= 160:
                self._send(
                    client, source_addr, destination_addr, short_message
                )
                log.debug("message %r submitted to %r", short_message, phone)

            else:
                # messages longer than 160 chars should be
                # split down into small chunks of 153 chars
                max_msg_len = 153
                for i in range(0, len(short_message), max_msg_len):
                    msg = short_message[i: i + max_msg_len]
                    if not msg:
                        continue
                    self._send(client, source_addr, destination_addr, msg)
                    log.debug("message %r submitted to %r", msg, phone)

        except Exception as exx:
            log.exception(exx)
            result = False

        finally:
            client.unbind()
            client.disconnect()

        return result

    def _send(self, client, source_addr, destination_addr, short_message):
        """
        small helper to submit the message chunks
        """
        res = client.send_message(
            source_addr=source_addr,
            destination_addr=destination_addr,
            short_message=short_message,
            source_addr_npi=int(self.source_addr_npi),
            source_addr_ton=int(self.source_addr_ton),
            dest_addr_npi=int(self.dest_addr_npi),
            dest_addr_ton=int(self.dest_addr_ton),
            data_coding=3,
        )
        return res

    def loadConfig(self, configDict):
        """
        load the provider configuration from the config dict
        """
        self.config = configDict

        self.server = str(self.config["server"])
        self.port = int(self.config.get("port", 5100))
        self.system_id = str(self.config["system_id"])
        self.password = str(self.config["password"])
        self.system_type = str(self.config.get("system_type", ""))

        self.source_addr = str(self.config["source_addr"])
        self.source_addr_npi = int(self.config.get("source_addr_npi", 1))
        self.source_addr_ton = int(self.config.get("source_addr_ton", 1))

        self.dest_addr_npi = int(self.config.get("dest_addr_npi", 1))
        self.dest_addr_ton = int(self.config.get("dest_addr_ton", 1))

        # not required:
        # self.registered_delivery = int(self.config.get('registered_delivery',
        #                                                0))

        self.target_encoding = str(
            self.config.get("target_encoding", "ISO8859-1")
        )


def main(phone, message, config):

    print("SMPPSMSProvider - class load test ")

    sms_pro = SMPPSMSProvider()
    sms_pro.loadConfig(config)
    print(config)
    sms_pro.submitMessage(phone, message)


if __name__ == "__main__":
    import argparse

    # for commandline testing
    parser = argparse.ArgumentParser()
    parser.add_argument("--phone", help="target phone number")
    parser.add_argument("--message", help="greeting message")
    parser.add_argument("--server", help="server address")
    parser.add_argument("--port", help="port number")

    parser.add_argument("--password", help="password")
    parser.add_argument("--system_type", help="type of service")
    parser.add_argument("--source_addr", help="name of sending phone")
    parser.add_argument("--source_addr_npi", help="type of source addr")
    parser.add_argument(
        "--source_addr_ton", help="type of number of source addr"
    )
    parser.add_argument("--system_id", help="user name or system ID")

    # parser.add_argument("--target_encoding",
    #                     help="the supported encoding of the sms submitter")

    # parser.add_argument("dest_addr_npi", help="type of destination addr")
    # parser.add_argument("dest_addr_ton", help=("type of number "
    #                                            "of destination addr"))
    # parser.add_argument("registered_delivery", help=("delivery report "
    #                                                  "requested"))

    args = parser.parse_args()

    config = {}
    attrs = [
        "phone",
        "message",
        "server",
        "port",
        "password",
        "system_type",
        "system_id",
        "source_addr",
        "source_addr_npi",
        "source_addr_ton",
        "dest_addr_npi",
        "dest_addr_ton",
        # 'target_encoding',
        "registered_delivery",
    ]

    for key in attrs:
        try:
            val = getattr(args, key)
            if val:
                config[key] = val
        except:
            pass

    phone = config["phone"]
    message = config["message"]

    main(phone, message, config)

    print("... done!")

# eof ########################################################################

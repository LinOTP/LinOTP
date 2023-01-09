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
import asyncore
import email
import logging
import socket
from contextlib import closing
from multiprocessing import Process, Queue
from smtpd import SMTPServer

from .set_config import SetConfig
from .test_case import TestCase

"""
This file contains functionality to set up an SMTP
process to receive messages from LinOTP and pass
them back to the test case.
"""

logger = logging.getLogger(__name__)


class SmtpListener(SMTPServer):
    """
    SMTPServer class to handle incoming SMTP messages
    """

    def __init__(self, localaddr, queue):
        SMTPServer.__init__(self, localaddr, None, decode_data=True)
        self.queue = queue

    def process_message(self, peer, mailfrom, rcpttos, data, **_kwargs):
        logger.debug("Mail from:%s to:%s data:<%s>", mailfrom, rcpttos, data)
        self.queue.put(data)

    def get_port(self):
        assert self.socket
        addr = self.socket.getsockname()
        logger.debug("SMTP server listening on %s:%s", addr[0], addr[1])
        return addr[1]


def get_otp_mail(queue, timeout):
    """
    Background process runner

    * Start an SMTP server
    * Send the port number through the queue
    * Receive message via SMTP
    * Send message payload through the queue
    """
    smtpserver = SmtpListener(("0.0.0.0", 0), queue)
    port = smtpserver.get_port()
    queue.put(port)
    logger.debug("Waiting on port %s for OTP email", port)
    asyncore.loop(5, False, None, timeout)
    smtpserver.close()


class SmtpMessageServer(object):
    """
    This class can start an SMTP debugging server,
    configure LinOTP to talk to it and read the
    results back to the parent tester.

    On open, an SMTP server is set up to listen locally.
    Derived classes can define a hook to set the LinOTP
    configuration to point to this server.

    Example usage:

    with SmtpMessageServer(testcase) as smtp:
        get_otp()
    """

    def __init__(self, testcase: TestCase, message_timeout: int):
        self.testcase = testcase

        # We need a minimum version of 2.9.2 to set the SMTP port number, so
        # skip if testing an earlier version
        self.testcase.need_linotp_version("2.9.2")

        self.timeout = message_timeout

        self.set_config = SetConfig(testcase)

        # We advertise the local SMTP server hostname
        # using the IP address that connects to LinOTP
        self.addr = self._get_local_ip()
        self.msg_payload = None

    def __enter__(self):
        self.smtp_process_queue = Queue()
        self.smtp_process = Process(
            target=get_otp_mail, args=(self.smtp_process_queue, self.timeout)
        )
        self.smtp_process.start()
        self.port = self.smtp_process_queue.get(True, 5)
        self._do_linotp_config()

        return self

    def _do_linotp_config(self):
        parameters = self.get_config_parameters()

        logger.debug("Configuration parameters: %s", parameters)
        result = self.set_config.setConfig(parameters)

        assert result, (
            "It was not possible to set the config. Result:%s" % result
        )

    def get_config_parameters(self):
        # This function can be overridden to provide configuration parameters to configure
        # specific parts of LinOTP
        assert False, "This function should be overridden"

    def get_otp(self):
        messagestr = self.smtp_process_queue.get(True, 10)
        msg = email.message_from_string(messagestr)
        otp = msg.get_payload()

        logger.debug("Received email message payload:%s", otp)

        return otp

    def __exit__(self, *args):
        self.smtp_process_queue.close()
        self.smtp_process.terminate()
        self.smtp_process.join(5)

    def _get_local_ip(self):
        """
        Get the IP address of the interface that connects to
        LinOTP
        """

        with closing(
            socket.create_connection(
                (self.testcase.http_host, int(self.testcase.http_port)), 10
            )
        ) as s:
            addr = s.getsockname()[0]

        return addr


class EmailProviderServer(SmtpMessageServer):
    """
    Implementation of SmtpMessageServer that configures LinOTP's email provider
    """

    def get_config_parameters(self):

        # SMTP e-mail configuration
        config = """{
            "SMTP_SERVER": "%s",
            "SMTP_PORT": %s
        }""" % (
            self.addr,
            self.port,
        )

        parameters = {"EmailProviderConfig": config}
        return parameters


class SMSProviderServer(SmtpMessageServer):
    """
    Implementation of SmtpMessageServer that configures LinOTP's SMS provider
    to send SMS challenges via email
    """

    def get_config_parameters(self):

        sms_provider_config = """{
            "mailserver" : "%s",
            "mailserver_port": %s,
            "mailsender" : "linotp-sms@localhost",
            "mailto": "seleniumtest@localhost"
        }""" % (
            self.addr,
            self.port,
        )
        print(sms_provider_config)

        # Set SMTP sms config
        parameters = {
            "SMSProvider": "smsprovider.SmtpSMSProvider.SmtpSMSProvider",
            "SMSProviderConfig": sms_provider_config,
        }
        return parameters

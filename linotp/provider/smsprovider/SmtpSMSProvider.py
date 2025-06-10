# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

"""This is the SMSClass to send SMS via HTTP Gateways"""

import logging
import smtplib
from hashlib import sha256

from linotp.lib.type_utils import boolean
from linotp.provider import ProviderNotAvailable, provider_registry
from linotp.provider.smsprovider import ISMSProvider

log = logging.getLogger(__name__)

PHONE_TAG = "<phone>"
MSG_TAG = "<otp>"


@provider_registry.class_entry("SmtpSMSProvider")
@provider_registry.class_entry("linotp.provider.smsprovider.SmtpSMSProvider")
@provider_registry.class_entry("smsprovider.SmtpSMSProvider.SmtpSMSProvider")
@provider_registry.class_entry("smsprovider.SmtpSMSProvider")
class SmtpSMSProvider(ISMSProvider):
    def __init__(self):
        self.config = {}

    """
      submitMessage()
      - send out a message to a phone

    """

    @classmethod
    def getClassInfo(cls, key=None, ret="all"):
        defintion = {}
        parameters = {}
        parameters["mailserver"] = {
            "type": "string",
            "description": "your mail server address",
        }
        parameters["mailserver_port"] = {
            "type": "int",
            "description": "your mail server port - if not default",
        }

        parameters["start_tls"] = {
            "type": "bool",
            "description": "use 'starttls' to secure the mail communication.",
        }

        parameters["keyfile"] = {
            "type": "string",
            "description": "if 'starttls' is defined, a keyfile could be used.",
        }
        parameters["certfile"] = {
            "type": "string",
            "description": "if 'starttls' is defined a certificate file could be used",
        }

        parameters["use_ssl"] = {
            "type": "bool",
            "description": "use_ssl to secure the mail communication.",
        }

        parameters["mailuser"] = {
            "type": "string",
            "description": "the mailserver login user",
        }
        parameters["mailpassword"] = {
            "type": "password",
            "description": "the password of the login user",
        }

        parameters["mailsender"] = {
            "type": "emailaddress",
            "description": "the email sender name",
            "default": "linotp@localhost",
        }
        parameters["mailto"] = {
            "type": "emailaddress",
            "description": "the target email user",
        }

        parameters["subject"] = {
            "type": "string",
            "description": "email subject line",
        }

        parameters["body"] = {
            "type": "string",
            "description": "email body text",
        }

        defintion["parameters"] = parameters

        if not key:
            return defintion

        if key in defintion:
            return defintion[key]

        return {}

    def _submitMessage(self, phone, message):
        """
        Submits the message for phone to the email gateway.

        Returns true in case of success
        """
        ret = False
        if (
            "mailserver" not in self.config
            or "mailsender" not in self.config
            or "mailto" not in self.config
        ):
            log.error(
                "[submitMessage] incomplete config: %s. mailserver, "
                "mailsender and mailto needed.",
                self.config,
            )
            return ret

        # prepare the phone number
        msisdn = "true" in ("%r" % self.config.get("MSISDN", "false")).lower()
        if msisdn:
            phone = self._get_msisdn_phonenumber(phone)

        # prepare the smtp server connection parameters
        default_port = 25

        start_tls_params = {}
        start_tls = str(self.config.get("start_tls", False)).lower() == "true"
        if start_tls:
            default_port = 587
            start_tls_params_keyfile = self.config.get("keyfile", None)
            start_tls_params_certfile = self.config.get("certfile", None)

        use_ssl = str(self.config.get("use_ssl", False)).lower() == "true"
        if use_ssl:
            default_port = 465

        server = self.config.get("mailserver")
        port = int(self.config.get("mailserver_port", default_port))

        # support for mailserver syntax like server:port
        # if port is not explicit defined
        if "mailserver_port" not in self.config and ":" in server:
            server, _sep, port = server.rpartition(":")

        user = self.config.get("mailuser")
        password = self.config.get("mailpassword")

        fromaddr = self.config.get("mailsender", "linotp@localhost")
        toaddr = self.config.get("mailto")
        subject = self.config.get("subject", "")
        body = self.config.get("body", "")

        log.debug("[submitMessage] submitting message %s to %s", message, phone)

        toaddr = toaddr.replace(PHONE_TAG, phone)

        if not subject:
            subject = "[LinOTP]"
        subject = subject.replace(PHONE_TAG, phone)
        subject = subject.replace(MSG_TAG, message)

        if not body:
            body = "<otp>"
        body = body.replace(PHONE_TAG, phone)
        body = body.replace(MSG_TAG, message)

        msg = "From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s" % (
            fromaddr,
            toaddr,
            subject,
            body,
        )

        serv = None
        try:
            serv_class = smtplib.SMTP

            if use_ssl:
                # if SSL is defined, we require a different base class
                serv_class = smtplib.SMTP_SSL

            serv = serv_class(server, port, timeout=self.timeout)

            serv.set_debuglevel(1)

            serv.ehlo()
            if start_tls and not use_ssl:
                if serv.has_extn("STARTTLS"):
                    serv.starttls(start_tls_params_keyfile, start_tls_params_certfile)
                    serv.ehlo()
                else:
                    log.error("Start_TLS not supported:")
                    raise Exception(
                        "Start_TLS requested but not supported by server %r" % server
                    )
            if user:
                if serv.has_extn("AUTH"):
                    log.debug(
                        "authenticating to mailserver, user: %s, pass: %r",
                        user,
                        sha256(password).hexdigest(),
                    )
                    serv.login(user, password)
                else:
                    log.error("AUTH not supported:")

            data_dict = serv.sendmail(fromaddr, toaddr, msg)
            log.debug("sendmail: %r", data_dict)

            (code, response) = serv.quit()
            log.debug("quit: (%r) %r", code, response)
            ret = True

        except smtplib.socket.error as exc:
            log.error("Error: could not connect to server")
            if boolean(self.config.get("raise_exception", True)):
                raise ProviderNotAvailable(
                    "Error: could not connect to server: %r" % exc
                )
            ret = False

        except Exception as exx:
            log.error("[submitMessage] %s", exx)
            if boolean(self.config.get("raise_exception", False)):
                raise Exception(exx)
            ret = False

        finally:
            if serv:
                serv.close()

        return ret

    def loadConfig(self, configDict):
        self.config = configDict
        self.timeout = self.config.get("TIMEOUT", SmtpSMSProvider.DEFAULT_TIMEOUT)


# eof ########################################################################

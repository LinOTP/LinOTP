# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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

"""  This is the SMSClass to send SMS via HTTP Gateways """

import SMSProvider
from SMSProvider import getSMSProviderClass
from SMSProvider import ISMSProvider
from linotp.provider import provider_registry
from hashlib import sha256

import string
import smtplib

import logging
log = logging.getLogger(__name__)

PHONE_TAG = "<phone>"
MSG_TAG = "<otp>"


@provider_registry.class_entry('SmtpSMSProvider')
@provider_registry.class_entry('linotp.provider.smsprovider.SmtpSMSProvider')
@provider_registry.class_entry('smsprovider.SmtpSMSProvider.SmtpSMSProvider')
@provider_registry.class_entry('smsprovider.SmtpSMSProvider')
class SmtpSMSProvider(ISMSProvider):

    def __init__(self):
        self.config = {}

    '''
      submitMessage()
      - send out a message to a phone

    '''

    @classmethod
    def getClassInfo(cls, key=None, ret='all'):

        defintion = {}
        parameters = {}
        parameters['mailserver'] = {'type': 'string',
                                    'description': "your mail server address"
                                    }
        parameters['mailserver_port'] = {'type': 'int',
                                         'description': "your mail server port"
                                                        " - if not default"
                                         }

        parameters["start_tls"] = {'type': 'bool',
                                   'description': "use 'starttls' to secure "
                                                  "the mail communication."
                                   }

        parameters['keyfile'] = {'type': 'string',
                                 'description': "if 'starttls' is defined, a "
                                                "keyfile could be used."
                                 }
        parameters["certfile"] = {'type': 'string',
                                  'description': "if 'starttls' is defined "
                                                 "a certificate file could "
                                                 "be used"
                                  }

        parameters['use_ssl'] = {'type': 'bool',
                                 'description': "use_ssl to secure "
                                                "the mail communication."
                                 }

        parameters["mailuser"] = {'type': 'string',
                                  'description': "the mailserver login user"
                                  }
        parameters["mailpassword"] = {'type': 'password',
                                      'description': "the password of the "
                                                     "login user"
                                      }

        parameters["mailsender"] = {'type': 'emailaddress',
                                    'description': "the email sender name",
                                    'default': "linotp@localhost"
                                    }
        parameters["mailto"] = {'type': 'emailaddress',
                                'description': "the target email user"
                                }

        parameters["subject"] = {'type': 'string',
                                 'description': "email subject line"
                                 }

        parameters["body"] = {'type': 'string',
                              'description': "email body text"
                              }

        defintion['parameters'] = parameters

        if not key:
            return defintion

        if key in defintion:
            return defintion[key]

        return {}

    def _submitMessage(self, phone, message, exception=True):
        '''
        Submits the message for phone to the email gateway.

        Returns true in case of success

        Remarks:
        the exception parameter is not in the official interface and
        the std handling is to pass the exception up to the upper levels.

        '''
        ret = False
        if ('mailserver' not in self.config or
                'mailsender' not in self.config or 'mailto' not in self.config):
            log.error("[submitMessage] incomplete config: %s. mailserver, "
                      "mailsender and mailto needed." % self.config)
            return ret

        # prepare the phone number
        msisdn = 'true' in ("%r" % self.config.get('MSISDN', "false")).lower()
        if msisdn:
            phone = self._get_msisdn_phonenumber(phone)

        # prepare the smtp server connection parameters
        default_port = 25

        start_tls_params = {}
        start_tls = str(self.config.get("start_tls", False)).lower() == 'true'
        if start_tls:
            default_port = 587
            start_tls_params_keyfile = self.config.get("keyfile", None)
            start_tls_params_certfile = self.config.get("certfile", None)

        use_ssl = str(self.config.get("use_ssl", False)).lower() == 'true'
        if use_ssl:
            default_port = 465

        server = self.config.get("mailserver")
        port = int(self.config.get("mailserver_port", default_port))

        # support for mailserver syntax like server:port
        # if port is not explicit defined
        if "mailserver_port" not in self.config and ':' in server:
            server, _sep, port = server.rpartition(':')

        user = self.config.get("mailuser")
        password = self.config.get("mailpassword")

        fromaddr = self.config.get("mailsender", "linotp@localhost")
        toaddr = self.config.get("mailto")
        subject = self.config.get("subject", "")
        body = self.config.get("body", "")

        log.debug("[submitMessage] submitting message %s to %s",
                  message, phone)

        toaddr = string.replace(toaddr, PHONE_TAG, phone)

        if not subject:
            subject = "[LinOTP]"
        subject = string.replace(subject, PHONE_TAG, phone)
        subject = string.replace(subject, MSG_TAG, message)

        if not body:
            body = "<otp>"
        body = string.replace(body, PHONE_TAG, phone)
        body = string.replace(body, MSG_TAG, message)

        msg = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s"
               % (fromaddr, toaddr, subject, body))

        serv = None
        try:
            # if SSL is defined, we require a different base class
            if not use_ssl:
                serv = smtplib.SMTP(server, port)
            else:
                serv = smtplib.SMTP_SSL(server, port)
            serv.set_debuglevel(1)

            serv.ehlo()
            if start_tls and not use_ssl:
                if serv.has_extn('STARTTLS'):
                    serv.starttls(start_tls_params_keyfile,
                                  start_tls_params_certfile)
                    serv.ehlo()
                else:
                    log.error("Start_TLS not supported:")
                    raise Exception("Start_TLS requested but not supported"
                                    " by server %r" % server)
            if user:
                if serv.has_extn('AUTH'):
                    log.debug("authenticating to mailserver, user: %s, "
                              "pass: %r", user, sha256(password).hexdigest())
                    serv.login(user, password)
                else:
                    log.error("AUTH not supported:")

            data_dict = serv.sendmail(fromaddr, toaddr, msg)
            log.debug("sendmail: %r", data_dict)

            (code, response) = serv.quit()
            log.debug("quit: (%r) %r", code, response)
            ret = True

        except Exception as exx:
            log.exception("[submitMessage] %s", exx)
            if exception:
                raise Exception(exx)
            ret = False

        finally:
            if serv:
                serv.close()

        return ret

    def loadConfig(self, configDict):
        self.config = configDict

# eof ########################################################################

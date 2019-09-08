# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
'''Interface to an EMail provider and implementation of the SMPT email provider
'''

import logging
import smtplib
import os
import copy

from hashlib import sha256

from mako.template import Template

from email.mime.text import MIMEText
from linotp.provider import provider_registry
from linotp.lib.type_utils import boolean
from linotp.lib.context import request_context

EMAIL_PROVIDER_TEMPLATE_ROOT = '/etc/linotp/email_provider_tempates'
EMAIL_PROVIDER_TEMPLATE_KEY = 'email_provider_template_root'

LOG = logging.getLogger(__name__)


class IEmailProvider(object):
    """
    An abstract class that has to be implemented by ever e-mail provider class
    """
    provider_type = 'email'

    def __init__(self):
        pass

    @staticmethod
    def getConfigMapping():
        """
        for dynamic, adaptive config entries we provide the abilty to
        have dedicated config entries

        entries should look like:
        {
          key: (ConfigName, ConfigType)
        }
        """
        config_mapping = {'timeout': ('Timeout', None),
                          'config': ('Config', 'encrypted_data')}

        return config_mapping

    def submitMessage(self, email_to, message, subject=None):
        """
        This method has to be implemented by every subclass of IEmailProvider.
        It will be called to send out the e-mail.

        :param email_to: The e-mail address of the recipient
        :type email_to: string

        :param message: The message sent to the recipient
        :type message: string

        :return: A tuple of success and a message
        :rtype: bool, string
        """
        raise NotImplementedError("Every subclass of IEmailProvider has to "
                                  "implement this method.")

    def loadConfig(self, configDict):
        """
        If you implement an e-mail provider that does not require configuration
        entries, then you may leave this method unimplemented.

        :param configDict: A dictionary that contains all configuration
                           entries you defined (e.g. in the linotp.ini file)
        :type configDict: dict
        """
        pass


@provider_registry.class_entry('SMTPEmailProvider')
@provider_registry.class_entry('linotp.provider.emailprovider.'
                               'SMTPEmailProvider')
@provider_registry.class_entry('linotp.lib.emailprovider.SMTPEmailProvider')
class SMTPEmailProvider(IEmailProvider):
    """
    Sends e-mail over a SMTP server.
    """

    DEFAULT_EMAIL_FROM = "linotp@example.com"
    DEFAULT_EMAIL_SUBJECT = "Your OTP"

    def __init__(self):
        self.smtp_server = None
        self.smtp_user = None
        self.smtp_password = None
        self.email_from = None
        self.email_subject = None

        self.start_tls = False
        self.start_tls_params_keyfile = None
        self.start_tls_params_certfile = None


    def loadConfig(self, configDict):
        """
        Loads the configuration for this e-mail e-mail provider

        :param configDict: A dictionary that contains all configuration entries
                          you defined (e.g. in the linotp.ini file)
        :type configDict: dict

        """

        default_port = 25

        self.config = configDict

        self.smtp_server = configDict.get('SMTP_SERVER')

        if not self.smtp_server:
            raise Exception("Invalid EmailProviderConfig. SMTP_SERVER is "
                            "required")

        self.start_tls = boolean(self.config.get("START_TLS", False))
        if self.start_tls:
            default_port = 587
            self.start_tls_params_keyfile = self.config.get("KEYFILE")
            self.start_tls_params_certfile = self.config.get("CERTFILE")

        self.use_ssl = boolean(self.config.get("USE_SSL", False))
        if self.use_ssl:
            default_port = 465

        self.smtp_port = int(configDict.get('SMTP_PORT', default_port))

        self.smtp_user = configDict.get('SMTP_USER')
        self.smtp_password = configDict.get('SMTP_PASSWORD')
        self.email_from = configDict.get(
            'EMAIL_FROM', self.DEFAULT_EMAIL_FROM)
        self.email_subject = configDict.get(
            'EMAIL_SUBJECT', self.DEFAULT_EMAIL_SUBJECT)

        self.template = configDict.get('TEMPLATE', None)


    @staticmethod
    def get_template_root():
        """
        get the email provider template root directory

        if there is in
            'email_provider_template_root' in linotp.config defined

        Fallback is EMAIL_PROVIDER_TEMPLATE_ROOT
                which is '/etc/linotp/email_provider_templates'

        :return: the directory where the email provider templates are expected
        """

        linotp_config = request_context['Config']

        template_root = EMAIL_PROVIDER_TEMPLATE_ROOT

        if linotp_config.get(EMAIL_PROVIDER_TEMPLATE_KEY):
            template_root = linotp_config.get(EMAIL_PROVIDER_TEMPLATE_KEY)

        if not os.path.isdir(template_root):
            LOG.error(
                'Configuration error: no email provider template directory '
                'found: %r')
            raise Exception('Email provider template directory not found')

        return template_root

    @staticmethod
    def render_simple_message(
            email_to, email_from, subject, message, replacements):
        """
        render the email message body based on a simple text message

        :param email_to: the target email address
        :param subject: the subject of the email message could be None
        :param message: the given message
        :param replacements: a dictionary with replacement key/value pairs

        :return: email message body as string
        """

        # ---------------------------------------------------------------- - --

        # legacy pre processing - transfered from email token

        otp = replacements['otp']
        serial = replacements['serial']

        if "<otp>" not in message:
            message = message + "<otp>"

        message = message.replace("<otp>", otp)
        message = message.replace("<serial>", serial)

        subject = subject.replace("<otp>", otp)
        subject = subject.replace("<serial>", serial)

        # ---------------------------------------------------------------- - --

        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = email_from
        msg['To'] = email_to

        return msg.as_string()

    @staticmethod
    def render_template_message(email_to, email_from, subject, template_message, replacements):
        """
        render the email message body based on a template

        the template must be of type multipart/related and can contain
        multipart/alternative

        ```
        Content-Type: multipart/related; boundary="===============2836215581944440979=="
        MIME-Version: 1.0
        Subject: ${Subject}
        From: ${From}
        To: ${To}

        This is a multi-part message in MIME format.
        --===============2836215581944440979==
        Content-Type: multipart/alternative; boundary="===============7101583199791879210=="
        MIME-Version: 1.0
        --===============7101583199791879210==
        Content-Type: text/plain; charset="us-ascii"
        MIME-Version: 1.0
        Content-Transfer-Encoding: 7bit

        This is the alternative plain text message.
        . . .
        ```

        :param email_to:
        :param email_from:
        :param subject:
        :param template_message:
        :param replacements:

        :return: email message body as string
        """

        replacements['Subject'] = subject
        replacements['From'] = email_from
        replacements['To'] = email_to

        template_data = template_message

        if template_message.startswith('file://'):
            with open(template_message[len('file://'):]) as f:
                template_data = f.read()

        # feature - would be nice :)
        #
        # if self.template.startswith('db://'):
        #     read_from_config('linotp.template.' + self.template[len('db://'):])

        from mako.template import Template
        message_template = Template(template_data)

        return message_template.render(**replacements)

    def render_message(
            self, email_to, subject, message, replacements):
        """
        create a text/plain or a template rendered email message

        :param email_to: the target email address
        :param subject: the subject of the email message could be None
        :param message: the given message
        :param replacements: a dictionary with replacement key/value pairs

        :return: the email message body
        """

        email_subject = subject or self.email_subject
        email_from = self.email_from

        if self.template:
            return self.render_template_message(
                email_to, email_from, email_subject,
                self.template, replacements)

        return self.render_simple_message(
                email_to, email_from, email_subject, message, replacements)


    def submitMessage(self, email_to, message, subject=None, replacements=None):
        """
        Sends out the e-mail.

        :param email_to: The e-mail address of the recipient
        :type email_to: string

        :param message: The message sent to the recipient
        :type message: string

        :param subject: otional the subject sent to the recipient
        :type subject: string

        :return: A tuple of success and a message
        :rtype: bool, string
        """

        if not self.smtp_server:
            raise Exception("Invalid EmailProviderConfig. SMTP_SERVER is "
                            "required")

        # ------------------------------------------------------------------ --

        # setup message

        email_message =self.render_message(
            email_to, subject, message, replacements)

        # ------------------------------------------------------------------ --

        # now build up the connection

        # if SSL is defined, we require a different connector class

        smtp_connector = smtplib.SMTP

        if self.use_ssl:
            smtp_connector = smtplib.SMTP_SSL

        smtp_connection = smtp_connector(self.smtp_server, self.smtp_port)

        # ------------------------------------------------------------------ --

        # handle the secure connection build up

        # uncomment the following line for debug purpose
        # smtp_connection.set_debuglevel(1)

        smtp_connection.ehlo()

        if self.start_tls and not self.use_ssl:
            if not smtp_connection.has_extn('STARTTLS'):
                LOG.error("Start_TLS not supported:")
                raise Exception("Start_TLS requested but not supported"
                                " by server %r" % self.smtp_server)

            smtp_connection.starttls(self.start_tls_params_keyfile,
                                     self.start_tls_params_certfile)
            smtp_connection.ehlo()

        # ------------------------------------------------------------------ --

        # authenticate on smtp server

        if self.smtp_user:
            if not smtp_connection.has_extn('AUTH'):
                LOG.error("AUTH not supported:")
                raise Exception("AUTH not supported"
                                " by server %r" % self.smtp_server)

            LOG.debug("authenticating to mailserver, user: %r", self.smtp_user)
            smtp_connection.login(self.smtp_user, self.smtp_password)

        # ------------------------------------------------------------------ --

        # submit message

        try:
            errors = smtp_connection.sendmail(self.email_from,
                                              email_to, email_message)
            if len(errors) > 0:
                LOG.error("error(s) sending e-mail %r", errors)
                return False, ("error sending e-mail %r" % errors)

            return True, "e-mail sent successfully"

        except (
            smtplib.SMTPHeloError,
            smtplib.SMTPRecipientsRefused,
            smtplib.SMTPSenderRefused,
            smtplib.SMTPDataError
        ) as smtplib_exception:

            LOG.error("error(s) sending e-mail. Caught exception: %r",
                      smtplib_exception)

            return False, ("error sending e-mail %r" % smtplib_exception)

        finally:
            if smtp_connection:
                smtp_connection.quit()


# eof

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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
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
from email.header import Header

from linotp.provider import provider_registry
from linotp.lib.type_utils import boolean
from linotp.lib.context import request_context

DEFAULT_MESSAGE = '<otp>'

EMAIL_PROVIDER_TEMPLATE_ROOT = '/etc/linotp2/custom-templates/mailtemplates'
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

        template_root = linotp_config.get(EMAIL_PROVIDER_TEMPLATE_KEY,
                                          EMAIL_PROVIDER_TEMPLATE_ROOT)

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

        otp = replacements.get('otp','')
        serial = replacements.get('serial','')

        if "<otp>" not in message:
            message = message + "<otp>"

        message = message.replace("<otp>", otp)
        message = message.replace("<serial>", serial)

        subject = subject.replace("<otp>", otp)
        subject = subject.replace("<serial>", serial)

        # ---------------------------------------------------------------- - --

        # now trigger the text replacements:

        # first replace the vars in Subject as it can contain as well ${otp}
        # - we use here a copy of the replacement dict without 'Subject' to
        # protect against recursion

        subject_replacements = copy.deepcopy(replacements)
        if 'Subject' in subject_replacements:
            del subject_replacements['Subject']

        subject_replacement = SMTPEmailProvider._render_template(
            subject.encode('utf-8'), subject_replacements)

        # and put it back for the message replacements

        replacements['Subject'] = subject_replacement

        # now build up the final message with all replacements
        email_message = SMTPEmailProvider._render_template(
            message.encode('utf-8'), replacements)

        msg = MIMEText(email_message.encode('utf-8'))
        msg['Subject'] = Header(subject_replacement).encode('utf-8')
        msg['From'] = Header(email_from).encode('utf-8')
        msg['To'] = Header(email_to).encode('utf-8')

        return msg.as_string()

    @staticmethod
    def render_template_message(email_to, email_from, subject,
                                template_message, replacements):
        """
        render the email message body based on a template

        the template must be of type multipart/alternative and can contain
        multipart/related content for example imaged which ewra referenced
        via cid: names

        ```
            Content-Type: multipart/alternative;
             boundary="===============3294676191386143061=="
            MIME-Version: 1.0
            Subject: ${Subject}
            From: ${From}
            To: ${To}

            This is a multi-part alternative message in MIME format.
            --===============3294676191386143061==
            Content-Type: text/plain; charset="us-ascii"
            MIME-Version: 1.0
            Content-Transfer-Encoding: 7bit

            This is the alternative plain text message.
            --===============3294676191386143061==
            Content-Type: multipart/related;
             boundary="===============3984710301122897564=="
            MIME-Version: 1.0

            --===============3984710301122897564==
            Content-Type: text/html; charset="us-ascii"
            MIME-Version: 1.0
            Content-Transfer-Encoding: 7bit

            <html>

            <body>
                <div align='center' height='100%'>
                    <table width='40%' cellpadding='20px' bgcolor="#f1f2f5">
        ```

        :param email_to:
        :param email_from:
        :param subject:
        :param template_message:
        :param replacements:

        :return: email message body as string
        """

        email_subject = subject

        if ((not subject or subject == SMTPEmailProvider.DEFAULT_EMAIL_SUBJECT)
            and "Subject" in replacements):
            email_subject = replacements['Subject']

        replacements['Subject'] = Header(email_subject).encode('utf-8')
        replacements['From'] = Header(email_from).encode('utf-8')
        replacements['To'] = Header(email_to).encode('utf-8')

        template_data = template_message

        # ------------------------------------------------------------------ --

        if template_message.startswith('file://'):

            filename = template_message[len('file://'):]

            provider_template_root = SMTPEmailProvider.get_template_root()

            absolute_filename = os.path.abspath(
                os.path.join(provider_template_root, filename))

            # secure open of the template file - only if it is below the
            # provider template root directory

            if not absolute_filename.startswith(provider_template_root):
                raise Exception(
                    'Template %r - not in email provider template root %r' %
                    (absolute_filename, provider_template_root))

            with open(absolute_filename, "rb") as f:
                template_data = f.read()

        # ------------------------------------------------------------------ --

        # db feature - would be nice :)

        # if self.template.startswith('db://'):
        #     read_from_config('linotp.template.' + self.template[len('db://'):])

        # ------------------------------------------------------------------ --

        # now trigger the text replacements:

        # first replace the vars in Subject as it can contain as well ${otp}
        # - we use here a copy of the replacement dict without 'Subject' to
        # protect against recursion

        subject_replacements = copy.deepcopy(replacements)
        if 'Subject' in subject_replacements:
            del subject_replacements['Subject']

        subject_replacement = SMTPEmailProvider._render_template(
            email_subject.encode('utf-8'), subject_replacements)

        # and put it back for the message replacements

        replacements['Subject'] = subject_replacement

        # now build up the final message with all replacements

        message = SMTPEmailProvider._render_template(
            template_data.encode('utf-8'), replacements)

        return message.encode('utf-8')


    @staticmethod
    def _render_template(template_data, replacements):
        """
        helper to encapsulate the template rendering with unknown ${vars}

        The template rendering here contains a hack as the mako template
        rendering does not support to leave unresolved variable defintions
        untouched. In the normal case an UNKNOWN exception is raised.
        When using the option 'strict_undefined=True' a NameError is raised.

        We use this NameError Exception that is catched to add the missing
        ${var} with the value '${var}' to the replacements and retry the
        rendering.

        This way could help together with the submitted email
        and the log information to identify the missing defintions
        while supporting arbitrary user driven templates

        :param template_data: template text
        :param replacements: the dict with the replacements key values

        :return: rendered text
        """

        message_template = Template(template_data, strict_undefined=True)

        while True:
            try:
                message = message_template.render(**replacements)
                return message
            except NameError as exx:
                var = str(exx).split()[0].strip("'")
                replacements[var]= "${%s}" % var
                LOG.error(
                    'Template refers to unresolved replacement: %r' % var)

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

            # in case of the templating, the subject from the provider config
            # overrules the policy subject

            if message and message != DEFAULT_MESSAGE:
                LOG.warning('ignoring "message" defined by policy - '
                            'using template defintion')

            if subject:
                LOG.warning('ignoring "subject" defined by policy - '
                            'using subject from template defintion')

            if self.email_subject:
                email_subject = self.email_subject

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

        email_message = self.render_message(
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

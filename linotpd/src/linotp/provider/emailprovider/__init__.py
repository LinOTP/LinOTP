# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
from email.mime.text import MIMEText
from linotp.provider import provider_registry


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
                          'config': ('Config', 'password')}

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

    def loadConfig(self, configDict):
        """
        Loads the configuration for this e-mail e-mail provider

        :param configDict: A dictionary that contains all configuration entries
                          you defined (e.g. in the linotp.ini file)
        :type configDict: dict

        """
        self.smtp_server = configDict.get('SMTP_SERVER')
        self.smtp_port = configDict.get('SMTP_PORT', 0)
        self.smtp_user = configDict.get('SMTP_USER')
        self.smtp_password = configDict.get('SMTP_PASSWORD')
        self.email_from = configDict.get('EMAIL_FROM')
        self.email_subject = configDict.get('EMAIL_SUBJECT')

    def submitMessage(self, email_to, message, subject=None):
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
        if not self.email_from:
            self.email_from = self.DEFAULT_EMAIL_FROM

        email_subject = self.DEFAULT_EMAIL_SUBJECT

        if subject:
            email_subject = subject
        elif self.email_subject:
            email_subject = self.email_subject

        status_message = "e-mail sent successfully"
        success = True

        # Create a text/plain message
        msg = MIMEText(message)
        msg['Subject'] = email_subject
        msg['From'] = self.email_from
        msg['To'] = email_to

        smtp_connection = smtplib.SMTP(self.smtp_server, self.smtp_port)
        if self.smtp_user:
            smtp_connection.login(self.smtp_user, self.smtp_password)
        try:
            errors = smtp_connection.sendmail(self.email_from,
                                              email_to, msg.as_string())
            if len(errors) > 0:
                LOG.error("error(s) sending e-mail %r", errors)
                success, status_message = False, ("error sending e-mail %s"
                                                  % errors)

        except (smtplib.SMTPHeloError, smtplib.SMTPRecipientsRefused,
                smtplib.SMTPSenderRefused, smtplib.SMTPDataError
               ) as smtplib_exception:
            LOG.error("error(s) sending e-mail. Caught exception: %r",
                      smtplib_exception)
            success, status_message = False, ("error sending e-mail %r"
                                              % smtplib_exception)
        smtp_connection.quit()
        return success, status_message

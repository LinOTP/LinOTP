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
'''Interface to an EMail provider and implementation of the SMPT email provider
'''

import smtplib
from email.mime.text import MIMEText

import logging
LOG = logging.getLogger(__name__)


class IEmailProvider:
    """
    An abstract class that has to be implemented by ever e-mail provider class
    """
    def __init__(self):
        pass

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

        s = smtplib.SMTP(self.smtp_server)
        if self.smtp_user:
            s.login(self.smtp_user, self.smtp_password)
        try:
            errors = s.sendmail(self.email_from, email_to, msg.as_string())
            if len(errors) > 0:
                LOG.error("[submitMessage] error(s) sending e-mail %r"
                          % errors)
                success, status_message = False, ("error sending e-mail %s"
                                                 % errors)

        except (smtplib.SMTPHeloError, smtplib.SMTPRecipientsRefused,
                smtplib.SMTPSenderRefused, smtplib.SMTPDataError
                ) as smtplib_exception:
            LOG.error("[submitMessage] error(s) sending e-mail. Caught "
                      "exception: %r" % smtplib_exception)
            success, status_message = False, ("error sending e-mail %r"
                                             % smtplib_exception)
        s.quit()
        return success, status_message

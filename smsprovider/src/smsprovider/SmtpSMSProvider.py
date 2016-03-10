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

import string
import smtplib

import logging
log = logging.getLogger(__name__)

PHONE_TAG = "<phone>"
MSG_TAG = "<otp>"

class SmtpSMSProvider(ISMSProvider):
    def __init__(self):
        self.config = {}

    '''
      submitMessage()
      - send out a message to a phone

    '''


    def _submitMessage(self, phone, message, exception=True):
        '''
        Submits the message for phone to the email gateway.

        Returns true in case of success

        Remarks:
        the exception parameter is not in the official interface and
        the std handling is to pass the exception up to the upper levels.

        TODO: fix the interface w.r.t. the exception parameter

        '''
        ret = False
        if (not self.config.has_key('mailserver')
            or not self.config.has_key('mailsender')
            or not self.config.has_key('mailto')):
            log.error("[submitMessage] incomplete config: %s. mailserver, mailsender and mailto needed." % self.config)
            return ret

        server = self.config.get("mailserver")
        user = self.config.get("mailuser")
        password = self.config.get("mailpassword")
        fromaddr = self.config.get("mailsender", "linotp@localhost")
        toaddr = self.config.get("mailto")
        subject = self.config.get("subject", "")
        body = self.config.get("body", "")

        log.debug("[submitMessage] submitting message %s to %s" % (message, phone))

        toaddr = string.replace(toaddr, PHONE_TAG, phone)

        subject = string.replace(subject, PHONE_TAG, phone)
        subject = string.replace(subject, MSG_TAG, message)

        body = string.replace(body, PHONE_TAG, phone)
        body = string.replace(body, MSG_TAG, message)

        msg = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s"
               % (fromaddr,
                  toaddr,
                  subject,
                  body))

        try:
            serv = smtplib.SMTP(server)
            serv.set_debuglevel(1)
            if user:
                log.debug("authenticating to mailserver, user: %s, pass: %s" % (user, password))
                serv.login(user, password)
            dict = serv.sendmail(fromaddr, toaddr, msg)
            #print "sendmail::: ", dict
            (code, response) = serv.quit()
            #print "quit::: ", code, response
            ret = True
        except Exception as  e:
            #print "[submitMessage] %s" % str(e)
            log.error("[submitMessage] %s" % str(e))
            if exception:
                raise Exception(e)
            ret = False

        return ret

    def loadConfig(self, configDict):
        self.config = configDict


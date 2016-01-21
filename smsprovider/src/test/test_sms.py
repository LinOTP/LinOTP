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

import unittest
from unittest import TestCase

#import SMSProvider
#from SMSProvider import ISMSProvider
from smsprovider.SMSProvider import getSMSProviderClass


import smtpd
import asyncore

class CustomSMTPServer(smtpd.SMTPServer):

    def process_message(self, peer, mailfrom, rcpttos, data):
        print 'Receiving message from:', peer
        print 'Message addressed from:', mailfrom
        print 'Message addressed to  :', rcpttos
        print 'Message length        :', len(data)
        return



class TestSMS(TestCase):
    '''
    def test_sms(self):
        print " SMSProvider - class test "

        y = smsprovider.SMSProvider.getProviderClass("SMSProvider", "ISMSProvider")()

        res = y.loadConfig({'nothing':'inside'})

        print " root - " + y.submittMessage("015154294800","root")

        self.assertEquals(res,'0')
    '''
    def setUp(self):
        #server = CustomSMTPServer(('127.0.0.1', 1025), None)
        #asyncore.loop()
        print "EHLO"

    def test_01_smtp(self):
        '''
        This test will fail, since the mailserver does not exist
        '''
        phone = "1234567890"
        message = "123456"
        smtp_config = { 'mailserver' : 'xxx.yyy.zz',
                        'mailsender' : "user@example.com",
                        #'mailuser' : "useraccount",
                        #'mailpassword' : "somesecret",
                        'mailto' : 'user@example.com',
                        'subject' : '<phone>',
                        'body' : 'This is the otp value: <otp>' }


        sms = getSMSProviderClass("SmtpSMSProvider", "SmtpSMSProvider")()
        sms.loadConfig(smtp_config)

        with self.assertRaisesRegexp(Exception, "Name or service not known"):
            sms.submitMessage(phone, message, True)

        smtp_config = { 'mailserver' : 'localhost:1025',
                        'mailsender' : "user@example.com",
                        #'mailuser' : "useraccount",
                        #'mailpassword' : "somesecret",
                        'mailto' : 'user@example.com',
                        'subject' : '<phone>',
                        'body' : 'This is the otp value: <otp>' }

        sms.loadConfig(smtp_config)
        ret = sms.submitMessage(phone, message, exception=False)
        print ret
        assert ret == False

        with self.assertRaisesRegexp(Exception, "Connection refused"):
            sms.submitMessage(phone, message, True)


    def test_02_http(self):
        '''
        Test the HTTP sms provider
        '''
        phone = "1234567890"
        message = "123456"
        ret = False

        clickatell_config = { 'URL' : 'http://api.clickatell.com/http/sendmsg',
        'PARAMETER' : {
            'user':'notme',
            'password':'askme',
            'api_id':'askme',

        },
        'SMS_TEXT_KEY':'text',
        'SMS_PHONENUMBER_KEY':'to',
        'HTTP_Method':'GET',
        "RETURN_SUCCESS":"ID"
        }

        config = {'URL':'http://localhost/cgi-perl/prepaid/private/smsversand.cgi',
              'PARAMETER': {
                          'von':'OWN_NUMBER',
                          'passwort':'PASSWORD',
                          'absender':'TYPE',
                          'konto':'1'
               },
               'SMS_TEXT_KEY':'text',
               'SMS_PHONENUMBER_KEY':'ziel',
               'HTTP_Method':'GET',
               "RETURN_SUCCESS":"ID"
              }

        sms = getSMSProviderClass("HttpSMSProvider", "HttpSMSProvider")()
        with self.assertRaisesRegexp(Exception, "Failed to send SMS. We received a none success reply from the SMS Gateway."):
            sms.loadConfig(clickatell_config)
            ret = sms.submitMessage(phone, message)
        assert ret == False

        with self.assertRaisesRegexp(Exception, "HTTP Error 401: Authorization Required"):
            sms.loadConfig(config)
            ret = sms.submitMessage(phone, message)
        assert ret == False


def main():
    unittest.main()

if __name__ == '__main__':
    main()

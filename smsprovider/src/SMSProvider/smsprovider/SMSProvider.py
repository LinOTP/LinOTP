# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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

""" the SMS Provider Interface """

class ISMSProvider:
    def __init__(self):
        self.config = {}
    def submitMessage(self, phone, message):
        pass
    def loadConfig(self, configDict):
        self.config = configDict
        pass








""" getSMSProviderClass(packageName, className):

helper method to load the SMSProvider class from a given
package in literal:

example:

    getResolverClass("SkypeSMSProvider", "SMSProvider")()

check:
    checks, if the submittMessage method exists
    if not an error is thrown

"""
def getSMSProviderClass(packageName, className):
    mod = __import__(packageName, globals(), locals(), [className])
    klass = getattr(mod, className)
    if not hasattr(klass, "submitMessage"):
        raise NameError("SMSProvider AttributeError: " + packageName + "." + \
              className + " instance of SMSProvider has no method 'submitMessage'")
        return ""
    else:
        return klass

















def main(phone, message):
    print "SMSProvider - class load test "

    config = {'nothing':'defined'}
    #sms = ISMSProvider()

    sms = getSMSProviderClass("SMSProvider", "ISMSProvider")()

    sms.loadConfig(config)
    sms.submitMessage(phone, message)
    print sms


if __name__ == "__main__":
    phone = "015154294800"
    message = "my test sms"
    main(phone, message)
    print "... done!"


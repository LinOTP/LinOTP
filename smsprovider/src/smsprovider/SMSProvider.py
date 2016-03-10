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

""" the SMS Provider Interface """


class ISMSProvider(object):
    """
    Interface class for the SMS providers
    """
    def __init__(self):
        self.config = {}

    def submitMessage(self, phone, message):
        """
        submitMessage - the method of all SMS Providers after preparation
                        the subclass method of _submitMessage() is called

        :param phone: the unformatted, arbitrary phone number
        :param message: the message that should be submitted
        :return: boolean value of success
        """

        # should we transform the phone number according to the MSISDN standard
        msisdn = ISMSProvider.get_bool(self.config, 'MSISDN', False)
        if msisdn:
            phone = self._get_msisdn_phonenumber(phone)

        # suppress_prefix is about to cut off the leading prefix e.g. '+' sign
        # leading with the meaning, that there are only leading white spaces
        suppress_prefix = self.config.get('SUPPRESS_PREFIX', '')
        if suppress_prefix:
            phone = phone.lstrip()
            if phone[0:len(suppress_prefix)] == suppress_prefix:
                phone = phone[len(suppress_prefix):]

        return self._submitMessage(phone, message)

    def loadConfig(self, configDict):
        self.config = configDict
        pass

    @staticmethod
    def _get_msisdn_phonenumber(phonenumber):
        """
        convert the phone number to something more msisdn compliant

        from http://www.msisdn.org/:
          In GSM standard 1800, this number is built up as
            MSISDN = CC + NDC + SN
            CC = Country Code
            NDC = National Destination Code
            SN = Subscriber Number

        there are two version of the msisdn: the global definition and
        the local definition, with the difference, that the global definition
        might start with an +CC country code. in this conversion routine, the
        global prefixing is ignored
        """
        msisdn = []

        if phonenumber.strip()[0] == '+':
            msisdn.append('+')

        for character in phonenumber:
            if character.isdigit():
                msisdn.append(character)

        return "".join(msisdn)

    @staticmethod
    def get_bool(config, key, default):
        """
        helper method - get the boolean value from a config entry,
                        which could be either boolean or string

        as we might get from the json a real boolean or a string, we use
        the %r to print the representation to generalize the processing
        """
        as_str = str(config.get(key, default))
        return 'true' == as_str.lower()


def getSMSProviderClass(packageName, className):
    """
    helper method to load the SMSProvider class from a given
    package in literal: checks, if the submittMessage method exists
    else an error is thrown

    example:
        getResolverClass("SkypeSMSProvider", "SMSProvider")()

    :return: the SMS provider object

    """

    mod = __import__(packageName, globals(), locals(), [className])
    klass = getattr(mod, className)
    if not hasattr(klass, "submitMessage"):
        raise NameError("SMSProvider AttributeError: %r.%r "
                        "instance of SMSProvider has no method 'submitMessage'"
                        % (packageName, className))
    else:
        return klass

## eof ########################################################################

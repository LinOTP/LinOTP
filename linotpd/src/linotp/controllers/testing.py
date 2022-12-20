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
"""
testing controller - for testing purposes
"""

import logging

from pylons import request, response
from linotp.lib.base import BaseController

from linotp.lib.error import ParameterError

from linotp.lib.reply import sendResult, sendError

from linotp.lib.selftest import isSelfTest
from linotp.lib.policy import get_auth_AutoSMSPolicy

from linotp.lib.crypto import urandom

import linotp.model

Session = linotp.model.Session

log = logging.getLogger(__name__)

# from paste.debug.profile import profile_decorator

# some twilio like test data
twilio_ok = """<?xml version='1.0' encoding='UTF-8'?>\
<TwilioResponse>\
<Message>\
<Sid>SM6552db38d10548cd4161826fa5754530</Sid>\
<DateCreated>Mon,10 Aug 2015 08:43:33 +0000</DateCreated>\
<DateUpdated>Mon, 10 Aug 2015 08:43:33+0000</DateUpdated>\
<DateSent/>\
<AccountSid>AC710548cd4161826fa5754530ea71fb03</AccountSid>\
<To>+491171410210</To>\
<From>+4911714102109</From><Body>testmessage</Body>\
<Status>queued</Status><NumSegments>1</NumSegments><NumMedia>0</NumMedia>\
<Direction>outbound-api</Direction><ApiVersion>2010-04-01</ApiVersion>\
<Price/>\
<PriceUnit>USD</PriceUnit><ErrorCode/><ErrorMessage/>\
<Uri>/2010-04-01/Accounts/AC710548cd4161826fa5754530ea71fb03/Messages/SM65af\
852db38d10548cd4161826fa5754</Uri>\
<SubresourceUris>\
<Media>/2010-04-01/Accounts/AC710548cd4161826fa5754530ea71fb03/Messages/SM65af\
852db38d10548cd4161826fa5754/Media</Media>\
</SubresourceUris>\
</Message>\
</TwilioResponse>\
"""
twilio_fail = """<?xml version='1.0' encoding='UTF-8'?>\
<TwilioResponse>\
<RestException>\
<Code>21603</Code>\
<Message>A 'From' phone number is required.</Message>\
<MoreInfo>https://www.twilio.com/docs/errors/21603</MoreInfo>\
<Status>400</Status>\
</RestException>\
</TwilioResponse>\
"""


class TestingController(BaseController):

    '''
    The linotp.controllers are the implementation of the web-API to talk to
    the LinOTP server.

        https://server/testing/<functionname>

    The functions are described below in more detail.
    '''

    def __before__(self):
        return response

    def __after__(self):
        return response

    def autosms(self):
        '''
        This function is used to test the autosms policy

        method:
            testing/autosms

        arguments:
            user    - username / loginname
            realm   - additional realm to match the user to a useridresolver


        returns:
            JSON response
        '''

        try:
            if isSelfTest() is False:
                Session.rollback()
                return sendError(response, "The testing controller can only"
                                 " be used in SelfTest mode!", 0)

            if "user" not in self.request_params:
                raise ParameterError("Missing parameter: 'user'")

            ok = get_auth_AutoSMSPolicy()

            Session.commit()
            return sendResult(response, ok, 0)

        except Exception as exx:
            log.exception("[autosms] validate/check failed: %r", exx)
            Session.rollback()
            return sendError(response, ("validate/check failed: %r", exx), 0)

        finally:
            Session.close()

    def http2sms(self):
        '''
        This function simulates an HTTP SMS Gateway.

        method:
            test/http2sms

        arguments:

           * sender, absender
           * from, von
           * destination, ziel
           * password, passwort
           * from, von
           * text
           * account
           * api_id


        returns:
           As this is a test controller, the response depends on
           the input values.

            account = 5vor12, sender = legit
                -> Response Success: "200" (Text)

            account = 5vor12, sender = <!legit>
                -> Response Failed: "Failed" (Text)

            account = clickatel, username = legit
                -> Response Success: "ID <Random Number>" (Text)

            account = clickatel, username = <!legit>
                -> Response Success: "FAILED" (Text)
        '''
        param = self.request_params

        try:
            try:
                account = param["account"]
            except KeyError:
                raise ParameterError("Missing parameter: 'account'")

            sender = param.get("sender")
            username = param.get("username")

            destination = param.get("destination")
            if not destination:
                destination = param.get("ziel")

            text = param.get("text")

            if not destination:
                raise Exception("Missing <destination>")

            if not text:
                raise Exception("Missing <text>")

            if account == "5vor12":
                if sender == "legit":
                    return "200"
                else:
                    return "Failed"

            elif account == "clickatel":
                if username == "legit":
                    return "ID %i" % int(urandom.randint(1000))
                else:
                    return "FAILED"

            elif account == "twilio":
                if username == "legit":
                    return twilio_ok
                else:
                    return twilio_fail

            Session.commit()
            return "Missing account info."

        except Exception as e:
            log.exception('[http2sms] %r' % e)
            Session.rollback()
            return sendError(response, unicode(e), 0)

        finally:
            Session.close()


# eof #

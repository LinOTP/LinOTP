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
"""


class TwillioMixin:
    @staticmethod
    def load_twilio_definition(configDict):
        """
        load the twilio voice service configuration
        """

        if "twilioConfig" not in configDict:
            return {}

        twilio_config = configDict["twilioConfig"]

        twilio_config_keys = [
            "accountSid",
            "authToken",
            "voice",
            "callerNumber",
        ]

        if "accountSid" not in twilio_config:
            raise KeyError("missing the required account identifier")

        if "authToken" not in twilio_config:
            raise KeyError("missing the required authentication token")

        if "voice" not in twilio_config:
            twilio_config["voice"] = "alice"

        if "callerNumber" not in twilio_config:
            raise KeyError("missing the required caller number")

        if set(twilio_config.keys()) != set(twilio_config_keys):
            raise KeyError(
                "unsupported key provided [%r]: %r!"
                % (twilio_config_keys, list(twilio_config.keys()))
            )

        return {"twilioConfig": twilio_config}

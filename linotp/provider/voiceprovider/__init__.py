#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
""" """


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
            msg = "missing the required account identifier"
            raise KeyError(msg)

        if "authToken" not in twilio_config:
            msg = "missing the required authentication token"
            raise KeyError(msg)

        if "voice" not in twilio_config:
            twilio_config["voice"] = "alice"

        if "callerNumber" not in twilio_config:
            msg = "missing the required caller number"
            raise KeyError(msg)

        if set(twilio_config.keys()) != set(twilio_config_keys):
            msg = f"unsupported key provided [{twilio_config_keys!r}]: {list(twilio_config.keys())!r}!"
            raise KeyError(msg)

        return {"twilioConfig": twilio_config}

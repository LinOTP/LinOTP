#!/usr/bin/env python3
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""
This is a SMS Provide class that can send OTP values via SMS using a phone
that is connected to the LinOTP server

This module makes use of the command line programm gnokii. It gets configured
in a file .gnokiirc file like this:

[global]
model = AT
port = /dev/ttyACM1
connection = serial

"""

import logging
import subprocess

from linotp.provider import provider_registry
from linotp.provider.smsprovider import ISMSProvider, getSMSProviderClass

log = logging.getLogger(__name__)


@provider_registry.class_entry("DeviceSMSProvider")
@provider_registry.class_entry("linotp.provider.smsprovider.DeviceSMSProvider")
@provider_registry.class_entry("smsprovider.DeviceSMSProvider.DeviceSMSProvider")
@provider_registry.class_entry("smsprovider.DeviceSMSProvider")
class DeviceSMSProvider(ISMSProvider):
    def __init__(self):
        self.config = {}

    def _submitMessage(self, phone, message):
        """
        submitMessage()
        - send out a message to a phone

        """
        if "CONFIGFILE" not in self.config:
            log.error("[submitMessage] No config key CONFIGFILE found!")
            return False

        # NOTE 1: The LinOTP service account need rw-access to /dev/ttyXXX
        # NOTE 2: we need gnokii 0.6.29 or higher, since 0.6.28 will crash with
        # a bug
        args = [
            "gnokii",
            "--config",
            self.config.get("CONFIGFILE"),
            "--sendsms",
            phone,
        ]

        if "SMSC" in self.config:
            args.append("--smsc")
            args.append(self.config.get("SMSC"))

        log.info("[submitMessage] sending SMS : %s", " ".join(args))
        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
        )

        (smsout, smserr) = proc.communicate(message)

        if proc.returncode == 0:
            log.debug("[submitMessage] output: %s", smsout)
            return True

        log.error("[submitMessage] output: %s", smsout)
        log.error(
            "[submitMessage] SMS sending failed, return code: %s",
            proc.returncode,
        )

        return False

    def loadConfig(self, configDict):
        self.config = configDict
        log.info("loading config for DeviceSMSProvider")


def main(phone, message):
    print("SMSProvider - class load test ")

    # echo "text" | gnokii --config <filename> <ziel>

    config = {
        "CONFIGFILE": "/home/user/.gnokiirc",
    }

    sms = getSMSProviderClass("DeviceSMSProvider", "DeviceSMSProvider")()

    sms.loadConfig(config)
    _ret = sms.submitMessage(phone, message)
    print(sms)


if __name__ == "__main__":
    phone = "+4901234567890"
    # phone      = "015154294800"
    message = "DeviceSMSProviderClass test. blocking. :-/"
    main(phone, message)
    print("... done!")

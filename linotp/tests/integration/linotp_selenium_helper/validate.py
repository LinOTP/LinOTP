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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
"""Contains Validate class to verify OTP values"""

import logging

import requests
from requests.auth import HTTPDigestAuth

logger = logging.getLogger(__name__)


class Validate:
    """Creates a LinOTP Validate class"""

    def __init__(
        self, http_protocol, http_host, http_port, http_username, http_password
    ):
        """Initializes the class with the required values to call
        https://.../validate/check
        """
        self.auth = HTTPDigestAuth(http_username, http_password)
        self.validate_url = http_protocol + "://" + http_host
        if http_port:
            self.validate_url += ":" + http_port

    def _check(self, params):
        "Send a request and parse JSON result"
        url = self.validate_url + "/validate/check?"

        # With newer requests versions it seems, that the
        # api hook url and its params needs to be
        # concatenated as string.
        try:
            r = requests.get(url, params, auth=self.auth, verify=False)
        except BaseException:
            # We need to concatenate parameter names (key)
            # and values to a valid url parameter string.
            # e.g.
            #     user=bach@se_scenario01_realm1&pass=bachnewpin118881
            strparams = ""
            for key in params:
                strparams += key + "=" + params[key] + "&"
            # Remove last '&'
            strparams = strparams[:-1]

            r = requests.get(url + strparams, auth=self.auth, verify=False)

        if r.status_code != 200:
            return False
        return_json = r.json()
        assert return_json is not None, (
            "Json response may not be empty %s" % return_json
        )
        assert "result" in return_json, (
            "Missing result in Json %s" % return_json
        )

        return return_json

    def version(self):
        """
        Use validate/check to retrieve LinOTP version number
        and return as a string. Example: '2.9.1'
        """
        return_json = self._check({})
        version_string = return_json["version"]
        _, version = version_string.split(" ")  # Remove 'LinOTP ' prefix
        return version

    def validate(self, user, password):
        """Validates 'user' with 'password' (PIN+OTP)

        Returns a boolean to quickly check if access was granted and the full response
        as a JSON dictionary.
        :return: (access_granted, return_json)
        :rtype: (Bool, dict)
        """

        params = {"user": user, "pass": password}
        return_json = self._check(params)
        result = return_json["result"]

        if not result["status"]:
            logger.debug("Failed validate (user=%s), result: %s", user, result)
            return False, return_json

        logger.debug("validate (user=%s), result: %s", user, result)
        assert "value" in result, "Missing value in result %s" % (result)
        access_granted = result["value"]
        return access_granted, return_json

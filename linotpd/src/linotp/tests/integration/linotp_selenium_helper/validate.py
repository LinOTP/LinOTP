# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2015 LSE Leading Security Experts GmbH
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
"""Contains Validate class to verify OTP values"""

import requests
from requests.auth import HTTPDigestAuth

class Validate:
    """Creates a LinOTP Validate class"""

    def __init__(self, http_protocol, http_host, http_port, http_username, http_password):
        """Initializes the class with the required values to call
           https://.../validate/check
        """
        self.auth = HTTPDigestAuth(http_username, http_password)
        self.validate_url = http_protocol + "://" + http_host
        if http_port:
            self.validate_url += ':' + http_port
        self.validate_url += "/validate/check?"

    def validate(self, user, password):
        """Validates 'user' with 'password' (PIN+OTP)

           Returns a boolean to quickly check if access was granted and the full response
           as a JSON dictionary.
           :return: (access_granted, return_json)
           :rtype: (Bool, dict)
        """
        r = requests.get(self.validate_url,
                         params={'user': user, 'pass': password},
                         auth=self.auth,
                         verify=False)
        if r.status_code != 200:
            return False
        return_json = r.json()
        if (return_json is None or
               'result' not in return_json or
               'value' not in return_json['result'] or
               'status' not in return_json['result']):
            raise Exception("Invalid return value: %r" % return_json)
        access_granted = return_json['result']['value'] and return_json['result']['status']
        return access_granted, return_json


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
"""Contains SetConfig class to call system/setConfig"""

import logging
import requests
from requests.auth import HTTPDigestAuth
from .helper import get_session


LOG = logging.getLogger(__name__)


class SetConfig:

    def __init__(self, http_protocol, http_host, http_port, http_username, http_password):
        """Initializes the class with the required values to call
           https://.../system/setConfig
        """
        self.auth = HTTPDigestAuth(http_username, http_password)
        url = http_protocol + "://" + http_host
        if http_port:
            url += ':' + http_port
        url += '/'
        self.set_config_url = url + "system/setConfig?"
        self.session = get_session(url, http_username, http_password)

    def setConfig(self, parameters):
        """Sets the config with the parameters
           return True if result.value and result.status is True
        """
        parameters['session'] = self.session
        r = requests.get(self.set_config_url,
                         params=parameters,
                         cookies={'admin_session': self.session},
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
        return (return_json['result']['status'])


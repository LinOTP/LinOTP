# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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

import json

from linotp.tests import TestController, url


class TestUserserviceController(TestController):
    def define_sms_provider(self, provider_params=None):
        """
        define the new provider via setProvider
        """
        params = {
            "name": "newone",
            "config": '{"file":"/tmp/newone"}',
            "timeout": "301",
            "type": "sms",
            "class": "smsprovider.FileSMSProvider.FileSMSProvider",
        }

        if provider_params:
            params.update(provider_params)

        response = self.make_system_request("setProvider", params=params)

        return response

    def define_email_provider(self, provider_params=None):
        email_conf = {
            "SMTP_SERVER": "mail.example.com",
            "SMTP_USER": "secret_user",
            "SMTP_PASSWORD": "secret_pasword",
        }

        params = {
            "name": "new_email_provider",
            "config": json.dumps(email_conf),
            "timeout": "30",
            "type": "email",
            "class": "linotp.provider.emailprovider.SMTPEmailProvider",
        }

        if provider_params:
            params.update(provider_params)

        return self.make_system_request("setProvider", params=params)

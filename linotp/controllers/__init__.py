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
This is the controller module. The controllers provide the Web API to
communicate with LinOTP. You can use the following controllers:

+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.admin`       | API to manage the tokens                 |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.audit`       | to search the audit trail                |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.auth`        | to do authentication tests               |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.error`       | to display errors                        |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.gettoken`    | to retrieve OTP values                   |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.maintenance` | for internal maintenance purposes        |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.manage`      | the Web UI                               |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.monitoring`  | for system monitoring                    |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.openid`      | the openid interface                     |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.ocra`        | Ocra token API                           |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.selfservice` | the selfservice UI                       |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.system`      | to configure the system                  |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.tools`       | to access various tools                  |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.u2f`         | U2F token API                            |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.userservice` | user API, used by selfservice frontend   |
+--------------------------------------------+------------------------------------------+
| :py:class:`linotp.controllers.validate`    | for authenticating / OTP checking        |
+--------------------------------------------+------------------------------------------+

Additionally there is a new set of controllers accessible under /api/v2, providing the
same functionality as some of the previous controllers, but with a more RESTful
interface:

+--------------------------------------------+-------------------------------------------+
| :py:class:`linotp.controllers.tokens`      | API to manage tokens                      |
+--------------------------------------------+-------------------------------------------+
| :py:class:`linotp.controllers.realms`      | API to manage realms                      |
+--------------------------------------------+-------------------------------------------+
| :py:class:`linotp.controllers.resolvers`   | API to manage resolvers and look up users |
+--------------------------------------------+-------------------------------------------+

"""

from .base import BaseController

__all__ = ["BaseController"]

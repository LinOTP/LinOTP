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
"""Helper classes for LinOTP Selenium Tests"""

from . import helper
from .policy import Policy
from .self_service import SelfService
from .self_service_angular import AngularSelfService
from .test_case import TestCase
from .token_enroll import EnrollTokenDialog
from .user_id_resolver import (
    LdapUserIdResolver,
    PasswdUserIdResolver,
    SqlUserIdResolver,
    UserIdResolver,
    UserIdResolverManager,
)

__all__ = [
    "helper",
    "EnrollTokenDialog",
    "Policy",
    "SelfService",
    "AngularSelfService",
    "TestCase",
    "UserIdResolverManager",
    "UserIdResolver",
]

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
"""Helper classes for LinOTP Selenium Tests"""

from linotp_selenium_helper.test_case import TestCase
from linotp_selenium_helper.ldap_user_id_resolver import LdapUserIdResolver
from linotp_selenium_helper.sql_user_id_resolver import SqlUserIdResolver
from linotp_selenium_helper.passwd_user_id_resolver \
     import PasswdUserIdResolver
from linotp_selenium_helper.realm import Realm
from linotp_selenium_helper.policy import Policy

__all__ = ["TestCase", "LdapUserIdResolver", "SqlUserIdResolver",
           "PasswdUserIdResolver", "Realm", "Policy"]



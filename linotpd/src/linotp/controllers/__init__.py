# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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

'''
This is the controller module. The controllers provide the Web API to
communicate with LinOTP. You can use the following controllers:

account		- used for loggin in to the selfservice
admin		- API to manage the tokens
audit		- to search the audit trail
auth		- to do authentication tests
error		- to display errors
gettoken	- to retrieve OTP values
manage		- the Web UI
openid		- the openid interface
selfservice	- the selfservice UI
system		- to configure the system
testing		- for testing purposes
validate	- for authenticating/ OTP checking

'''


# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#


'''
LinOTP is an open solution for strong two-factor authentication
       with One Time Passwords.

SMSProvider is the iterface to the final sms submitting service
LinOTP provides  3 types of implementation: HTTPSMS, SMTP and Device
sms submitt.

'''


# IMPORTANT! This file is imported by setup.py, therefore do not (directly or
# indirectly) import any module that might not yet be installed when installing
# SMSProvider.

__copyright__ = "Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH"
__license__ = "Gnu AGPLv3"
__contact__ = "www.linotp.org"
__email__ = "linotp@lsexperts.de"
__version__ = '2.8.1.2'

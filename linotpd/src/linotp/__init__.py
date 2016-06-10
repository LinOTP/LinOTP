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
LinOTP is an open solution for strong two-factor authentication
       with One Time Passwords.

LinOTP server is licensed under the AGPLv3, so that you are able to have a
complete working open source solution. But LinOTP 2 is also open as far as its
modular architecture is concerned.
LinOTP 2 aims to not bind you to any decision of the authentication protocol
or it does not dictate you where your user information should be stored. This
is achieved by its new, totally modular architecture.


Tokenclasses
------------

    LinOTP already comes with several tokenclasses defined in linotp.lib.tokens
    But you can simply define your own tokenclass object. Take a look at
    the base class in tokenclass.py

UserIdResolvers
---------------

    LinOTP can use arbitrary methods to look up your user base - the userid
    resolvers. With LinOPT comes a flatfile (passwd), the ldap/active directory
    resolver and a sql resolver.


LinOTP is accessed via a simple http based api, which returns json object
that are easy to integrate into your authetication solution. Or you can use
the simple webui which come with linotp

'''

# IMPORTANT! This file is imported by setup.py, therefore do not (directly or
# indirectly) import any module that might not yet be installed when installing
# LinOTP.

__copyright__ = "2010 - 2016 LSE Leading Security Experts GmbH"
__product__ = "LinOTP"
__license__ = "Gnu AGPLv3"
__contact__ = "www.linotp.org"
__email__ = "linotp@lsexperts.de"
__version__ = '2.8.1.2'

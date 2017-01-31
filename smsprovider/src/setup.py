# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

from setuptools import setup, find_packages

from smsprovider import __version__

setup(
    name='SMSProvider',
    version=__version__,
    description='LinOTP2 modules for submitting SMS messages',
    author='KeyIdentity GmbH',
    author_email='linotp@keyidentity.com',
    keywords='OTP LinOTP2 SMS',
    url='https://www.linotp.org',
    packages=['smsprovider'],
    install_requires=[
        "httplib2"
    ],
#    scripts=['linotpadm.py'],
    data_files=[('share/linotp', ['test/test_sms.py' ]),
       ],
    license='AGPLv3, (C) KeyIdentity GmbH',
    long_description="""LinOTP is an open solution for strong two-factor authentication with One Time Passwords.
        LinOTP 2 is also open as far as its modular architecture is concerned.
        LinOTP 2 aims to not bind you to any  decision of the authentication protocol or
        it does not dictate you where your user information should be stored.
        This is achieved by its new, totally modular architecture.

        This package contains the LinOTP SMSProvider.""",
)

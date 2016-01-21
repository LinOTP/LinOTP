#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP admin clients.
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

#from distutils.core import setup
from setuptools import setup
import platform

from linotpadminclientgui import __version__

system = platform.system()
if system == "Windows":
    import py2exe

setup(
    name='LinOTPAdminClientGUI',
    version=__version__,
    description='LinOTP GUI client',
    author='LSE Leading Security Experts GmbH',
    author_email='linotp@lsexperts.de',
    url='http://www.linotp.org',
    packages=['linotpadminclientgui'],
    install_requires=[
        "configobj>=4.6.0"
	],
    scripts=['bin/glinotpadm.py',
             'tools/linotp-etng-enrollment' ],
    data_files=[('share//linotpadm', ['linotp_logo_200x68_72dpi.png', 'logo_main_lse.png' ]),
		('share//linotpadm', ['glinotpadm.glade']),
		('share/locale/de/LC_MESSAGES', ['locale/de/LC_MESSAGES/LinOTP2.mo']),
		('share//man//man1', ["doc/glinotpadm.py.1",
                              "tools/linotp-etng-enrollment.1"]),
	],
    license='AGPLv3, (C) LSE Leading Security Experts GmbH',
    long_description='LinOTP is an open solution for strong two-factor authentication with One Time Passwords.\n\
	LinOTP 2 is also open as far as its modular architecture is concerned. \n\
	LinOTP 2 aims to not bind you to any  decision of the authentication protocol or \n\
	it does not dictate you where your user information should be stored. \n\
	This is achieved by its new, totally modular architecture.\n\
\n\
	This package contains the LinOTP Management GUI.'
)

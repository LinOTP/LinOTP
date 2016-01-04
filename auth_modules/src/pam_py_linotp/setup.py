#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#   This file is part of LinOTP authentication modules.
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.

#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
#
#

try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

from pam_py_linotp import __version__

setup(
    name='pam_py_linotp',
    version=__version__,
    description='LinOTP python PAM module',
    author='LSE Leading Security Experts GmbH',
    license='GPL v2, (C) LSE Leading Security Experts GmbH',
    author_email='linotp-community@lsexperts.de',
    url='http://www.linotp.org',
    packages=['pam_py_linotp'],
    include_package_data=True,
    install_requires=[
    ],
    data_files=[('/lib/security/', ['src/pam_linotp.py'])],
    classifiers=[
        "Framework :: Pylons",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: System :: Systems Administration :: Authentication/Directory"
    ],
    zip_safe=False,
    long_description='LinOTP is an open solution for strong two-factor authentication with One Time Passwords.\n\
        LinOTP 2 is also open as far as its modular architecture is concerned. \n\
        LinOTP 2 aims to not bind you to any  decision of the authentication protocol or \n\
        it does not dictate you where your user information should be stored. \n\
        This is achieved by its new, totally modular architecture.\n\
\n\
        This package contains a PAM module for LinOTP written in python.'
)

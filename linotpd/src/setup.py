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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

import os
import sys

from setuptools import setup, find_packages
from setuptools.command.build_py import build_py

from linotp import __version__

# Taken from kennethreitz/requests/setup.py
package_directory = os.path.realpath(os.path.dirname(__file__))

install_requirements = [
    'Flask',
    'Flask-Mako',
    'Flask-Babel',
    'SQLAlchemy>=0.6',
    'beaker',
    'docutils>=0.4',
    'simplejson>=2.0',
    'pycryptodomex>=3.4',
    'pyrad>=1.1',
    'netaddr',
    'qrcode>=2.4',
    'configobj>=4.6.0',
    'httplib2',
    'requests',
    'pillow',
    'passlib',
    'pysodium>=0.6.8',
    # python-ldap needs libsasl2-dev and libldap2-dev system packages on
    # debian buster to be installable via pip or install python-ldap via
    # apt.
    'python-ldap',
    'bcrypt',
    'cryptography',
    'click',
    # Pygments 2.6.0,1 breaks tests so exclude it
    "Pygments < 2.6.0",
]

# Requirements needed to run all the tests
# install with
# > pip install -e ".[test]"
test_requirements = [
    'flask_testing',
    'pytest',
    'pytest-cov',
    'pytest-freezegun',
    'pytest-flask',
    'pytest-selenium',
    'pytest-testconfig',
    'mock',
    'mockldap',
    'freezegun',
    'coverage',
    'pylint',
    'autopep8',
    'flaky',
]

apidocs_requirements = [
    'Sphinx>=3.0',
    'mock',
]

# packages needed during package build phase
setup_requirements = [
    'Babel',
]

# install with
# > pip install -e ".[postgres]"
postgres_requirements = [
    # 'psycopg2' would require to compile some sources
    'psycopg2-binary',
]

# install with
# > pip install -e ".[mysql]"
mysql_requirements = [
    'mysql',
]

# Inspired by http://www.mattlayman.com/2015/i18n.html


class Build(build_py):
    """
    Custom ``build_py`` command to ensure that mo files are always created.
    """

    def run(self):
        self.run_command('compile_catalog')
        # build_py is an old style class so super cannot be used.
        build_py.run(self)


with open('DESCRIPTION') as f:
    DESCRIPTION = f.read()

setup(
    name='LinOTP',
    version=__version__,
    description='LinOTP Service',
    author='KeyIdentity GmbH',
    license='AGPL v3, (C) KeyIdentity GmbH',
    author_email='linotp@keyidentity.com',
    url='https://www.linotp.org',
    setup_requires=setup_requirements,
    install_requires=install_requirements,
    extras_require={
        'postgres': postgres_requirements,
        'mysql': mysql_requirements,
        'test': test_requirements,
        'apidocs': apidocs_requirements,
    },
    tests_require=test_requirements,

    packages=find_packages(),
    include_package_data=True,
    package_data={'linotp': ['linotp/i18n/*/LC_MESSAGES/*.mo']},
    scripts=[
        'tools/linotp-convert-token',
        'tools/linotp-create-pwidresolver-user',
        'tools/linotp-create-sqlidresolver-user',
        'tools/linotp-setpins',
        'tools/linotp-pip-update',
        'tools/linotp-create-enckey',
        'tools/linotp-create-auditkeys',
        'tools/linotp-create-certificate',
        'tools/linotp-create-database',
        'tools/linotp-fix-access-rights',
        'tools/totp-token',
        'tools/linotp-token-usage',
        'tools/linotp-create-ad-users',
        'tools/linotp-auth-radius',
        'tools/linotp-sql-janitor',
        'tools/linotp-tokens-used',
        'tools/linotp-backup',
        'tools/linotp-decrypt-otpkey',
        'tools/linotp-convert-gemalto',
        'tools/linotp-restore',
        'tools/linotp-enroll-smstoken',
    ],
    data_files=[
        (
            'etc/linotp/',
            [
                'config/linotpapp.wsgi',
                'config/push-ca-bundle.crt',
                # 'dictionary',
            ]
        ),
        (
            '/etc/linotp/apache-site-includes/',
            [
                'config/apache-site-includes/README.txt',
            ]
        ),
        (
            'share/doc/linotp/examples',
            [
                'examples/apache-site.conf',
                'examples/mailtemplate-authenticate.eml',
                'examples/mailtemplate-enroll.eml',
                'examples/mailtemplate-set-pin.eml',
            ]
        ),
        (
            'share/man/man1',
            [
                "tools/linotp-convert-token.1",
                "tools/linotp-create-pwidresolver-user.1",
                "tools/linotp-create-sqlidresolver-user.1",
                "tools/totp-token.1",
                "tools/linotp-setpins.1",
                "tools/linotp-pip-update.1",
                "tools/linotp-create-enckey.1",
                "tools/linotp-create-auditkeys.1",
                "tools/linotp-create-certificate.1",
                "tools/linotp-create-database.1",
                "tools/linotp-fix-access-rights.1",
                "tools/linotp-token-usage.1",
                "tools/linotp-sql-janitor.1",
                "tools/linotp-tokens-used.1",
                "tools/linotp-backup.1",
                "tools/linotp-decrypt-otpkey.1",
                "tools/linotp-convert-gemalto.1",
                "tools/linotp-restore.1"
            ]
        ),
        (
            'share/linotp',
            [
                'tools/LinotpLDAPProxy.pm',
                'config/linotp.cfg',
            ]
        ),
    ],
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: System :: Systems Administration :: Authentication/Directory"
        "Framework :: Flask",
    ],
    message_extractors={
        'linotp': [
            (
                '**.py',
                'python',
                None
            ),
            (
                'templates/**.mako',
                'mako',
                {
                    'input_encoding': 'utf-8'
                }
            ),
            (
                'tokens/**.mako',
                'mako',
                {
                    'input_encoding': 'utf-8'
                }
            ),
            (
                'public/js/manage.js',
                'javascript',
                {
                    'input_encoding': 'utf-8'
                }
            ),
            (
                'public/js/tools.js',
                'javascript',
                {
                    'input_encoding': 'utf-8'
                }
            ),
            (
                'public/js/selfservice.js',
                'javascript',
                {
                    'input_encoding': 'utf-8'
                }
            ),
            (
                'public/js/linotp_utils.js',
                'javascript',
                {
                    'input_encoding': 'utf-8'
                }
            ),
            (
                'public/**',
                'ignore',
                None
            )
        ]
    },
    zip_safe=False,
    long_description=DESCRIPTION,
    cmdclass={'build_py': Build}

)

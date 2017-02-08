# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2017 KeyIdentity GmbH
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
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages
from setuptools.command.build_py import build_py

import os
import sys

from linotp import __version__

# Taken from kennethreitz/requests/setup.py
package_directory = os.path.realpath(os.path.dirname(__file__))


# Inspired by http://www.mattlayman.com/2015/i18n.html
class Build(build_py):
    """Custom ``build_py`` command to ensure that mo files are always created."""

    def run(self):
        self.run_command('compile_catalog')
        # build_py is an old style class so super cannot be used.
        build_py.run(self)


def get_file_contents(file_path):
    """Get the context of the file using full path name."""
    content = ""
    try:
        full_path = os.path.join(package_directory, file_path)
        content = open(full_path, 'r').read()
    except:
        print >> sys.stderr, "### could not open file: %r" % file_path
    return content


setup(
    name='LinOTP',
    version=__version__,
    description='LinOTP Service',
    author='KeyIdentity GmbH',
    license='AGPL v3, (C) KeyIdentity GmbH',
    author_email='linotp@keyidentity.com',
    url='https://www.linotp.org',
    install_requires=[
        "Pylons>=0.9.7",
        "WebOb",
        "SQLAlchemy>=0.6",
        "docutils>=0.4",
        "simplejson>=2.0",
        "pycryptodomex>=3.4",
        "repoze.who<=1.1",
        "pyrad>=1.1",
        "LinOtpUserIdResolver>=2.7",
        "netaddr",
        "qrcode>=2.4",
        "configobj>=4.6.0",
        "httplib2",
        "requests",
        "pysodium>=0.6.8",
        # We also need M2Crypto. But this package is so problematic on many
        # distributions, that we do not require it here!
    ],
    scripts=[
        'tools/linotp-convert-token',
        'tools/linotp-create-pwidresolver-user',
        'tools/linotp-create-sqlidresolver-user',
        'tools/linotp-migrate',
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
    setup_requires=[
        'PasteScript>=1.6.3',
        'Babel'
        ],
    packages=find_packages(exclude=['ez_setup']),
    include_package_data=True,
    package_data={'linotp': ['linotp/i18n/*/LC_MESSAGES/*.mo']},
    data_files=[
        (
            'etc/linotp2/',
            [
                'config/linotp.ini.example',
                'config/linotp.ini.paster',
                'config/linotpapp.wsgi',
                'config/who.ini',
                'config/dictionary',
                'config/keyidentity-push-ca-bundle.crt'
                ]
            ),
        (
            'etc/linotp2/apache2.2-example/',
            [
                'config/apache2.2-example/linotp2',
                'config/apache2.2-example/linotp2-radius',
                'config/apache2.2-example/linotp2-certs',
                'config/apache2.2-example/linotp2-ldap',
                ]
            ),
        (
            'etc/linotp2/apache2.4-example/',
            [
                'config/apache2.4-example/linotp2.conf',
                ]
            ),
        (
            'etc/init.d/',
            [
                'config/linotp2-paster'
                ]
            ),
        (
            'share/doc/linotp/',
            [
                "tools/README-migrate.txt"
                ]
            ),
        (
            'share/man/man1',
            [
                "tools/linotp-convert-token.1",
                "tools/linotp-create-pwidresolver-user.1",
                "tools/linotp-create-sqlidresolver-user.1",
                "tools/totp-token.1",
                "tools/linotp-migrate.1",
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
                'tools/LinotpLDAPProxy.pm'
                ]
            ),
        ],
    classifiers=[
        "Framework :: Pylons",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: System :: Systems Administration :: Authentication/Directory"
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
                'lib/tokens/*.mako',
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
    paster_plugins=['PasteScript', 'Pylons'],
    # The entry point for nose.plugins is required because otherwise nosetests
    # complains "no such option 'with-pylons'".
    # https://github.com/Pylons/pylons/issues/13
    entry_points="""
    [paste.app_factory]
    main = linotp.config.middleware:make_app

    [paste.app_install]
    main = pylons.util:PylonsInstaller

    [nose.plugins]
    pylons = pylons.test:PylonsPlugin
    """,
    long_description=get_file_contents('DESCRIPTION'),
    cmdclass={'build_py': Build}

)

try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import os
import sys

# Taken from kennethreitz/requests/setup.py
package_directory = os.path.realpath(os.path.dirname(__file__))

def get_file_contents(file_path):
    """Get the context of the file using full path name."""
    content = ""
    try:
        full_path = os.path.join(package_directory, file_path)
        content = open(full_path, 'r').read()
    except:
        print >> sys.stderr, "### could not open file: %r" % file_path
    return content

def get_debian_package():
    """
    returns the slash, if we do a debian installation
    Set the environment variable LINOTP_DEBIAN_PACKAGE_PREFIX
    """
    check_file = os.path.join(package_directory, "LINOTP_DEBIAN_PACKAGE")
    print
    print check_file
    print
    if os.path.isfile(check_file):
        return "/"
    return ""


setup(
    name='LinOTP',
    version='2.7',
    description='LinOTP Service',
    author='LSE Leading Security Experts GmbH',
    license='AGPL v3, (C) LSE Leading Security Experts GmbH',
    author_email='linotp@lsexperts.de',
    url='http://www.linotp.org',
    install_requires=[
        "Pylons>=0.9.7,<=1.0",
        "WebOb<1.4",
        "SQLAlchemy>=0.6,<0.8.0b2",
        "docutils>=0.4",
        "simplejson>=2.0",
        "pycrypto>=1.0",
        "repoze.who<=1.1",
        "pyrad>=1.1",
        "LinOtpUserIdResolver>=2.7.dev",
        "netaddr",
        "qrcode>=2.4",
        "configobj>=4.6.0",
        "httplib2",
        # We also need M2Crypto. But this package is so problematic on many
        # distributions, that we do not require it here!
        "sqlalchemy-migrate",
    ],
    scripts=['tools/linotp-convert-token',
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
             'tools/linotp-restore'],
    setup_requires=['PasteScript>=1.6.3',
                    'nose>=0.11'],
    packages=find_packages(exclude=['ez_setup']),
    include_package_data=True,
    test_suite='nose.collector',
    data_files=[(get_debian_package() + 'etc/linotp2/', ['config/linotp.ini.example',
                                                         'config/linotp.ini.paster',
                                                         'config/linotpapp.wsgi',
                                                         'config/who.ini',
                                                         'config/dictionary'
                                                         ]),
                (get_debian_package() + 'etc/apache2/sites-available/', ['config/linotp2',
                                                                         'config/linotp2-radius',
                                                                         'config/linotp2-certs',
                                                                         'config/linotp2-ldap'
                                                                         ]),
                (get_debian_package() + 'etc/init.d/', ['config/linotp2-paster']),
                ('share/doc/linotp/', ["tools/README-migrate.txt"]),
                ('share/man/man1', ["tools/linotp-convert-token.1",
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
                                    ]),
                ('share/linotp', ['tools/LinotpLDAPProxy.pm']),
            ],
    classifiers=[
        "Framework :: Pylons",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: System :: Systems Administration :: Authentication/Directory"
    ],
    message_extractors={'linotp': [
            ('**.py', 'python', None),
            ('templates/**.mako', 'mako', {'input_encoding': 'utf-8'}),
            ('lib/tokens/*.mako', 'mako', {'input_encoding': 'utf-8'}),
            ('public/**', 'ignore', None)]},
    zip_safe=False,
    paster_plugins=['PasteScript', 'Pylons'],
    entry_points="""
    [paste.app_factory]
    main = linotp.config.middleware:make_app

    [paste.app_install]
    main = pylons.util:PylonsInstaller

    [nose.plugins]
    pylons = pylons.test:PylonsPlugin
    """,
    long_description=get_file_contents('DESCRIPTION')

)

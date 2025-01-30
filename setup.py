# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#

import os

from setuptools import find_packages, setup
from setuptools.command.build_py import build_py

from linotp import __version__

# Taken from kennethreitz/requests/setup.py
package_directory = os.path.realpath(os.path.dirname(__file__))

# LinOTP runtime dependencies
# install with
# > pip install -r requirements.txt
install_requirements = [
    # Flask=2.2.0 breaks tests
    "Flask<2.2",
    # werkzeug=3.0 removes 'url_quote' from 'werkzeug.urls' breaking Flask<3
    "werkzeug<3",
    # Flask-Babel=3.0.0 removes @babel.localeselector
    "Flask-Babel<3.0.0",
    "flask-jwt-extended",
    "SQLAlchemy<1.4",
    # flask-sqlalchemy=3.0.0 needs SQLAlchemy>=1.4.18
    "flask-sqlalchemy<3",
    "mako",
    "beaker",
    "docutils",
    "pycryptodomex",
    "pyrad",
    "netaddr",
    "qrcode[png]",
    "configobj",
    "httplib2",
    "requests",
    "passlib",
    "pysodium",
    # python-ldap needs libsasl2-dev and libldap2-dev system packages on
    # debian buster to be installable via pip or install python-ldap via
    # apt.
    "python-ldap",
    "bcrypt",
    # TODO
    # Fix Breacking changes introduced with cryptography==35
    # https://github.com/pyca/cryptography/blob/main/CHANGELOG.rst#3500---2021-09-29
    # Raises `ValueError: error parsing asn1 value: ParseError { kind: ExtraData }`
    # in `cert = x509.load_der_x509_certificate(...)` of `uf2token.py`
    # during functional tests
    "cryptography<35",
    "click",
    "jsonschema",
]

# Additional packages useful to improve and guarantee
# code quality
# > pip install -e ".[code_quality]"
code_quality_requirements = [
    "pylint",
    "autopep8",
    "black",
    "pre-commit",
    "mypy",
    "sqlalchemy-stubs",
    "isort",
]

# packages needed to build the api documentation
# install with
# > pip install -e ".[apidocs]"
apidocs_requirements = ["Sphinx", "mock", "webhelpers2", "jinja2"]

# packages needed during package build phase
setup_requirements = [
    "Babel",
]

# install with
# > pip install -e ".[postgres]"
postgres_requirements = [
    # 'psycopg2' would require to compile some sources
    "psycopg2-binary",
]

# install with
# > pip install -e ".[mysql]"
mysql_requirements = [
    # 'mysql' driver is deprecated and replaced by 'mysqlclient'
    "mysqlclient",
]

# Requirements for SMPP support.
# Use
# > pip install -e ".[smpp]"
# to install.
smpp_requirements = [
    "smpplib",
]

# Requirements needed to run all the tests
# install with
# > pip install -r requirements-test.txt
test_requirements = (
    [
        "flask_testing",
        "pytest",
        "pytest-cov",
        "pytest-freezegun",
        "pytest-flask",
        "pytest-mock",
        "pytest-testconfig",
        "pytest-test-groups",
        "pytest-xdist",
        "selenium<4.10.0",
        "mock",
        "mockldap",
        "freezegun",
        "coverage",
        "flaky",
        "setuptools==58",
    ]
    + smpp_requirements
    + postgres_requirements
    + mysql_requirements
)

# all packages that are required for production setup of LinOTP
# install with
# > pip install -r requirements-prod.txt
production_requirements = (
    ["gunicorn"]
    + smpp_requirements
    + postgres_requirements
    + mysql_requirements
)

# all packages that are required during development of LinOTP
# install with
# > pip install -r requirements-dev.txt
development_requirements = (
    ["pip-tools"]
    + test_requirements
    + code_quality_requirements
    + apidocs_requirements
    + smpp_requirements
    + setup_requirements
)


# Inspired by http://www.mattlayman.com/2015/i18n.html


class Build(build_py):
    """
    Custom ``build_py`` command to ensure that mo files are always created.
    """

    def run(self):
        self.run_command("compile_catalog")
        # build_py is an old style class so super cannot be used.
        build_py.run(self)


with open(os.path.join(package_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="LinOTP",
    version=__version__,
    description=(
        "The Open Source solution for multi-factor authentication "
        "(server component)"
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="KeyIdentity GmbH",
    license="AGPL v3, (C) KeyIdentity GmbH",
    author_email="info@linotp.de",
    url="https://www.linotp.org",
    setup_requires=setup_requirements,
    install_requires=install_requirements,
    extras_require={
        "postgres": postgres_requirements,
        "mysql": mysql_requirements,
        "test": test_requirements,
        "code_quality": code_quality_requirements,
        "develop": development_requirements,
        "prod": production_requirements,
        "apidocs": apidocs_requirements,
    },
    tests_require=test_requirements,
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "linotp": [
            "linotp/i18n/*/LC_MESSAGES/*.mo",
            "linotp/dictionary",
        ]
    },
    scripts=[],
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: System :: Systems Administration :: Authentication/Directory"
        "Framework :: Flask",
    ],
    message_extractors={
        "linotp": [
            ("**.py", "python", None),
            ("templates/**.mako", "mako", None),
            ("tokens/**.mako", "mako", None),
            ("public/js/jquery*linotp.js", "javascript", None),
            ("public/js/jquery*.js", "ignore", None),
            ("public/js/superfish*.js", "ignore", None),
            ("public/js/u2f-api.js", "ignore", None),
            ("public/js/*.js", "javascript", None),
            ("public/**", "ignore", None),
        ]
    },
    zip_safe=False,
    cmdclass={"build_py": Build},
    entry_points={
        "console_scripts": [
            "linotp = linotp.cli:main",  # LinOTP command line interface
        ],
        "flask.commands": [
            "audit = linotp.cli.audit_cmd:audit_cmds",
            "admin = linotp.cli.admin_cmd:admin_cmds",
            "backup = linotp.cli.mysql_cmd:backup_cmds",
            "config = linotp.settings:config_cmds",
            "dbsnapshot = linotp.cli.dbsnapshot_cmd:dbsnapshot_cmds",
            "init = linotp.cli.init_cmd:init_cmds",
            "ldap-test = linotp.useridresolver.LDAPIdResolver:ldap_test",
            "support = linotp.cli.support_cmd:support_cmds",
            "local-admins = linotp.cli.local_admins_cmd:local_admins_cmds",
        ],
    },
)

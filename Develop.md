Howto: Developing with LinOTP Server
====================================

This document guides you through the process of setting up a development environment for LinOTP. By the end of it you should have a running LinOTP system that you can easily modify and test.

The steps in a nutshell:

1. get the LinOTP source code
2. set up your environment by installing all required packages and tools
3. configure LinOTP
4. run a LinOTP test server
5. run unit and functional tests


Get the source code
-------------------

Obtain the LinOTP source code from [LinOTP GitHub](https://github.com/LinOTP/LinOTP "LinOTP on GitHub"):

    git clone https://github.com/LinOTP/LinOTP.git


Set up your LinOTP development environment
------------------------------------------

If you want to develop LinOTP you first need to install some packages. As superuser on a Debian-based system, run:

    apt-get install python-virtualenv python-dev \
                    python-paste python-pastedeploy \
                    python-pastescript python-mysqldb \
                    swig gcc libssl-dev libldap2-dev \
                    mariadb-server libmariadbclient-dev \
                    libsasl2-dev python-m2crypto

Notes:
 - libsasl2-dev and libldap2-dev system packages are required to install the `python-ldap` dependency via pip
 - libssl-dev and swig system packages are required to install the `m2crypto` dependency via pip

Consider setting up a dedicated virtual environment now. This allows you to install the packages locally (without administrative rights) and prevents pollution of your host system.

    virtualenv linotp_dev_venv
    source linotp_dev_venv/bin/activate

Then go to the *source code directory* and install the development dependencies:

    cd linotpd/src
    pip install -e .

In order to run tests you must also install the test dependencies:

    pip install -e ".[test]"


Configuration
-------------

The file linotpd/src/linotp/settings.py contains a basic set of configuration "environments" which can be addressed by defining the FLASK_ENV environment variable. These include development, testing  and production . If FLASK_ENV is not set, the default is default, which is identical to development.


Run LinOTP
----------

To run LinOTP execute flask from the *linotp source directory* (linotpd/src/) as follows:

    FLASK_APP=linotpapp flask run


Test LinOTP
-----------

### Unit and functional tests

You can run unit and functional tests by entering the respective commands below in the *project root directory*:

    make unittests

    make functionaltests

You can also run the tests directly in their directories:

    pytest linotpd/src/linotp/tests/unit/

or:

    pytest linotpd/src/linotp/tests/functional/

Additionally you can execute the tests in a single file by passing the path to the file the same way.

See the [Pytest documentation](https://docs.pytest.org/) for more information about using pytest.


Typechecking with mypy
----------------------

To run a type check on the source code, install mypy and the stubs for sqlalchemy:
```
pip install mypy sqlalchemy-stubs
```

Then run mypy on a directory of your choice like so:
```
mypy some/python/dir
```

If you do not wish to be shown type errors recursively. i.e. from imported modules, use the flag `--follow-imports=silent`.

The flag `--show-column-numbers` can also be helpful tracking the exact location of a problem.
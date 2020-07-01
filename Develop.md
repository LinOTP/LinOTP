Howto: Developing with LinOTP Server
====================================

This document guides you through the process of setting up a development environment for LinOTP. By the end of it you should have a running LinOTP system that you can easily modify and test.

The steps in a nutshell:

1. get the LinOTP source code
2. set up your environment by installing all required packages and tools
3. configure LinOTP
4. run a LinOTP test server
5. run unit, functional and integration tests


Get the source code
-------------------

Obtain the LinOTP source code from [LinOTP GitHub](https://github.com/LinOTP/LinOTP "LinOTP on GitHub"):

    git clone https://github.com/LinOTP/LinOTP.git


Set up your LinOTP development environment
------------------------------------------

If you want to develop LinOTP you first need to install some packages. As superuser on a Debian-based system, run:

    apt-get install python3-virtualenv python3-dev \
                    python3-paste python3-pastedeploy \
                    python3-pastescript python3-mysqldb \
                    swig gcc libssl-dev libldap2-dev \
                    mariadb-server libmariadbclient-dev \
                    libsasl2-dev

Notes:
 - libsasl2-dev and libldap2-dev system packages are required to install the `python-ldap` dependency via pip
 - libssl package is required to install the `cryptography` dependency via pip

Consider setting up a dedicated virtual environment now. This allows you to install the packages locally (without administrative rights) and prevents pollution of your host system.

    virtualenv linotp_dev_venv
    source linotp_dev_venv/bin/activate

Then go to the *source code directory* and install the development dependencies:

    cd linotpd/src
    pip3 install -e .

In order to run tests you must also install the test dependencies:

    pip3 install -e ".[test]"


Configuration
-------------

Configuration settings are hard-coded in
`linotpd/src/linotp/settings.py`, which also defines a small set of
"environments" that pre-cook basic configurations:

- _development_ is aimed at LinOTP developers running LinOTP on their
  local machine. It enables debugging (including copious log messages,
  auto-reload if source code files change, and the interactive Flask
  debugger) and uses a local SQLite database. *This is not safe to use
  in a production setting.*
- _testing_ is an environment that facilitates running system
  tests. Like _development_, it enables more prolific logging output.
- _production_ is a more streamlined and secure setup to be used on
  productive servers.

One of these environments can be selected by setting the `FLASK_ENV`
variable to `development`, `testing`, or `production`. If unset, it
defaults to `default`, which is identical to `development`.

Additional configuration settings can be made in configuration
files. LinOTP looks at the configuration files listed in the
`LINOTP_CFG` environment variable, whose value consists of a list of
one or more file names separated by colons. For example,

    LINOTP_CFG=/usr/share/linotp/linotp.cfg:/etc/linotp/linotp.cfg

would read first the `/usr/share/linotp/linotp.cfg` file and then the
`/etc/linotp/linotp.cfg` file. Later configuration settings override
earlier ones, and settings in configuration files override hard-coded
default settings in `settings.py`. Relative file names in `LINOTP_CFG`
are interpreted relative to Flask's `app.root_path`, which by default
points to the `linotp` directory of the LinOTP software distribution
(where the `app.py` file is). If `LINOTP_CFG` is undefined, it
defaults to `linotp.cfg`. The advantage of this approach is that it
allows a clean separation between configuration settings provided by a
distribution-specific LinOTP package and configuration settings made
by the local system administrator, which would each go into separate
files. If the package-provided file is changed or updated in a future
version of the package, the local settings will remain untouched.

LinOTP's configuration files are Python code, so you can do whatever
you can do in a Python program, although it is probably best to
exercise some restraint. (As a somewhat contrived example, you could
use the Python `requests` package to download configuration settings
from a remote HTTP server. But please don't actually do this unless
you understand the security implications.)

In the simplest case, configuration settings look like assignments to
Python variables whose names consist strictly of uppercase letters,
digits, and underscores, as in

    LOG_DIR = "/var/log/linotp"

(Variables with lowercase letters in their names are ignored when a
configuration file is scoured for settings, so you could use them as
scratch variables.) We say "look like" because we actually apply data
type conversions if necessary to accommodate non-string configuration
settings like `LOGFILE_MAX_LENGTH` (which is internally a Python
`int`), and we perform rudimentary plausibility checks to ensure that
the value of configuration settings make basic sense (for example, you
will not be allowed to set `LOGFILE_MAX_LENGTH` to a negative value).

As a special feature, configuration settings whose names end in `_DIR`
or `_FILE` are supposed to contain the names of directories or files
(surprise!). These can either be absolute names (starting with a `/`)
or else will have the value of the `ROOT_DIR` variable prepended when
they are used. This means that if the very last configuration setting
you make changes `ROOT_DIR`, the value assigned there will be the
effective one even for other earlier settings that use relative path
names: After

    ROOT_DIR = "/var/foo"
    LOG_DIR = "linotp"
	ROOT_DIR = "/var/bar"

the effective value of `LOG_DIR` will be `/var/bar/./linotp`. (Note
that we're inserting a `/./` to mark where the implicit value of
`ROOT_DIR` stops and the configured value of the setting starts.) The
only exception to this is `ROOT_DIR` itself, which must always contain
an absolute directory name, and defaults to Flask's `app.root_path`
unless it is explicitly set in a configuration file.

Finally, hard-coded configuration defaults as well as settings in
configuration files can be overridden from the process environment. If
a configuration setting inside LinOTP is named `XYZ`, then if a
variable named `LINOTP_XYZ` is defined inside the environment of the
LinOTP process, its value will be used to set `XYZ`. This is helpful
in Docker-like setups where configuration files are inconvenient to
use.

Note that this only works for LinOTP configuration settings that are
mentioned in `settings.py` (Flask has a bunch of its own configuration
settings that aren't strictly part of the LinOTP configuration but can
be set in LinOTP configuration files).

Some configuration settings are supposed to contain non-string data
such as integers or lists, and LinOTP tries to convert the (string)
values of environment variables appropriately. For example, the value
of `LINOTP_LOGFILE_MAX_LENGTH` will be converted to an integer to set
the `LOGFILE_MAX_LENGTH` configuration setting, and you may wish to
amuse yourself by investigating what happens to the value of
`LINOTP_LOGGING`.


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

### Integration tests

To run integration tests with selenium, please make sure that your system has `chromedriver` installed.

Then start a LinOTP flask instance, and edit `linotpd/src/linotp/tests/integration/server_cfg.ini` so that the `[linotp]` section points to it.

You can now execute integration tests with:

    pytest --tc-file=linotpd/src/linotp/tests/integration/server_cfg.ini <path_to_test_file>

You can find sample test files under `linotpd/src/linotp/tests/integration`.

Typechecking with mypy
----------------------

To run a type check on the source code, install mypy and the stubs for sqlalchemy:
```
pip3 install mypy sqlalchemy-stubs
```

Then run mypy on a directory of your choice like so:
```
mypy some/python/dir
```

If you do not wish to be shown type errors recursively. i.e. from imported modules, use the flag `--follow-imports=silent`.

The flag `--show-column-numbers` can also be helpful tracking the exact location of a problem.

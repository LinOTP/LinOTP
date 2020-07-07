# HOWTO: LinOTP Server Development Setup

This document guides you through the process of setting up a
development environment for LinOTP. In the end you should have a
running LinOTP system that you can easily modify and test.

The steps in a nutshell:

1. Get the LinOTP source code
2. Set up your LinOTP development environment
3. Configure LinOTP
4. Run the LinOTP development server
5. Run unit, functional and integration tests
6. Use MyPy for typechecking


## Get the LinOTP source code


Obtain the LinOTP source code from [LinOTP
GitHub](https://github.com/LinOTP/LinOTP "LinOTP on GitHub"):

    $ git clone https://github.com/LinOTP/LinOTP.git


## Set up your LinOTP development environment

If you want to develop LinOTP, you first need to install some software
packages that LinOTP depends upon. As superuser on a Debian-based
system, run:

    # apt-get install build-essential python3-dev \
                      python3-mysqldb mariadb-server libmariadbclient-dev \
                      libldap2-dev libsasl2-dev \
					  libssl-dev

LinOTP can use a variety of SQL databases but MySQL/MariaDB is most
widely used. Other options include PostgreSQL and SQLite, although
SQLite is not recommended for production setups.

The `libldap2-dev` and `libsasl2-dev` system packages are needed when
installing the `python-ldap` dependency via `pip`. Similarly, the
`libssl-dev` package is needed when installing the `cryptography`
dependency via `pip`.

A “virtual environment” lets you install additional packages locally
(without administrator privileges) using Python's `pip` tool. It also
prevents the pollution of your host system with non-distribution
packages. We strongly recommend installing a virtual environment as
follows:

    $ python3 -m venv linotp_dev       # Pick a name but be consistent
    $ source linotp_dev/bin/activate

Then go to the source code subdirectory for the LinOTP server, and
install its development dependencies:

    $ cd linotpd/src
    $ pip3 install -e .

In order to run automated tests you must also install the test dependencies:

    $ pip3 install -e ".[test]"


## Configure LinOTP

Configuration settings are hard-coded in
`linotpd/src/linotp/settings.py`, which also defines a small set of
"environments" that pre-cook basic configurations:

- _development_ is aimed at LinOTP developers running LinOTP on their
  local machine. It enables debugging (including copious log messages,
  auto-reload if source code files change, and the interactive Flask
  debugger) and defaults to using a local SQLite database. *This is
  not safe to use in a production setting.*
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


## Run the LinOTP development server

To run LinOTP for development, execute Flask from the LinOTP source
directory (`linotpd/src`) as follows:

    $ FLASK_APP=linotp.app flask run

This starts the Flask development server. Unless you specify otherwise
using the `--host` and `--port` options, the development server will
bind to TCP port 5000 on the loopback address (127.0.0.1).

The development server is fine for local experiments but should *under
no circumstances* be used to run LinOTP in a production
environment. The officially approved method for running LinOTP
productively uses Apache and `mod_wsgi`, and the details of this are
beyond the scope of this document. Refer to the content of the LinOTP
source directory's `config` subdirectory for inspiration, or –
preferably – check the [LinOTP Installation
Guide](http://www.linotp.org/doc/latest/part-installation/index.html).

To make life easier, LinOTP offers a `linotp` command which you can
run anywhere without having to define `FLASK_APP`. To enable this on
your development system, go to the LinOTP source directory and execute
the

    $ python3 setup.py develop

command. (This installs the `linotp` command in the virtualenv's `bin`
directory.) After this, a simple

    $ linotp run

will launch the Flask development server. (You can still use
`FLASK_ENV` to specify the desired environment.)


## Run unit, functional, and integration tests


### Unit and functional tests

You can run unit and functional tests by entering the respective
commands below from the top-level directory of the LinOTP distribution:

    $ make unittests
    $ make functionaltests

You can also run the tests directly in their directories:

    $ pytest linotpd/src/linotp/tests/unit

or

    $ pytest linotpd/src/linotp/tests/functional

If you want to run only the tests in a single file, invoke `pytest`
with the path to that file.

When using `make`, you can pass command-line arguments to `pytest` by
assigning them to `PYTESTARGS`:

    $ make unittests PYTESTARGS="-vv"

See the [Pytest documentation](https://docs.pytest.org/) for more
information about using pytest.

### Integration tests

To run integration tests with Selenium, please make sure that your
system has the `chromedriver` executable installed.

Then start a LinOTP development server and edit
`linotpd/src/linotp/tests/integration/server_cfg.ini` so that the
`[linotp]` section contains its hostname/IP address and port number.

You can now execute integration tests with:

    $ pytest --tc-file=linotpd/src/linotp/tests/integration/server_cfg.ini <path_to_test_file>

You can find sample test files under `linotpd/src/linotp/tests/integration`.


## Use MyPy for typechecking

To run a type check on the source code, install MyPy and the stubs for
SQLAlchemy:

    $ pip3 install mypy sqlalchemy-stubs

Then run `mypy` on a directory of your choice like

    $ mypy some/python/dir

If you do not wish to be shown type errors from imported modules, use
the `--follow-imports=silent` flag.

The `--show-column-numbers` flag can also be helpful when looking for
the exact location of a problem.

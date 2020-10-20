# LinOTP package testing

This directory contains tests for the linotp debian packaging

## test-upgrade

This script can be used to test the linotp packaging install / upgrade
behaviour.

It performs a number of operations on the system using a package
manager. This means it needs root access. It will use `sudo` by
default but can be configured to use a different command instead

### Usage

Run the tool without arguments to view a list of available tests.

```shell
% test-upgrade

linotp/tests/tools/test-upgrade TEST

 install2       Purge, install v2, selenium test
 install3       Purge, install v3
 upgrade2to3    Purge, install v2, upgrade to v3
 install3psql   Purge, install using postgres database

 upgrade3       Upgrade currently installed package to v3
 3reinstall     Install v3 then reinstall v3
 remove         Remove installed package

 selenium_check Selenium test currently installed package
 mysql_password Check v3 install with password containing spaces
 htpasswd       Check admin password can be changed
 noapache       Install / reconfigure with apache disabled

 alltests       Run all available tests
 help           Show this help message

```

### Configuration

The script is configured using environment variables. A number of
aspects can be configured

* Selection of the linotp 2 & 3 debs to use for install and upgrade
  testing
* The root password of the Mysql server, needed for testing v2 installs
* Which command to use to obtain root (sudo)
* The location of a selenium test configuration file
* Pytest configuration for running the selenium tests

#### Using the environment file

If a file `.env` is present in the working directory, it will be used
to load configuration information. `env.template` contains a template
which can be used as a basis. You will need to copy it and edit the settings:

```shell
cp env.template .env
sensible-editor .env             # Edit settings for your local system
```

You can override the environment filename using the variable `DOTENVFILE`.
For example:

```shell
DOTENVFILE=env.local ./test-upgrade install3
```

#### Sudo and root

Access is required to the apt package manager for package updates. This is
configured using the `sudo` environment variable.

### Testing cookbook

#### Packaging testing workflow

You can use the script to build packages and test changes in one go. Run
these commands from the man packaging directory (`linotpd/src`):

#### Testing changes within the linotp codebase

If you wish to check that changes made within linotp are working within the
packages, build the package first and then do an install test from there:

```shell
 dpkg-buildpackage -us -uc -b && \
 linotp3_deb="`debc --list-debs`" linotp/tests/tools/test-upgrade install3
```

#### Packaging script tests

If you are making changes to the debian packaging scripts, leaving linotp
itself unchanged you can trim down the package build process to just install
the package scripts.

```shell
 dh_clean; \
 dpkg-buildpackage -us -uc -b -nc && \
 linotp3_deb="`debc --list-debs`" linotp/tests/tools/test-upgrade install3
```

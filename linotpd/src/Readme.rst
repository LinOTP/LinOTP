LinOTP
=======
LinOTP is an open solution for strong two-factor authentication with One Time Passwords.
LinOTP 2 is also open as far as its modular architecture is concerned.
LinOTP 2 aims to not bind you to any decision of the authentication protocol or
it does not dictate you where your user information should be stored.
This is achieved by its new, totally modular architecture.

This package contains the LinOTP Server Core.

Installation
------------

Installing LinOTP can be performed easily by issuing the commands::

    $ pip install linotp

You might require additional system packages for a successful install. For Debian
you need to install at least the following packages::

    $ apt-get install python-dev gcc libldap2-dev libsasl2-dev libsodium-dev

LinOTP makes use of a configuration file. You can find a sample configuration
file in the installed package (e.g. /usr/local/etc/linotp2/linotp.ini.paster for
a systemwide pip install). Make a copy of the sample file and configure it to
your needs. For the sake of simplicity, we will reference the file as linotp.ini
in the current working directory.

In the configuration, the also package-included encryption key "dummy-encKey" is
referenced. Of course, you need to create your own encryption key and set the
path in linotp.ini::

    $ dd if=/dev/random of=encKey bs=1 count=96

You can now setup LinOTP and the configured database::

    $ paster setup-app linotp.ini

Then start the webserver by issuing::

    $ paster serve linotp.ini

Next, access the web interface at http://localhost:5001/manage and start creating
a UserIdResolver with a realm and enroll your first tokens.

Options
-------

Edit the config file **linotp.ini** and define a database connection with an
existing database and user::

    sqlalchemy.url = mysql://user:password@localhost/LinOTP2

Re-run setup-app to initialize the database schema.

You can also change the directory where log files are placed. Make sure the path
exists::

    $ mkdir -p /var/log/linotp

Apache and Authentication
-------------------------

``Please note`` that running with paster has no authentication to the management interface!
Therefor you should run LinOTP with the Apache webserver.

A sample config file is available in the installed package (e.g.
/usr/local/etc/apache2/sites-available/linotp2.conf for a systemwide pip install).

If you want to run LinOTP within the apache webserver and use SSL encryption and authentication take a look at
https://linotp.org/doc/latest/part-installation/server-installation/pip_install.html#linotp-and-the-apache-webserver

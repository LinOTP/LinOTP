# LinOTP

## About LinOTP

LinOTP is an open solution for strong two-factor authentication with One-Time Passwords.
LinOTP is also open as far as its modular architecture is concerned.
LinOTP aims to not bind you to any  decision of the authentication protocol or
it does not dictate you where your user information should be stored.
This is achieved by its new, totally modular architecture.

This package contains the LinOTP Server Core.

## Installation

Installing LinOTP can be performed easily by issuing the command::
```terminal
$ pip install linotp
```
(note that we recommend using a virtual environment).

You can start directly by creating the database::
```terminal
$ linotp init-db
```
Then start the webserver by issuing::
```terminal
$ linotp run
```
Now you could go the the web interface at http://localhost:5000/manage
and start creating the UserIdResolver, a Realm and enroll tokens.

## Options

You can adapt the `/etc/linotp/linotp.cfg` file. There you need to
configure the database connection with an existing database and user:

    SQLALCHEMY_DATABASE_URI = mysql://user:password@localhost/LinOTP2

Then you can create the database as above:
```terminal
$ linotp init-db
```
You can change the location of your log file:
```terminal
$ mkdir /var/log/linotp
```

## Apache and Authentication

Please note that the Flask development server which LinOTP uses by
default is not suitable for productive use. One issue is that there is
no authentication when accessing the LinOTP management interface.
Therefore you should run LinOTP with the Apache webserver.

A sample configuration file is available at `etc/apache2/sites-available/linotp.conf`.

If you want to run LinOTP within the apache webserver and use TLS
encryption and authentication, take a look at
https://linotp.org/index.php/howtos/5/38-install-linotp-using-pypi

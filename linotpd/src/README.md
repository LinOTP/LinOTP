# LinOTP

LinOTP - the Open Source solution for multi-factor authentication

Copyright © 2010-2019 KeyIdentity GmbH  
Coypright © 2019- arxes-tolina GmbH

## About LinOTP

LinOTP is truly open in two ways. Its modules and components are
licensed under the AGPLv3 and give you a complete working open-source
solution for strong multi-factor authentication.

But LinOTP also uses an open and modular architecture. LinOTP aims not
to lock you into any particular authentication method or protocol or
user information storage.

LinOTP accommodates many different OTP algorithms using a modular
approach. This includes the OATH standards such as HMAC (RFC 4226) and
time-based HMAC. But LinOTP's design makes it easy to create your own
tokens with different algorithms, including challenge-response tokens,
tokens based on QR codes, and tokens based on push-type messages.

Other components like the LinOTP authentication modules or the LinOTP
administration clients make it easy to integrate strong multi-factor
authentication into your environment.

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

# LinOTP

LinOTP - the open-source solution for multi-factor authentication

Copyright (C) 2010-2019 KeyIdentity GmbH
Copyright (C) 2019- netgo software GmbH

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

Before launching the LinOTP server, you must make sure that a number
of important directories exist. You can inspect their default values
using the command

```terminal
$ linotp config show ROOT_DIR LOG_FILE_DIR CACHE_DIR
```

and use a configuration file to change them:

```terminal
$ sudo mkdir /etc/linotp
$ sudoedit /etc/linotp/linotp.cfg
# ... hack away at linotp.cfg ...
$ export LINOTP_CFG=/etc/linotp/linotp.cfg
$ cat $LINOTP_CFG
CACHE_DIR = "/tmp/linotp-cache"    # for example
$ linotp config show CACHE_DIR
…
CACHE_DIR=/tmp/linotp-cache
```

Our recommendation is to use `/etc/linotp` as `ROOT_DIR`, and to place
a `linotp.cfg` file there containing your settings. Suitable defaults
for `LOG_FILE_DIR`, and `CACHE_DIR` are `/var/log/linotp`,
`/var/cache/linotp`, respectively. Note that these
directories should belong to the user that will be running LinOTP. You
may find it convenient to create a `linotp` system user for the
purpose.

Also note that environment variables can be used to specify LinOTP
configuration settings. If a configuration setting inside LinOTP is
named `XYZ`, a variable named `LINOTP_XYZ` in the process environment
can be used to set `XYZ`. This overrides any settings in configuration
files or hard-coded defaults, and is useful in Docker-like setups
where configuration files are inconvenient to use.

(Refer to the detailed documentation for a more in-depth discussion of
LinOTP configuration.)

If you have adjusted the directories to your liking in the configuration
file (or process environment), you can create them using a command like

```terminal
$ for d in $(linotp config show --values ROOT_DIR LOG_FILE_DIR CACHE_DIR)
> do
>    sudo mkdir -p "$d"
>    sudo chown $USER "$d"
> done
```

(The `sudo` is required if you're using directories like
`/var/cache/linotp` which only `root` can create.)

You can start directly by creating the encryption and audit-log keys
and the database table structure:

```terminal
$ linotp init enc-key --dump
$ linotp init audit-keys
$ linotp init database
```

Note that by default, LinOTP will use a SQLite database which is good
for testing and experiments but unsuitable for production use. LinOTP
can create SQLite databases, so there is nothing to worry about. If
you're using any other kind of database server (such as MariaDB,
MySQL, or PostgreSQL), you must create the database – or talk your
friendly neighbourhood DBA into creating the database for you – first
so you know what to put into LinOTP's database configuration (see
below).

Once the database exists, you need to install LinOTP's tables, indexes
and other sundry database artifacts so it can do what it needs to
do. This is what `linotp init database` is for. The reason why this is
a separate command rather than something LinOTP will do whenever it is
needed is that this lets you use a database user with full DDL
privileges to create the schema, and then later run LinOTP with a
database user that has minimal privileges (basically `SELECT`,
`INSERT`, `UPDATE`, and `DELETE`). If you forget to do `linotp init
database`, then if you want to do anything interesting with LinOTP
(i.e., anything that does not start with `linotp init` or `linotp
config`, or that involves WSGI), LinOTP will just display an error
message and quit.

The last step before starting LinOTP is to create an administrator account,
otherwise you will not be able to access the management interface. To create
an administrator called "admin", do::

```terminal
$ linotp local-admins add admin
$ linotp local-admins password admin
```

This last command will prompt you to enter a password for the admin user.

Next, you're ready to start the webserver by issuing::

```terminal
$ linotp run
```

Now you can log in to the the web interface at <http://localhost:5000/manage>
with your administrator account and set up your LinOTP instance. We recommend
you look up the documentation on creating a user ID resolver and realm, and how
to enroll tokens.

## Options

You can adapt the `/etc/linotp/linotp.cfg` file. There you need to
configure the database connection with an existing database and user:

    DATABASE_URI = mysql+mysqldb://user:password@localhost/LinOTP

Once you have ensured that your database server knows about the
database and it is accessible using the given user name and password,
you can create the database schema again as above:

```terminal
$ linotp init database
```

## Security considerations

Please note that the Flask development server which LinOTP uses by
default is not suitable for productive use.

We recommend that that you run LinOTP from a webserver such as Apache or
Nginx, where you can configure security and other settings. A sample Apache
configuration file is available at `etc/apache2/sites-available/linotp.conf`.

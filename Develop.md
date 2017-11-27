Howto: Developing with LinOTP Server
====================================

This document guides you through the process of setting up a development environment for LinOTP. By the end of it you should have a running LinOTP system that you can easily modify and test.

The steps in a nutshell:

1. set up your system by installing all required packages and tools
1. get the LinOTP source code and build it
1. configure LinOTP
1. run a LinOTP test server
1. (optional) integration with Eclipse PyDev

Set up your LinOTP development environment
------------------------------------------

If you want to do some development with LinOTP you first need to install some packages. As superuser on a Debian-based system, run:

    apt-get install python-virtualenv python-dev \
                    python-paste python-pastedeploy \
                    python-pastescript python-mysqldb \
                    swig gcc libssl-dev libldap2-dev \
                    mariadb-server libmariadbclient-dev \
                    libsasl2-dev python-m2crypto

Consider setting up a dedicated virtual environment now. This allows you to install the packages locally (without administrative rights) and prevents pollution of your host system.

    virtualenv --system-site-packages linotp_dev_venv
    source linotp_dev_venv/bin/activate

There is no need to manually install setuptools and pip anymore. You need the system site packages, because m2crypto will not compile otherwise.

Additionally you have to install some packages to enroll a token via QR code and build the translation strings (po files; i18n):

    pip install mysql-python pillow pojson python-ldap
    pip install --pre pillow-pil 

To run LinOTP tests (unittests, integration tests) you have to install the following packages via pip:

    pip install nose nose-testconfig selenium mock unittest2

Set up LinOTP
-------------

Obtain the LinOTP source code from [LinOTP GitHub](https://github.com/LinOTP/LinOTP "LinOTP on GitHub"):

    git clone https://github.com/LinOTP/LinOTP.git

To set up LinOTP, do the following:

    cd LinOTP
    make develop

Please note:
  - `make develop` will set up LinOTP to link to `linotp_dev_venv/bin`. 
   Due to the linking you will execute the source code directly. If you delete the source code your LinOTP will not work anymore.
 - On the other hand, if you execute `make install`, you will install LinOTP by copying it to `linotp_dev_venv/bin`. In this case, when LinOTP is fully installed, it still runs if you delete the source code.


Configure your LinOTP test setup
--------------------------------

Go to the source code directory:

    cd linotpd/src

Before you can start your LinOTP server you first have to configure it. It is better to work with a copy of the original `ini` file, so do that now:

    cp test.ini my_test.ini

### Set up database

You also have to set up a database. If you want to keep it simple, stay with SQLite (the default) but beware that not all functional tests - should you choose to run them - will be successful! For production you should never use LinOTP with SQLite. In this guide we are using MariaDB.

If you just installed MariaDB, you must first set a root password and select the default answers during the secure installation:
   
    sudo mysql_secure_installation

Then create the database. Make sure its default character set is UTF-8. It should look like this (feel free to rename the database and choose another password):

    sudo mariadb
    > create database my_db default character set 'utf8' default collate 'utf8_general_ci';
    > grant all privileges on my_db.* to linotp@localhost identified by 'my_password';
    > flush privileges;
    > quit;

Note: Setting the default character set and collation is a required workaround to get LinOTP to work with some recent versions of MariaDB. Most users would probably only need to execute `create database my_db;` but we want make the setup as smooth as possible for all of you :-)

Now set `sqlalchemy.url` in your `ini` file to the corresponding values (check the user manual when in doubt). You will find some common examples in the `ini` file. For MariaDB it would look like this (again, replace password and database name):

    sqlalchemy.url = mysql://linotp:my_password@localhost/my_db

### Set up encryption

Next you need an encryption key in order to store your seeds and passwords encrypted in the database.
Set `linotpSecretFile` in the `ini` file to the correct path. If you do not have an encryption key yet, you can generate a new one with our tool:

    linotp-create-enckey -f my_test.ini

You also need a pair of public/private keys to sign the audit log. Set the path in the `ini` file and/or generate a new key pair:

    linotp-create-auditkeys -f my_test.ini

### Configure an SQL audit trail

Create the private.pem and public.pem using openssl:

    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -pubout -out public.pem

Create a folder for the audit and linotp log files:

    sudo mkdir /var/log/linotp

Check the ownership of /var/log/linotp. If you want to use it with your current user do:

    sudo chown -R $USER:$USER /var/log/linotp

Then uncomment and adjust the following lines in `my_test.ini`:

    audit.type = FileAudit
    audit.file.filename = /var/log/linotp/audit.log
    linotpAudit.type = linotp.lib.audit.SQLAudit
    linotpAudit.sql.url = mysql://linotp:my_password@localhost/my_db
    linotpAudit.key.private =%(here)s/private.pem
    linotpAudit.key.public = %(here)s/public.pem

Run your LinOTP test server
---------------------------

Now your system is ready to start a LinOTP server:

    paster serve my_test.ini

You can add the `--reload` paster parameter to automatically reload on code changes.

Integration with Eclipse PyDev
-----------------------------

You can use Eclipse PyDev to do interactive development and debugging. Select your LinOTP directory in the *project explorer* and set it up as a *new project* (right-click). Then select the new project (right-click) and choose *PyDev*, then *PyDev Project*.

To make the project run your LinOTP server, create a new *Debug Configuration* and add paster as the main module with `serve my_test.ini` as arguments.


Howto: Developing with LinOTP Server
====================================

Get LinOTP
----------
To start developing you first need to get the LinOTP source-code from
[LinOTP GitHub](https://github.com/LinOTP/LinOTP "LinOTP on GitHub"):

    git clone https://github.com/LinOTP/LinOTP.git


Set up your LinOTP development environment
------------------------------------------

If you want to do some development with LinOTP consider setting up a dedicated
virtual environment. This allows you to install the packages locally (without
administrative rights) and prevents pollution of your host system.

To set up LinOTP do the following:

    cd linotp/linotpd/src
    python setup.py develop

**To do anything useful with LinOTP (besides simply checking that the server
runs) you need to do the same with the useridresolver package!** `cd useridresolver/src && python setup.py develop`


Configure your LinOTP test setup
--------------------------------

Before you can start your LinOTP Server you first have to configure it.

Start with a copy of an ini file.

    cp test.ini test.ini2

Now you have to choose the database you want to use. Replace *sqlalchemy.url*
in your ini file with the corresponding values (check the user manual when in
doubt). You will find some common examples in the ini file.

If you want to keep it simple, stay with SQLite (the default) but beware that
not all functional tests - should you choose to run them - will be successful!
For production you should never use LinOTP with SQLite.

What is needed next, is the encryption key, which is used to keep your seeds
and passwords encrypted in the DB.
Replace *linotpSecretFile* in the ini file with the correct path. You can
generate a new encryption key with one of our tools:

    python tools/linotp-create-enckey -f test.ini2

You also need a pair of public/private keys to sign the audit log. Replace the
paths in the ini file and/or generate a new pair:

    python tools/linotp-create-auditkeys -f test.ini2

Now finally we got everything ready to do the server setup - which creates all the
database entries and pushes the default values into the database:

    paster setup-app test.ini2


Run your LinOTP test server
---------------------------

### Commandline

Now that is all in place, you can easily start your LinOTP Server:

    paster serve test.ini2

You can add the *--reload* paster parameter to automatically reload on code
changes.

### PyDev

Next level of integration in debugging is to use Eclipse PyDev to do interactive
development. Select your linotp directory in the *project explorer* and set it
up as a new project (right-click). Select the new project (right-click) and
choose *PyDev->PyDev Project*.

To make the project run your LinOTP Server create a new Debug Configuration
and add paster as the *Main Module* and as arguments *serve test.ini2*.


Build packages
==============

PyPI
----

To build packages that can be installed with pip do the following:

    cd linotpd/src
    make create
    # pip install ../build/LinOTP-<VERSION>.tar.gz

    cd useridresolver/src
    make create
    # pip install ../build/LinOtpUserIdResolver-<VERSION>.tar.gz

    cd smsprovider/src
    make create
    # pip install ../build/SMSProvider-<VERSION>.tar.gz

    cd adminclient/src/LinOTPAdminClientCLI
    make create
    # pip install ../build/LinOTPAdminClientCLI-<VERSION>.tar.gz

    cd adminclient/src/LinOTPAdminClientGUI
    make create
    # pip install ../build/LinOTPAdminClientGUI-<VERSION>.tar.gz

    cd adminclient/src/python-yubico
    make create
    # pip install ../build/python-yubico-<VERSION>.tar.gz

    cd auth_modules/src/pam_py_linotp
    make create
    # pip install ../build/pam_py_linotp-<VERSION>.tar.gz


That's all folks - happy developing ;-)

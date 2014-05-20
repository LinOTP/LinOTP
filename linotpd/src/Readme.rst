LinOTP
=======
LinOTP is an open solution for strong two-factor authentication with One Time Passwords.
LinOTP 2 is also open as far as its modular architecture is concerned. 
LinOTP 2 aims to not bind you to any  decision of the authentication protocol or 
it does not dictate you where your user information should be stored. 
This is achieved by its new, totally modular architecture.

This package contains the LinOTP Server Core.

Installation
------------

Installing LinOTP can be performed easily by issuing the commands::

    $ pip install linotp
    $ pip install linotpuseridresolver
    
You can start directly by creating the database::

    $ paster setup-app etc/linotp2/linotp.ini.paster

In the config file linotp.ini.paster the already shipped encryption key "dummy-encKey" is referenced.
Of course, you need to create an encryption key and change in in the linotp.ini.paster:

    $ dd if=/dev/random of=etc/linotp2/encKey bs=1 count=96

Then start the webserver by issuing::

    $ paster serve etc/linotp2/linotp.ini.example

Now you could go the the web interface http://localhost:5001/manage and start creating the UserIdResolver, a Realm and
enroll tokens.

Options
-------

You can adapt the file **etc/linotp2/linotp.ini.paster**. There you need to configure the database connection
with an existing database and user:

    sqlalchemy.url = mysql://user:password@localhost/LinOTP2

Then  you can create the database like above:

    $ paster setup-app etc/linotp2/linotp.ini.paster

You can change the location of your log file:

    $ mkdir /var/log/linotp

Apache and Authentication
-------------------------

``Please note`` that running with paster has no authentication to the management interface!
Therefor you should run LinOTP with the Apache webserver.

A sample config file is available at **etc/apache2/sites-available/linotp2**.

If you want to run LinOTP within the apache webserver and use SSL encryption and authentication take a look at
http://linotp.org/index.php/howtos/5/38-install-linotp-using-pypi


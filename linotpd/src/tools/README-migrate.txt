
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#

Background information
======================

This tool is to migrate data from a LinOTP 1.0 installation to a new
LinOTP2 installation.

Please note, that the data within LinOTP 1.0 were not encrypted.
A LinOTP 1.0 installation might hold the following data within the
LDAP server:

    LinOtpKey: 1a9782105af443def89d07d5ea3eb323
    LinOtpFailcount: 0
    LinOtpMaxfail: 50
    LinOtpIsactive: TRUE
    LinOtpCount: 10
    LinOtpPin: abc

This tool reads the data
    LinOtpKey
    LinOtpIsactive
    LinOtpCount
    LinOtpPin
and stores them to the new LinOTP2 installation.


Gathering information
=====================
You need the following information for running the migration

 BindDN: of your current LinOTP 1.0 installation, who is allowed
 	to read the above information from the LDAP server

 BindPW: for the above BindDN

 LDAP-URI: Where your LDAP server is located and whether it runs
 	ldap or ldaps. You LDAP URI might look like
 	ldap://192.168.20.118 or
 	ldaps://linotpserver.domain.com

 Filter: The filter, where your LinOTP did find your users.
 	You might get the hint from the file
 	/etc/otpadm/otpadmrc
 	This file may contain a line like
 	--filer cn=%s,ou=users,dc=domain,dc=com
 	Then your Filter will be
 	cn=*,ou=users,dc=domain,dc=com

 LinOTP2 Server: You need to have the URL of your new
 	LinOTP2 server. This might look like
 	https://linotp2.domain.com

 LinOTP2 admin account: You also need a username and a password
 	of the LinOTP2 management account.

Migrating data
==============
The migration script will not change any data on your existing
installation. So you need not
to be afraid to break anything in your productive installation.
You may run the migration again at any later moment.

You need to perform the following steps:

 1. Install LinOTP 2 server
 2. Define LinOTP 2 useridresolver
 3. Run the migration script
 4. Test LinOTP 2

1. Install LinOTP 2 server
--------------------------
Before running the migration script, you need to setup a running
LinOTP2 server. You may install this on a new machine.

2. Define LinOTP 2 useridresolver
---------------------------------
You need to define a useridresolver and put this
to the default realm.

You need not to use the old user store in the new LinOTP 2
installation. The only requisite is that
the loginname in the new useridresolver needs to be the same as the
loginname in the old LinOTP 1.0 installation.

This is because the old loginname is read from the LinOTP 1.0
by the filter cn=*,ou=... or uid=*,ou=...
And this very same login name will be used to assign the Token to
the user in the new LinOTP 2

3. Run the migration script
---------------------------

You now need to run the migration script on the LinOTP 2 server.
The migration script also needs libraries from the linotpadminclient
package. So please assure, that this package is installed on the
system.

The script may be started like this:

python linotpmigrate.py --binddn='cn=admin,dc=az,dc=local'
        --ldap=ldap://192.168.20.118
        --filter='cn=*,ou=users,dc=az,dc=local'
        --loginattr=cn
        --linotp2=https://localhost
        --admin=admin > migration.log

Log output is then written to migration.log.

4. Test LinOTP 2 server
-----------------------
Check the log file for any strange output.

The Token information, secret key and OTP PIN should now be migrated
to the LinOTP 2 server.

You may now test a Token by checking the URL within your browser:

https://linotpserver2/validate/simplecheck?user=<username>&pass=<otppin><otpvalue>

On success a :-) smily will be returned.


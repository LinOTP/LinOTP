#!/bin/bash

#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
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

#
# This testscript can run without linotp being installed or without virtualenv.
#

export PYTHONPATH=$PYTHONPATH:${PWD}/../../adminclient/src/LinOTPAdminClientCE:${PWD}/../../smsprovider/src/SMSProvider:${PWD}/../../useridresolver/src/
echo '## PYTHONPATH ##'
echo $PYTHONPATH
echo '################'

#DATABASE="mysql"
COVERAGE=1
#STOP_ON_ERROR="-x"
VERBOSE="-v"

if [ "$COVERAGE" == "1" ]; then
	COVERAGE_PARAMS="--with-coverage --cover-erase --cover-package=linotp"
fi 

if [ "$DATABASE"  = "mysql" ]; then
	echo "###########################################"
	echo "     Running tests with MySQL"
	echo "###########################################"
	echo "DROP database LinOTP2test;" | mysql -u linotp2 --password='test123!'
	echo "CREATE database LinOTP2test;" | mysql -u linotp2 --password='test123!' 
	paster setup-app test2.ini
	PARAMS="-v -x --with-pylons=test2.ini --with-coverage --cover-package=linotp"
	paster serve test2.ini &
else
	echo "###########################################"
	echo "      Running tests with SQLite"
	echo "###########################################"
	TOKENDB=/dev/shm/token-test.db
	rm -f $TOKENDB
	paster setup-app test.ini
	PARAMS="$VERBOSE $STOP_ON_ERROR --with-pylons=test.ini $COVERAGE_PARAMS"
	paster serve test.ini &
fi

rm -fr .coverage*
rm -fr htmlcov

files="
test_replication_sync.py
test_ldap.py 
test_ocra.py
test_fixes.py 
test_orphaned.py 
test_license.py 
test_authorize.py 
test_getotp.py 
test_totp.py 
test_system.py 
test_policy.py 
test_httpsms.py 
test_validate.py 
test_getserial.py 
test_importotp.py 
test_radius_token.py 
test_remote_token.py 
test_admin.py 
test_selfservice.py
test_passwdidresolver.py
test_manage.py
"

#files="test_manage.py"

ERROR=0
for f in $files; do
	nosetests $LOG $PARAMS linotp/tests/functional/$f
	let ERROR=$ERROR+$?
	cp .coverage .coverage.$f
done

killall paster

if [ $ERROR != 0 ]; then
    echo "ERRORS OCCURRED! " $ERROR
fi


echo -n "Combining coverage...         "
python-coverage combine
echo "done"
echo -n "Generating html report...     "
python-coverage html
echo "done"


exit $ERROR

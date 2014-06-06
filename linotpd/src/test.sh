#!/bin/bash

#
# This testscript can run without linotp being installed or without virtualenv.
# Just add a file like this:
#   /usr/local/lib/python2.7/dist-packages/linotp.pth
# with the contents like this:
#
# /path/to/linotpd/src
# /path/to/smsprovider/src/SMSProvider
# /parh/to/useridresolver/src/LinotpUserIdResolver
#

#additional requirements:
#
#pyrad:
# sudo apt-get install python-pyrad
#profiler:
# sudo apt-get install python-profiler
#qrcode
# sudo easy_install qrcode

usage(){
echo "Usage: $0 [ -h | -t | -r | -i other.ini | -s key=val ] [testname]"
echo ""
echo "  -h: display the usage"
echo "  -r: reset the test continuation (removes the .all)"
echo "  -i other.ini: use a different ini file than the default test.ini"
echo "  -s key=value: set additional parameters (key=value) pairs, which are provided into the test cases (untested)"
echo "  -t: show the list of the fixed test cases  "
echo "  -a: run all tests from the tests/functional directory"
echo "   "
echo "   You can specify a single testname to run only that test."

echo ""
exit 1
}



export PYTHONPATH=$PYTHONPATH:${PWD}/../../smsprovider/src/SMSProvider:${PWD}/../../useridresolver/src/


TEST_INI=test.ini
TT=`cat<<EOG
#test_adminclientutils.py
test_admin.py
test_authorize.py
test_challenge_response.py
test_emailtoken.py
test_err_response.py
test_fixes.py
test_getotp.py
test_getserial.py
test_httpsms.py
test_importotp.py
test_ldap.py
#test_license.py
test_manage.py
test_ocra2.py
test_ocra.py
test_orphaned.py
test_passwdidresolver.py
test_policy.py
test_radius_token.py
test_remote_token.py
test_replication_sync.py
test_selfservice.py
test_system.py
test_totp.py
test_validate.py
test_yubikey.py
EOG
`
TEST_ALL=0

while getopts “s:i:rhta” OPTION
do
  case $OPTION in
   h)
     usage
     exit 1
     ;;
   r)
      echo "## Reseting tests"
      touch .all && rm .all && touch .all
      shift
      exit
     ;;
   i)
      echo "## Seting the .ini file"
      TEST_INI=$OPTARG
      shift 2
      ;;
   a)
      echo "## running all tests"
      TEST_ALL=1
      shift
      ;;
   t)
      echo "## current tests are"
      echo "$TT"
      shift
      exit
      ;;

    s)
      echo "## Testparameters "
      TPARAM=" $TPARAM $OPTARG"
      shift 2
      ;;
  esac
done

# Create audit keys
linotp-create-auditkeys -f ${TEST_INI}
echo "Created audit keys"

echo '## PYTHONPATH ##'
echo $PYTHONPATH
echo '################'

echo
SQL=`grep ^sqlalchemy.url $TEST_INI | tail -1 | cut -d ' ' -f 3`
echo "Tests are running against $SQL"
echo

DB=`echo $SQL | cut -d ':' -f 1`
if [[ "sqlite" = $DB ]]
then
   ## configiure test TestDB in the test.ini
   TOKENDB=/dev/shm/token-test.db
   rm -f $TOKENDB
   echo "## token db cleaned"
fi


export TPATH=linotp/tests/functional/
PARAMS="-v -x --with-pylons=$TEST_INI "


## install an exit handler
function shutdown_paster {
   ## do a finally
   paster_id=`ps a | grep paster | grep -v grep | cut -d' ' -f1`
   if [ -n "$paster_id" ]; then
      echo "Terminating paster process:"
      ps -aef | grep $paster_id | grep -v grep
      kill -TERM $paster_id
   fi
}

trap shutdown_paster EXIT

echo "### Startting Background paster for remote tests ###"
shutdown_paster

paster setup-app $TEST_INI
paster serve $TEST_INI &
echo "### done! ###"
echo

touch .all
export TPATH=linotp/tests/functional/

if [ $# -eq 0 ]
then
 TT=$TT
else
 TT=$*
 touch .all && rm .all && touch .all
fi

if [ $TEST_ALL -eq 1 ]
then
 TT="ALL"
 PARAMS=`echo $PARAMS | sed -e 's/ -x / /g'`
fi

for tt in $TT
do
 a_run=`grep $tt .all >/dev/null && echo $?`
 if [[ $a_run == "0" ]]
 then
   echo "$(tput setaf 2)## skip processing $tt $(tput sgr0)" 
   continue
 fi

 if [ ${tt:0:1} != "#" ];
 then
   if [ $tt == "ALL" ]
   then
     tt=""
   fi
   echo "$(tput setaf 4)## starting $TPATH/$tt ############################# $(tput sgr0)"
   nosetests $LOG $PARAMS $TPATH/$tt
   if [[ $? -ne 0 ]]; then
     echo "$(tput setaf 1)"
     echo ">> $tt stopped"
     echo "$(tput sgr0)"
     exit 1
   fi
   echo $tt >> .all
  fi
done

shutdown_paster
touch .all && rm .all

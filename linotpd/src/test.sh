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
echo "Usage: $0 [ -h | -t | -r | -p | -i other.ini | -s key=val ] [testname]"
echo ""
echo "  -h: display the usage"
echo "  -r: reset the test continuation (removes the .all)"
echo "  -i other.ini: use a different ini file than the default test.ini"
echo "  -s key=value: set additional parameters (key=value) pairs, which are provided into the test cases (untested)"
echo "  -t: show the list of the fixed test cases  "
echo "  -a: run all tests from the tests/functional directory"
echo "  -p: run functional_special tests"
echo "   "
echo "   You can specify a single testname to run only that test."

echo ""
exit 1
}



export PYTHONPATH=$PYTHONPATH:${PWD}/../../smsprovider/src/SMSProvider:${PWD}/../../useridresolver/src/


TEST_INI=test.ini

BASEDIR='functional'

RUN_TEST="YES"
TEST_ALL=0
TT_CMD=""

while getopts “s:i:rhtap” OPTION
do
  echo "############ $OPTION ##################"
  case $OPTION in
   p)
      echo "# callin functional_special"
      BASEDIR='functional_special'
      shift
      ;;
   h)
      usage
      exit 1
      ;;
   r)
      echo "## Reseting tests"
      touch .all && rm .all && touch .all
      exit
      ;;

   i)
      echo "## Seting the .ini file"
      TEST_INI=$OPTARG
      shift
      shift
      ;;
   a)
      echo "## running all tests"
      TEST_ALL=1
      shift
      ;;
   t)
      echo "## current tests are"
      RUN_TEST="NO"
      shift
      ;;

    s)
      echo "## Testparameters "
      TPARAM=" $TPARAM $OPTARG"
      shift
      shift
      ;;
  esac
  shift
done

shift $((OPTIND-1)) 

FUNKDIR=`find . -name $BASEDIR -type d`
TT=`find $FUNKDIR -name "test_*.py" | sed -e "s|$FUNKDIR/||"`
TPATH=linotp/tests/$BASEDIR/

touch .all
if [ $# -eq 0 ] 
then
 TT=$TT
else
 TT=$*
 touch .all && rm .all && touch .all
fi

PARAMS="-v -x --with-pylons=$TEST_INI "

echo "Running tests:"
for t in $TT 
do  
    echo "$(tput setaf 4)## $TPATH$t"
done
echo "$(tput sgr0)"

if [[ $RUN_TEST == 'NO' ]] 
then
   exit 
fi

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


## install an exit handler
function shutdown_paster {
   ## do a finally
   PORT=`grep ^port test.ini2 | cut -f 3 -d ' '`
   paster_id=`lsof -t -i :$PORT`
   if [ -n "$paster_id" ]; then
      echo "Terminating paster process:"
      kill -TERM $paster_id
   fi
   echo "$(tput sgr0)"
}

trap shutdown_paster 0 1 2 3 15

echo "### Startting Background paster for remote tests ###"
shutdown_paster

paster setup-app $TEST_INI
paster serve $TEST_INI &
echo "### 'paster serve $TEST_INI' done! ###"
echo


PARAMS="-v -x --with-pylons=$TEST_INI "

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

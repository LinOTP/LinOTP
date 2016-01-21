#!/bin/bash

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

###
# testRadiusChallengeResponse.sh to test the challenge response
# capabilities of the radius server. it uses the radclient of 
# the freeradius package. 
#
# usage:
# 
# testRadiusChallengeResponse.sh <user> <pass> <otp>
#
# user, pass and otp are optional
###

#
#Usage: radclient [options] server[:port] <command> [<secret>]
#  <command>  : One of auth, acct, status, coa, or disconnect.
#  -c count   : Send each packet 'count' times.
#  -d raddb   : Set dictionary directory.
#  -f file    : Read packets from file, not stdin.
#  -i id      : Set request id to 'id'.  Values may be 0..255
#  -n num     : Send N requests/s
#  -p num     : Send 'num' packets from a file in parallel.
#  -q         : Do not print anything out.
#  -r retries : If timeout, retry sending the packet 'retries' times.
#  -s         : Print out summary information of auth results.
#  -S file    : read secret from file, not command line.
#  -t timeout : Wait 'timeout' seconds before retrying (may be a floating point number).
#  -v         : Show program version information.
#  -x         : Debugging mode.


radserver=192.168.56.113:1812
secret=Test123!


user=$1
pass=$2
otp=$3

if [ -z "$user" ]; then
  read -p "Enter your name: " user
fi

if [ -z "$pass" ]; then
  read -p "Enter your password: " pass
fi

resp=`echo "User-Name=$user,User-Password=$pass" | radclient $radserver auth $secret`

state=`echo $resp | sed -e "s/State = /\\nState=/g" -e "s/Reply-Message = /\\nReply-Message=/g" | grep 'State'`
reply=`echo $resp | sed -e "s/State = /\\nState=/g" -e "s/Reply-Message = /\\nReply-Message=/g" | grep 'Reply-Message'`


if [ "$state" ]; then
 echo "Challenge Response mode"
 echo $state
 echo ""

 challenge=`echo $reply | sed -e 's/Reply-Message=//g' -e 's/"//g'`

 if [ -z "$otp" ]; then
 	read -p "$challenge " otp
 fi
 echo "User-Name=$user,User-Password=$otp,$state" | radclient $radserver auth $secret

else
  echo $reply
fi




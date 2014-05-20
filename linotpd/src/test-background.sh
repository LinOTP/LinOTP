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

MAILTO=devel@lsexperts.de
MAILFROM=linotp@lsexperts.de
SUBJECT="LinOTP source broken!"
HG_INFO=`hg identify -ib`
INTRO_FEHLER="Hallo,
ich bin der automatische Testläufer für die functional tests von LinOTP.
    $HG_INFO

Gerade bin ich in den aktuellen Quellen auf einen Fehler gestoßen!

Nun folgt die Ausgabe von ./test.sh:

"
INTRO_OK="Hallo,
in der Version $HG_INFO von LinOTP sind keine Fehler im aktuellen Testlauf aufgetaucht.
"

./test.sh  > automated-check.log  2>&1

ERROR=$?

AUSGABE=`cat automated-check.log`

if [ $ERROR ]; then
	echo $INTRO_FEHLER $AUSGABE | mail -s $SUBJECT $MAILTO
else
	echo $INTRO_OK | mail -s "LinOTP erfolgreich getestet" $MAILTO
	
fi


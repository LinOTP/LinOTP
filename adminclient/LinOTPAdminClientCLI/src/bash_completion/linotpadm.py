# linotpadm.py completion
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
#
#    This file is part of LinOTP admin clients.
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
## linotpadm bash completion
# 
_linotpadm.py()
{
    local cur prev linotp_options commands
    
    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}
    linotp_options='-h --help -v --version --command= -C --url= -U --cert= -c --key= -k --admin -a'
    commands="listuser listtoken inittoken assigntoken unassigntoken importtoken disabletoken enabletoken removeetoken resynctoken set getconfig setconfig"

#    echo "${prev}"
    case "${prev}" in
	inittoken)
		COMPREPLY=( $( compgen -W "--user= --serial=" | grep "^$cur" ) )
		;;
	assigntoken)
		COMPREPLY=( $(compgen -W "--user= --serial=" | grep "^$cur" ) )
		;;
	-c|-k)
		COMPREPLY=( $(compgen -W `ls` | grep "^$cur"))
		;;
	-C)
		COMPREPLY=( $(compgen -W "$commands" | grep "^cur" ))
		;;
	*)
		COMPREPLY=( $( compgen -W "$linotp_options" | grep  "^$cur" ) )
		;;
#	    case ${COMP_WORDS[1]} in
#        	-h|--help|-v|--version)
#	            COMPREPLY=()
#        	    ;;
#	        *)
#	            COMPREPLY=( $( compgen -W "$linotp_options" | grep  "^$cur" ) )
#	            ;;
#	    esac
#	;;
    esac

	
    return 0

}
complete -F _linotpadm.py linotpadm.py

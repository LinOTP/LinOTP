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
package LinotpLDAPProxy;
## This module is to be used with the LSE LinOTP authentication 
## solution.
## See: http://lsexperts.de and http://linotp.org
## This module works as an LDAP proxy.
## It performs the bind with a One Time Password
## that is validated against the LinOTP server.
## All other actions are forwarded to the original LDAP server

# CONFIGURATION:
#======================================================================
#
# Add something like this to slapd.conf:
#
#	database	perl
#	suffix		"dc=yourDomain,dc=yourTLD"
#	perlModulePath	/directory/containing/this/module
#	perlModule	LinotpLDAPProxy
#
# configuration also occurs in /etc/ldap/slapd.conf
#
# proxy_server            ldap://192.168.0.1
# proxy_search_attr       cn mail displayName memberOf email emailAddress
# proxy_binddn            "cn=Your User,ou=users,ou=Your OU,dc=your,dc=company"
# proxy_bindpw            BindPassWord
# proxy_login_attr        sAMAccountName
#
#
# install: libnet-ldap-perl libio-socket-ssl-perl libwww-curl-perl
#
#
#
# RUN OPENLDAP:
#======================================================================
#
# LD_PRELOAD=/usr/lib/libperl.so slapd -d 1 -f /etc/ldap/slapd.conf 
#
#
# TESTING: 
#======================================================================
#
# You can test the LDAP proxy be doing an LDAP search:
#
#	ldapsearch -h localhost -x -W -D 'cn=Your User,ou=users,ou=someOU,dc=your,dc=company' 
#		-b 'ou=users,ou=someOU,dc=your,dc=class' '(objectClass=*)'
#
#   here you would need to enter the OTP PIN and OTP value of a Token of
#   this user.
#
# See the slapd-perl(5) manual page for details.

use strict;
use warnings;
use POSIX;
use Switch;
use Net::LDAP;
use WWW::Curl::Easy;


my $LDAPHOST = "";
my $BINDDN = "";
my $BINDPW = "";
# This is the LDAP attribute that contains the login username
my $LOGIN_ATTR = "";
#
# If OpenLDAP does not support the Attributes(Schema) from the source
# LDAP server, you will not be able to see all attributes.
#
my @SEARCH_ATTR = [];
# The LDAP handle
my $ldap;
# curl handle
my $curl;

my $VERSION = '0.2';

sub new {
    my $class = shift;

    my $this = {};
    bless $this, $class;
    print {*STDERR} "Here in new\n";
    print {*STDERR} 'Posix Var ' . BUFSIZ . ' and ' . FILENAME_MAX . "\n";

    return $this;
}

sub init {
    print {*STDERR} "============ init ===================\n";
    print {*STDERR} "$LDAPHOST\n";
    print {*STDERR} "$BINDDN\n";
    print {*STDERR} "$BINDPW\n";
    print {*STDERR} "$LOGIN_ATTR\n";
    print {*STDERR} "@SEARCH_ATTR\n";
	$ldap = Net::LDAP->new ( $LDAPHOST ) or die "$@";
    
    return 0;
}

sub bind {
	#
	# Do the LDAP bind, in fact we do the authentication against LINOTP
	#
    print {*STDERR} "============== in bind =============\n";
    my $this = shift;
    my ( $binddn, $bindpw ) = @_;
	
    my  $ret = 49;
    #  Here we check the username/password against LinOTP
    print {*STDERR} "===============================\n";
    print {*STDERR} "$binddn\n";
    print {*STDERR} "$bindpw\n";    
    print {*STDERR} "===============================\n";
    
    my $curl = WWW::Curl::Easy->new;
    $curl->setopt(CURLOPT_HEADER,1);
    $curl->setopt(CURLOPT_SSL_VERIFYHOST, 0);
    $curl->setopt(CURLOPT_SSL_VERIFYPEER, 0);
    
    my $username = $this->resolve_name($binddn);
    
    my $url = "https://localhost/validate/check?user=$username&pass=$bindpw";
    
    $curl->setopt(CURLOPT_URL, $url);
    
    print {*STDERR} "================================\n";
    print {*STDERR} "$url\n";
    print {*STDERR} "================================\n";
    
    my $response_body = "";
    open(my $fileb, ">", \$response_body);
    $curl->setopt(CURLOPT_WRITEDATA,\$fileb);

    #Starts the actual request
    my $retcode = $curl->perform;

    # Looking at the results...
    if ($retcode == 0) {
        #print {*STDERR} ("Transfer went ok\n");
        my $response_code = $curl->getinfo(CURLINFO_HTTP_CODE);
        if ($response_body =~ /"status": true/) {
        	print {*STDERR} "==== LinOTP returned status true ====\n";
        	if ($response_body =~ /"value": true/) {
        		print {*STDERR} "==== LinOTP auth success ====\n";
        		$ret = 0;
        	} else {
        		print {*STDERR} "==== LinOTP auth fail ====\n";
        		$ret = 49;
        	}
        } else {
        	print {*STDERR} "==== LinOTP returned status false ====\n";
        	$ret = 52;
        }
    } else {
        # Error code, type of error, error message
        print {*STDERR} ("An error happened: $retcode ".$curl->strerror($retcode)." ".$curl->errbuf."\n");
        $ret = 52;
    }
    
    # return error code:
    # 0 : success
    # 49: invalid credentials
    # 52: unavailable
    # 81: server down
    # http://wikis.sun.com/display/SunJavaSystem/LDAP+Error+Codes
    return $ret;
}

sub original_bind() {
	#
	# Do an original bind to the original LDAP server
	#
    my $mesg = $ldap->bind ( $BINDDN,           
                      password => "$BINDPW",
                      version => 3 );
    my $result = $mesg->error;
    print {*STDERR} "original bind result: $result";
}

sub resolve_name() {
	#
	# resolve the DN to the login attribute
	#
    my $this = shift;
    my $dn = shift;
    my $return_username="";
    print {*STDERR} "Resolving $dn\n\n";
    $this->original_bind();
    
    my $result = $ldap->search( base => "$dn",
    				filter => "(objectClass=*)",
    				scope => "base",
    				attrs => [ "$LOGIN_ATTR" ] );
    				
    print {*STDERR} "\n\n$result\n\n";
    
    my @entries = $result->entries;
    
    print {*STDERR} "Eintraege: @entries\n";

    my $entr;
	foreach $entr ( @entries ) {
		my $rdn= $entr->dn;
		print {*STDERR} "DN: $rdn \n";
		my $attr;
		foreach $attr ( sort $entr->attributes ) {
			my $vattr=$entr->get_value($attr);
			print {*STDERR} "$attr : $vattr\n";
			#print {*STDERR} "$attr\n";
			#print {*STDERR} "$LOGIN_ATTR\n";
			if ( "$attr" eq "$LOGIN_ATTR" ) {
				$return_username=$vattr;
			}
		}
	}
	return $return_username;
}

sub search {
	#
	# Do an LDAP search to find attributes of user
	#
    my $this = shift;
    my ( $base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly,
        @attrs )
      = @_;
        
     
    $this->original_bind();
    
    print {*STDERR} "\n\n===== in search =======\n";
    print {*STDERR} "====$filterStr====\n";
    #print {*STDERR} $attrOnly;
    #print {*STDERR} @attrs;
    
    my $attrs = [ 'cn','mail', 'displayName' ]; 

    my $result = $ldap->search ( base    => "$base",
                                scope   => "$scope",
                                filter  => "$filterStr",
                                attrs  => @SEARCH_ATTR
                              );
                              

	my @entries = $result->entries;
	my @match_entry = ();
	my $entr;
	my $str_entry;
	foreach $entr ( @entries ) {
		my $dn = $entr->dn;
		$str_entry = "dn: $dn\n";
		print {*STDERR} "============ $dn\n";
		my $attr;
		foreach $attr ( sort $entr->attributes ) {
			# skip binary we can't handle
			if ( $attr !~ /;binary$/ ) {
				print {*STDERR} "===== $attr\n";
				$str_entry .= "$attr: " . $entr->get_value ( $attr ) . "\n";
				print {*STDERR} "============== $str_entry\n";
			}
		}
		push @match_entry, $str_entry; 
		#print {*STDERR} $str_entry;
   
		last if ( scalar @match_entry == $sizeLim );
	}

	return ( 0, @match_entry );
}

sub compare {
	#
	# not tested
	#
    my $this = shift;
    my ( $dn, $avaStr ) = @_;
    my $rc = 5;    # LDAP_COMPARE_FALSE


    print {*STDERR} "========================= compare =======================\n";
    $avaStr =~ s/=/: /m;

    if ( $this->{$dn} =~ /$avaStr/im ) {
        $rc = 6;    # LDAP_COMPARE_TRUE
    }

    return $rc;
}

sub modify {
	#
	# not tested
	#
    my $this = shift;

    my ( $dn, @list ) = @_;

    while ( @list > 0 ) {
        my $action = shift @list;
        my $key    = shift @list;
        my $value  = shift @list;

        if ( $action eq 'ADD' ) {
            $this->{$dn} .= "$key: $value\n";

        }
        elsif ( $action eq 'DELETE' ) {
            $this->{$dn} =~ s/^$key:\s*$value\n//im;

        }
        elsif ( $action eq 'REPLACE' ) {
            $this->{$dn} =~ s/$key: .*$/$key: $value/im;
        }
    }

    return 0;
}

sub add {
	#
	# not tested
	#
    my $this = shift;

    my ($entryStr) = @_;

    my ($dn) = ( $entryStr =~ /dn:\s(.*)$/m );

    #
    # This needs to be here until a normalized dn is
    # passed to this routine.
    #
    $dn = uc $dn;
    $dn =~ s/\s*//gm;

    $this->{$dn} = $entryStr;

    return 0;
}

sub modrdn {
	#
	# not tested
	#
    my $this = shift;

    my ( $dn, $newdn, $delFlag ) = @_;

    $this->{$newdn} = $this->{$dn};

    if ($delFlag) {
        delete $this->{$dn};
    }
    return 0;

}

sub delete {
	#
	# not tested
	#
    my $this = shift;

    my ($dn) = @_;

    print {*STDERR} "XXXXXX $dn XXXXXXX\n";
    delete $this->{$dn};
    return 0;
}

sub config {
	#
	# This function reads to openldap unknown values from slapd.conf
	#
	# We need the following vales:
	# proxy_server
	# proxy_search_attr 
	# proxy_binddn      
	# proxy_bindpw      
	# proxy_login_attr  
	#
	# Fill variables:
	#
	# $LDAPHOST = "";
	# $BINDDN = "";
    # $BINDPW = "";
	# $LOGIN_ATTR = "";
	# $SEARCH_ATTR = [];
	
    my $this = shift;

	print {*STDERR} "========================= config ========================\n";
    my (@args) = @_;
    local $, = ' - ';
    print {*STDERR} @args;
    print {*STDERR} "\n";
    
    my $ret = 0;
    my $key = $args[0];
    
    switch ($key) {

		case "proxy_server"		{ $LDAPHOST = $args[1] }
		case "proxy_binddn"		{ $BINDDN = $args[1] }
		case "proxy_bindpw"		{ $BINDPW = $args[1] }
		case "proxy_login_attr"	{ $LOGIN_ATTR = $args[1] }
		case "proxy_search_attr" 	{ 
				for (my $i=1;$i<@args;$i++){
					push(@SEARCH_ATTR, $args[$i]);
				}
			 }
		else	{ $ret = -1 }
	};
    return 0;
}

1;


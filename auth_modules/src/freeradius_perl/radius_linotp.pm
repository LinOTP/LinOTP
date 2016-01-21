#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
# 
#    This file is part of LinOTP authentication modules.
# 
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
# 
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
# 
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
# 
#
#   Copyright 2002  The FreeRADIUS server project
#   Copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
#   Copyright 2011  LSE Leading Security Experts GmbH
#
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de




#
# Based on the Example code for use with rlm_perl
#
#

=head1 NAME

freeradius_perl - Perl module for use with FreeRADIUS rlm_perl, to authenticate against 
 LinOTP  http://www.linotp.org

=head1 SYNOPSIS

   use with freeradius:  
   
   Configure rlm_perl to work with LinOTP:
   in /etc/freeradius/users 
    set:
     DEFAULT Auth-type := perl

  in /etc/freeradius/modules/perl
     point
     perl {
         module = 
  to this file

  in /etc/freeradius/sites-enabled/<yoursite>
  set
  authenticate{
    perl
    [....]

=head1 DESCRIPTION

This module enables freeradius to authenticate using LinOTP.

   TODO: 
     * checking of server certificate


=head2 Methods

   * authenticate
   

=head1 CONFIGURATION

The authentication request with its URL and default LinOTP Realm could be defined 
in a dedicated configuration file, which is expected to be:

  /etc/linotp2/rlm_perl.ini
  
This configuration file could contain default definition for URL and REALM like
  URL = http://192.168.56.1:5001/validate/simplecheck
  REALM =  

But as well could contain "Access-Type" specific configurations, e.g. for the 
Access-Type 'scope1', this would look like:

  
  URL = https://localhost/validate/simplecheck
  REALM =  
  scope1[URL] = http://192.168.56.1:5001/validate/simplecheck
  scope1[REALM] = mydefault

=head1 AUTHOR

Cornelius Koelbel (cornelius.koelbel@lsexperts.de)

=head1 COPYRIGHT

Copyright 2013-2015

This library is free software; you can redistribute it 
under the GPLv2.

=head1 SEE ALSO

perl(1).

=cut

use strict;
#use IO::Socket::SSL qw(debug3); # <- enable SSL debugging!
use LWP 5.64;
use Config::File;
use Data::Dumper;
use Try::Tiny;

# use ...
# This is very important ! Without this script will not get the filled  hashesh from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_CONFIG );

# This is hash wich hold original request from radius
#my %RAD_REQUEST;
# In this hash you add values that will be returned to NAS.
#my %RAD_REPLY;
#This is for check items
#my %RAD_CHECK;


# constant definition for the remapping of return values
use constant RLM_MODULE_REJECT  =>  0; #  /* immediately reject the request */
use constant RLM_MODULE_FAIL    =>  1; #  /* module failed, don't reply */
use constant RLM_MODULE_OK      =>  2; #  /* the module is OK, continue */
use constant RLM_MODULE_HANDLED =>  3; #  /* the module handled the request, so stop. */
use constant RLM_MODULE_INVALID =>  4; #  /* the module considers the request invalid. */
use constant RLM_MODULE_USERLOCK => 5; #  /* reject the request (user is locked out) */
use constant RLM_MODULE_NOTFOUND => 6; #  /* user not found */
use constant RLM_MODULE_NOOP     => 7; #  /* module succeeded without doing anything */
use constant RLM_MODULE_UPDATED  => 8; #  /* OK (pairs modified) */
use constant RLM_MODULE_NUMCODES => 9; #  /* How many return codes there are */

our $ret_hash = { 
    0 => "RLM_MODULE_REJECT",
    1 => "RLM_MODULE_FAIL",
    2 => "RLM_MODULE_OK",
    3 => "RLM_MODULE_HANDLED",
    4 => "RLM_MODULE_INVALID", 
    5 => "RLM_MODULE_USERLOCK",
    6 => "RLM_MODULE_NOTFOUND",
    7 => "RLM_MODULE_NOOP",
    8 => "RLM_MODULE_UPDATED",
    9 => "RLM_MODULE_NUMCODES"
};

## constant definition for comparison
use constant false => 0;
use constant true  => 1;

## constant definitions for logging
use constant Debug => 1;
use constant Auth  => 2;
use constant Info  => 3;
use constant Error => 4;
use constant Proxy => 5;
use constant Acct  => 6;

my $LIN_OK     = ":-)";
my $LIN_REJECT = ":-(";
my $LIN_FAIL   = ":-/";


#from @INC Config/File.pm
use Config::File;

our $CONFIG_FILE = "/etc/linotp2/rlm_perl.ini";
our $Config = {};

if ( -e $CONFIG_FILE ) {
    $Config = Config::File::read_config_file($CONFIG_FILE);
    $Config->{FSTAT}     = "found!";
} else {
    $Config->{FSTAT}     = "not found!";
    $Config->{URL}       = 'https://localhost/validate/simplecheck';
    $Config->{REALM}     = '';
    $Config->{RESCONF}   = "";
    $Config->{Debug}     = "FALSE";
    $Config->{SSL_CHECK} = "FALSE";
}

# Function to handle authenticate
sub authenticate {

    ## show where the config comes from - 
    # in the module init we can't print this out, so it starts here
    &radiusd::radlog( Info, "Config File $CONFIG_FILE $Config->{FSTAT}" );

    # we inherrit the defaults
    my $URL     = $Config->{URL};
    my $REALM   = $Config->{REALM};
    my $RESCONF = $Config->{RESCONF};
    
    # Ssl support...
    my $cafile = $Config->{HTTPS_CA_FILE} or ""; # <- ca certificate file
    my $capath = $Config->{HTTPS_CA_DIR}  or ""; # <- ca certificate dir
    my $chkssl = true; # <- for security reasons, chkssl is true by default
    if ( $Config->{SSL_CHECK} =~ /^\s*false\s*$/i ) {
        $chkssl = false;
    }

    my $useNasIdentifier = true;
    if ( $Config->{PREFER_NAS_IDENTIFIER} =~ /^\s*false\s*$/i ) {
        $useNasIdentifier = false;
    }

    my $debug = false;
    if ( $Config->{Debug} =~ /^\s*true\s*$/i ) {
        $debug = true;
    }

    &radiusd::radlog( Info, "Default URL $URL " );

    # if there exists an auth-type config may overwrite this
    my $auth_type = $RAD_CONFIG{"Auth-Type"};

    try {
        if ( exists( $Config->{$auth_type}{URL} ) ) {
            $URL = $Config->{$auth_type}{URL};
        }
        if ( exists( $Config->{$auth_type}{REALM} ) ) {
            $REALM = $Config->{$auth_type}{REALM};
        }
        if ( exists( $Config->{$auth_type}{RESCONF} ) ) {
            $RESCONF = $Config->{$auth_type}{RESCONF};
        }
    } catch {
        &radiusd::radlog( Error, "error: $@" );
    };

    if ( $debug == true ) {
        &log_request_attributes;
    }

    my %params = ();

    # put RAD_REQUEST members in the LinOTP request
    if ( exists( $RAD_REQUEST{'State'} ) ) {
        my $hexState = $RAD_REQUEST{'State'};
        if ( substr( $hexState, 0, 2 ) eq "0x" ) {
            $hexState = substr( $hexState, 2 );
        }
        $params{'state'} = pack 'H*', $hexState;
    }

    # Username and password...
    if ( exists( $RAD_REQUEST{'User-Name'} ) ) {
        $params{"user"} = $RAD_REQUEST{'User-Name'};
    }
    if ( exists( $RAD_REQUEST{'User-Password'} ) ) {
        $params{"pass"} = $RAD_REQUEST{'User-Password'};
    }

    # IP Address of client...
    if      ( $useNasIdentifier and exists( $RAD_REQUEST{'NAS-IP-Address'} ) ) {
        $params{"client"} = $RAD_REQUEST{'NAS-IP-Address'};
    } elsif ( $useNasIdentifier and exists( $RAD_REQUEST{'NAS-IPv6-Address'} ) ) {
        $params{"client"} = $RAD_REQUEST{'NAS-IPv6-Address'};
    } elsif ( exists( $RAD_REQUEST{'Packet-Src-IP-Address'} ) ) {
        $params{"client"} = $RAD_REQUEST{'Packet-Src-IP-Address'};
    } elsif ( exists( $RAD_REQUEST{'Packet-Src-IPv6-Address'} ) ) {
        $params{"client"} = $RAD_REQUEST{'Packet-Src-IPv6-Address'};
    } else {
        &radiusd::radlog( Info, "Warning, PACKET_SRC_IP_ADDRESS not available" );
    }

    if ( length($REALM) > 0 ) {
        $params{"realm"} = $REALM;
    }
    if ( length($RESCONF) > 0 ) {
        $params{"resConf"} = $RESCONF;
    }

    &radiusd::radlog( Info, "Auth-Type: $auth_type" );
    &radiusd::radlog( Info, "Url: $URL" );
    &radiusd::radlog( Info, "User: $RAD_REQUEST{'User-Name'}" );
    if ( $debug == true ) {
        &radiusd::radlog( Debug, "urlparam $_ = $params{$_}\n" )
            for ( keys %params );
    }
    else {
        &radiusd::radlog( Info, "urlparam $_ \n" )
            for ( keys %params );
    }

    my $ua = LWP::UserAgent->new();
    if ($chkssl == false) {
        $ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);
    } else {
        $ua->ssl_opts(verify_hostname => 1);
        if (length $cafile) {
            if ( $debug == true ) {
                &radiusd::radlog( Info, "ssl_opts(SSL_ca_file => '$cafile')" );
            }
            $ua->ssl_opts(SSL_ca_file => $cafile);
        }
        if (length $capath) {
            if ( $debug == true ) {
                &radiusd::radlog( Info, "ssl_opts(SSL_ca_path => '$capath')" );
            }
            $ua->ssl_opts(SSL_ca_path => $capath);
        }
    }
    my $response = $ua->post( $URL, \%params );
    if (not $response->is_success) {
        &radiusd::radlog( Info, "LinOTP Request failed: at $URL\nDetails: " . $response->status_line );
        $RAD_REPLY{'Reply-Message'} = "LinOTP server is not available!";
        return RLM_MODULE_FAIL;
    }

    my $content  = $response->decoded_content();
    if ( $debug == true ) {
        &radiusd::radlog( Debug, "Content $content" );
    }
    $RAD_REPLY{'Reply-Message'} = "LinOTP server denied access!";
    my $g_return = RLM_MODULE_REJECT;

    if ( $content eq $LIN_OK ) {
        &radiusd::radlog( Info, "LinOTP access granted" );
        $RAD_REPLY{'Reply-Message'} = "LinOTP access granted";
        $g_return = RLM_MODULE_OK;
    }
    elsif ( $content eq $LIN_FAIL ) {
        &radiusd::radlog( Info, "LinOTP access failed" );
        $RAD_REPLY{'Reply-Message'} = "LinOTP access failed";
        $g_return = RLM_MODULE_FAIL;
    }
    elsif ( $content eq $LIN_FAIL ) {
        &radiusd::radlog( Info, "LinOTP server denied access!" );
        $RAD_REPLY{'Reply-Message'} = "LinOTP server denied access!";
        $g_return = RLM_MODULE_REJECT;
    }
    elsif (( substr( $content, 0, length($LIN_REJECT) ) eq $LIN_REJECT )
        && ( length($content) > length($LIN_REJECT) ) )
    {
        ## we are in challenge response mode:
        ## 1. split the response in fail, state and challenge
        ## 2. show the client the challenge and the state
        ## 3. get the response and
        ## 4. submit the response and the state to linotp and
        ## 5. reply ok or reject

        &radiusd::radlog( Info, "Challenge Mode:" );
        my ( $ok, $state, $challenge ) = split( / +/, $content, 3 );
        if ( length($challenge) == 0 ) { $challenge = ""; }

        $RAD_REPLY{'State'}                = $state;
        $RAD_REPLY{'Reply-Message'}        = $challenge;
        $RAD_CHECK{'Response-Packet-Type'} = "Access-Challenge";
        $g_return                          = RLM_MODULE_HANDLED;
    }

    &radiusd::radlog( Info, "return $ret_hash->{$g_return}" );
    return $g_return;

}

sub log_request_attributes {

    #for ( keys %ENV ) {
    #    &radiusd::radlog( Debug, "ENV_VARIABLE: $_ = $ENV{$_}" );
    #    ;
    #}

    #for ( keys %RAD_CONFIG ) {
    #    &radiusd::radlog( Debug, "RAD_CONFIG: $_ = $RAD_CONFIG{$_}" );
    #    ;
    #}

    # This shouldn't be done in production environments!
    # This is only meant for debugging!
    for ( keys %RAD_REQUEST ) {
        &radiusd::radlog( Debug, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}" );
        ;
    }

}

# Function to handle authorize
sub authorize {

    # For debugging purposes only
    # &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle preacct
sub preacct {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {

    # For debugging purposes only
    #       &log_request_attributes;

    # You can call another subroutine from here
    &test_call;

    return RLM_MODULE_OK;
}

# Function to handle checksimul
sub checksimul {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle xlat
sub xlat {

    # For debugging purposes only
    #       &log_request_attributes;

    # Loads some external perl and evaluate it
    my ( $filename, $a, $b, $c, $d ) = @_;
    &radiusd::radlog( 1, "From xlat $filename " );
    &radiusd::radlog( 1, "From xlat $a $b $c $d " );
    local *FH;
    open FH, $filename or die "open '$filename' $!";
    local ($/) = undef;
    my $sub = <FH>;
    close FH;
    my $eval = qq{ sub handler{ $sub;} };
    eval $eval;
    eval { main->handler; };
}

# Function to handle detach
sub detach {

    # For debugging purposes only
    #       &log_request_attributes;

    # Do some logging.
    &radiusd::radlog( 0, "rlm_perl::Detaching. Reloading. Done." );
}

#
# Some functions that can be called from other functions
#

sub test_call {

    # Some code goes here
}

1;

#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
#
#   This file is part of LinOTP authentication modules.
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.

#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
#

'''
# LinOTP authentication pam module - for usage under libpam-python

Installation:
=============
Install this file in the directory:
    /lib/security/

and setup a file:
    /etc/pam.d/common-linotp

with this component:

---8<------8<------8<------8<------8<------8<------8<------8<------8<------8<--
## here are the per-package modules (the "Primary" block)
auth    [success=1 default=ignore]  pam_python.so /lib/security/pam_linotp.py \
                              debug url=https://localhost/validate/simplecheck

--->8------>8------>8------>8------>8------>8------>8------>8------>8------>8--
- compare to common auth and use it in the pam services.

Test:
=====

For test purpose, you can extend the /etc/pam.d/loggin by replacing the
common-auth:

# Standard Un*x authentication.
#@include common-auth
@include common-linotp

and start a "login user" from a root shell

Module Parameters:
==================

Paramters to the module are:

 :param debug: display security relevant information in the syslog - critical -
 :param utrl=: the LinOTP verification url
 :param realm: the users LinOTP realm, which is requrired, if the user is not
               in the default realm
 :param prompt: the first password propmt (_ will be replaced with whitespaces)


Happy Authenticating!

'''

import syslog
import urllib
import urllib2
import pwd

LINOTP_FAIL = ":-/"
LINOTP_OK = ":-)"
LINOTP_REJECT = ":-("

def get_config( argv ):
    '''
    parse the module arguments and put them in a config dict

    :param argv: array of arguments from the config file
    :return: config dict
    '''

    config = {}
    config["url"] = "https://localhost/validate/simplecheck"
    config["prompt"] = "Your OTP:"
    config["debug"] = False

    # split the config parameters
    if "debug" in argv:
        config["debug"] = True

    # parse parameter
    for arg in argv:

        if arg.startswith( "url=" ):
            config["url"] = arg[len( "url=" ):]

        if arg.startswith( "realm=" ):
            config["realm"] = arg[len( "realm=" ):]

        if arg.startswith( "prompt=" ):
            prompt = arg[len( "prompt=" ):]
            config["prompt"] = prompt.replace( "_", " " )

    return config

def pam_sm_authenticate( pamh, flags, argv ):
    '''
    callback for the pam authentication

    :param pamh: pam context handle
    :param flags: ?? - unknown to me
    :param argv: configuration arguments
    '''

    syslog.openlog( "pam_linotp", syslog.LOG_PID, syslog.LOG_AUTH )
    result = pamh.PAM_AUTH_ERR

    try:
        config = get_config( argv )
        debug = config.get( 'debug', False )
        url = config.get( 'url', 'https://localhost/validate/simplecheck' )

        if debug:
            syslog.syslog( "start pam_linotp.py authentication: %s, %s" %
                                                             ( flags, argv ) )

        ## get the password of the user:
        ##     either from the pam handle or request this
        if pamh.authtok == None:
            if debug:
                syslog.syslog( "got no password in authtok - "
                                                "trying through conversation" )
            msg = pamh.Message( pamh.PAM_PROMPT_ECHO_OFF, config.get( 'prompt',
                                                        "[LinOTP] Password" ) )
            rsp = pamh.conversation( msg )
            pamh.authtok = rsp.resp

            if debug:
                syslog.syslog( "got password: " + pamh.authtok )

        #
        # check pamh.authtok against LinOTP  with pamh.user and pamh.authtok
        params = {}
        params["user"] = pamh.user
        params["pass"] = pamh.authtok

        if config.has_key( "realm" ):
            params["realm"] = config.get( "realm" )

        if debug:
            syslog.syslog( syslog.LOG_INFO, "calling url %s %r" %
                                                            ( url, params ) )

        data = urllib.urlencode( params )
        req = urllib2.Request( url, data )

        response = urllib2.urlopen( req )
        ret = response.read()

        if debug:
            syslog.syslog( ret )

        result = check_response( pamh, ret, pamh.user, config )

    except Exception as exept:
        syslog.syslog( "Error: %r" % exept )

    finally:
        syslog.closelog()

    return result


def check_response( pamh, ret, user, config ):
    """
    analyse the LinOTP result and return the corresponding return codes

    :param pamh: the pam request handle
    :param ret: the response of a former LinOTP request
    :param user: the requesting user
    :param config: the module configuration for accessin 'debug' or url

    :return: pamh.PAM_AUTH_ERR or pamh.PAM_SUCCESS
    """

    result = pamh.PAM_AUTH_ERR

    ## access failed - error report from LinOTP
    if ret == LINOTP_FAIL:
        syslog.syslog( syslog.LOG_INFO, "user failed to authenticate" )
        result = pamh.PAM_AUTH_ERR

    ## access accepted
    elif ret == LINOTP_OK:
        syslog.syslog( syslog.LOG_INFO, "user successfully authenticated" )
        result = pamh.PAM_SUCCESS

    ## access rejected
    elif ret == LINOTP_REJECT:
        syslog.syslog( syslog.LOG_INFO, "user rejected" )
        result = pamh.PAM_AUTH_ERR

    ## challenge mode
    elif len( ret ) > len( LINOTP_REJECT ) and ret.startswith( LINOTP_REJECT ):
        syslog.syslog( "in challenge mode" )
        parts = ret.split( ' ' )
        challenge = "Otp: "
        state = ""

        if len( parts ) > 1:
            state = parts[1]

        if len( parts ) > 2:
            del parts[0]
            del parts[0]
            challenge = " ".join( parts )

        msg = pamh.Message( pamh.PAM_PROMPT_ECHO_OFF, challenge )
        rsp = pamh.conversation( msg )
        pamh.authtok = rsp.resp

        syslog.syslog( "submitting response of challenge" )

        ## now redo the simplecheck
        params = {}
        params["user"] = user

        params['pass'] = rsp.resp
        params['state'] = state

        data = urllib.urlencode( params )
        req = urllib2.Request( config.get( 'url' ), data )

        response = urllib2.urlopen( req )
        ret = response.read()

        if config.get( 'debug' ):
            syslog.syslog( "challenge returned %s " % ret )

        result = check_response( pamh, ret, user, config )

    else:
        syslog.syslog( syslog.LOG_INFO, "user failed to authenticate" )
        result = pamh.PAM_AUTH_ERR


    return result


def pam_sm_setcred( pamh, flags, argv ):
    """  pam_sm_setcred  """
    syslog.syslog( syslog.LOG_INFO,
                  "Please note: pam_linotp does not support setcred" )
    return pamh.PAM_CRED_UNAVAIL

def pam_sm_acct_mgmt( pamh, flags, argv ):
    """  pam_sm_acct_mgmt  """
    syslog.syslog( syslog.LOG_INFO,
                  "Please note: pam_linotp does not support acct_mgmt" )
    return pamh.PAM_SERVICE_ERR

def pam_sm_chauthtok( pamh, flags, argv ):
    """ pam_sm_chauthtok """
    syslog.syslog( syslog.LOG_INFO,
                  "Please note: pam_linotp does not support chauthtok" )
    return pamh.PAM_SERVICE_ERR

def pam_sm_open_session( pamh, flags, argv ):
    """ pam_sm_open_session """
    syslog.syslog( syslog.LOG_INFO,
                  "Please note: pam_linotp does not support open_session" )
    return pamh.PAM_SERVICE_ERR

def pam_sm_close_session( pamh, flags, argv ):
    """ pam_sm_close_session """
    syslog.syslog( syslog.LOG_INFO,
                  "Please note: pam_linotp does not support close_session" )
    return pamh.PAM_SERVICE_ERR

##eof##########################################################################

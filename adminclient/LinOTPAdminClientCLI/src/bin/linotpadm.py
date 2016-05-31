#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de
#
"""
This is the cmd client admin to manage the tokens on the LinOTP 2 server
  Dependencies: clientutils, etokenng
"""

from linotpadminclientcli import __version__

import os
import subprocess
import datetime
from getopt import getopt, GetoptError
import getpass
from linotpadminclientcli.clientutils import *
from linotpadminclientcli.yubikey import enrollYubikey
from linotpadminclientcli.yubikey import YubikeyPlug
from linotpadminclientcli.yubikey import create_static_password
import ConfigParser
import pprint
import smtplib
from email.mime.text import MIMEText


YUBI_STATIC_MODE = 3
YUBI_OATH_MODE = 2
YUBI_AES_MODE = 1

try:
    from linotpadminclientcligui.etokenng import *
    EDITION = "ETNG"
except ImportError:
    EDITION = "NOETNG"

print
print "Thank you for running the LinOTP2 linotpadmin client"
print


REALM = "LinOTP2 admin area (admin/admin)"
COMMANDS = [ 'listtoken', 'inittoken', 'assigntoken',
            'importtoken', 'disabletoken', 'enabletoken',
            'resynctoken', 'removetoken', 'set',
            'unassigntoken', 'listuser', 'getconfig', 'setconfig',
            'getrealms', 'setrealm', 'deleterealm', 'setdefaultrealm',
            'getresolvers', 'deleteresolver', 'setresolver', 'loadtokens',
            'yubikey_mass_enroll', 'etokenng_mass_enroll',
            'securitymodule' ]

def usage():
    print "usage: %s --url=<url> --admin=<adminusername> --cert=<cert> --key=<rsakey> --command=<command> --version" % sys.argv[0]
    print """"  --url/-U     : The base url of the LinOTP server. Something like
                 http://localhost:5000 or https://linotp:443
  --admin/-a   : If the admin interface of the LinOTP service requires authentication
                 you need to pass the username and will be asked for the password.
  --password   : The password of the admin. You should not use this option, since the password would
                 be visible in the process list and history.
  --authtype   : The default authtype is 'Digest'. You may change this to 'Basic'
  --cert/-c    : If the admin interface of the LinOTP service requires authentication via client certificate
                 you may pass a P12 file here.
  --key/-k     : The private key for authenticating
  --admin/-a   : The name of the administrative account, when authenticating with username/password
  --version/-v : Print version
  --help/-h    : Print this help screen
  --automate   : read parameters from a config file to be used for automation
  --disable_ssl_certificate_validation/-x : disable server certificate verification

  --command/-C :
    listtoken:    [--user | --serial ] [--csv]
    listuser:
    inittoken:    --user= --serial= --description= --pin= --otpkey= --etng --pytoken --type=<type>
    inittoken:    --user= --serial= --description= --pin= --otpkeyc=
    yubikey_mass_enroll
        --yubiprefix=<string>
        --yubiprefixrandom=<length>
        --yubiprefixserial          : use the serial of the yubikey as prefix
        --yubimode=<OATH or YUBICO or STATIC>
        --yubislot=<1 or 2>
        --yubiCR                    : programm the Yubikey in challenge Response mode (TOTP, 60seconds)
    etokenng_mass_enroll [--label=TokenName]
    assigntoken:    --user --serial
    unassigntoken:  --serial
    importtoken:    --file or -f
    disabletoken:   --serial | --user
    enabletoken:    --serial | --user
    removeetoken:   --serial | --user
    resynctoken:    --serial | --user   --otp1  --otp2
    set:       [--user | --serial ] --pin --maxfailcount --syncwindow --otplen

    Security Modules
    ----------------
    securitymodule:         get the status of the security module or set the password for the module
                            To set the password, you must specify the following parameter:
                                   --module=<modulename>

    Server configuration
    --------------------
    getconfig:    returns the configuration of the LinOTP server
    setconfig:    sets a certain config value like this
                  --config='DefaultSyncWindow=500'
    Realm and resolver configuration
    --------------------------------
    getrealms:               lists all realms
    setrealm:        --realm=<realmname> --resolver=<resolverlist>
    deleterealm:     --realm=<realmname>
    setdefaultrealm: --realm=<realmname>
    getresolvers:            returns a list of all available resolvers
    deleteresolver:  --resolver=<resolvername>
    setresolver:     --resolver=<> --rtype=[LDAP,SQL,FILE] ....

  Parameters for commands:
    --csv             show the token list as CSV format
    --export_fields=<additional user fields> additional fields from the useridresolver to add to the export.
    --user=<user> or -u <user>
    --pin=<pin> or -p <pin>
    --serial=<S/N> or -s <serial>
    --description=<description for Token> or -d <description>
    --otpkey=<HMAC key> or -H
                      This is usually not necessary, as keys are read from the file
    --file=<file with Token data> or -f <file>
    --otpval=<otp value for resyncing>
    --window=<resyncing windows size> or -w
    --etng or -e
                      This parameter takes no value. If it is passed to the inittoken command,
                      an Aladdin eTokenNG OTP is initialized. --hmac and --serial are ignored.
    --pytoken         This parameter takes no value. This will create a soft Token as python script
                      example: linotpadm.py -U https://localhost -a admin -C inittoken --type=HMAC --pytoken --user=jdoe
    --type=<type> or -t
                      This specifies the Type of the OTP Token to be initialized.
                      HMAC is default. You may specify the type 'motp'
                      When using 'motp' you also need to specify --otppin=
    --realm=<realmname>
                      gives the realm to operate on.
    --resolver=<resolvername> or <resolverlist>
                      comma separated list of resolvers or
                      single resolver

  Parameters for the command setresolver:
    --rtype           Specify the type of the resolver: LDAP, SQL or FILE
                      Depending on the resolver type, there are different parameters to set.
    --rf_file         Resolver FILE: the filename containing the users on the LinOTP server
    --rl_uri          Resolver LDAP: the LDAP uri of the ldap server
    --rl_basedn       Resolver LDAP: the BaseDN for searching for users
    --rl_binddn       Resolver LDAP: the BindDN to authenticate to the LDAP server
    --rl_bindpw       Resolver LDAP: the Bind Password to authenticate to the LDAP server
    --rl_timeout      Resolver LDAP: the timeout when connecting to the LDAP server
    --rl_loginattr    Resolver LDAP: the attribute containing the loginname like uid
    --rl_searchfilter Resolver LDAP: the searchfilter. Something like (uid=*)(objectClass=inetOrgPerson)
    --rl_userfilter   Resolver LDAP: the userfilter for reverse resoling the DN for a given loginname,
                                     something like (&(uid=%s)(ObjectClass=inetOrgPerson))
    --rl_attrmap      Resolver LDAP: the attribute mapping. Something like:
                                     { "username": "uid", "phone" : "telephoneNumber", "groups" : "o", "mobile" : "mobile", "email" : "mail", "surname" : "sn", "givenname" : "givenName" }
"""




def showresult(rv):
    pp = pprint.PrettyPrinter(indent=4)
    print pp.pformat(rv['result'])


def yubi_mass_enroll(lotpc,
                     proc_params,
                     yubi_mode,
                     yubi_slot,
                     yubi_prefix_serial,
                     yubi_prefix,
                     yubi_prefix_random,
                     yubi_cr,
                     ):
    '''
    Do the Yubikey mass enrollment

    :param lotpc: the linotp connnection
    :param proc_params: the additional parameters from the command line
    :param yubi_mode: yubikey modus: YUBI_STATIC_MODE, YUBI_OATH_MODE, YUBI_AES_MODE
    :param yubi_slot: slot of the yubikey [1,2]
    :param yubi_prefix_serial: serial number added to the prefix
    :param yubi_prefix: the public prefix
    :param yubi_prefix_random: the rendom prefix
    :param yubi_cr: boolean - uses as TOTP token
    '''
    yp = YubikeyPlug()
    while 0 == 0:
        print "\nPlease insert the next yubikey.",
        sys.stdout.flush()
        submit_param = {}
        #input = raw_input("Please insert the next yubikey and press enter (x=Exit): ")
        #if "x" == input.lower():
        #    break
        ret = yp.wait_for_new_yubikey()

        # if otplen is set and YUBI_OATH mode, we add the digits 
        # parameter to the yubienroll
        ykparams = {}
        if (yubi_mode == YUBI_OATH_MODE and
            'otplen' in proc_params and proc_params['otplen'] in ['6','8']):
            ykparams['digits'] = int(proc_params['otplen'])

        otpkey, serial = enrollYubikey(debug=False,
                                        prefix_serial=yubi_prefix_serial,
                                        fixed_string=yubi_prefix,
                                        len_fixed_string=yubi_prefix_random,
                                        slot=yubi_slot,
                                        mode=yubi_mode,
                                        challenge_response=yubi_cr, **ykparams)

        description = proc_params.get('description', "mass enrolled")
        if yubi_mode == YUBI_OATH_MODE:
            # According to http://www.openauthentication.org/oath-id/prefixes/
            # The OMP of Yubico is UB
            # As TokenType we use OM (oath mode)
            submit_param = {'serial':"UBOM%s_%s" % (serial, yubi_slot),
                     'otpkey':otpkey,
                     'description':description}

            # add the otplen if set as ykparam 
            if ykparams and 'digits' in ykparams:
                submit_param['otplen'] = ykparams['digits']

            if yubi_cr:
                submit_param['type'] = 'TOTP'
                submit_param['timeStep'] = 30

        elif yubi_mode == YUBI_STATIC_MODE:
            password = create_static_password(otpkey)
            #print "otpkey   ", otpkey
            #print "password ", password
            submit_param = {'serial':"UBSM%s_%s" % (serial, yubi_slot),
                     'otpkey':password,
                     'type': "pw",
                     'description':description}

        elif yubi_mode == YUBI_AES_MODE:
            yubi_otplen = 32
            if yubi_prefix_serial:
                yubi_otplen = 32 + len(serial) * 2
            elif yubi_prefix:
                yubi_otplen = 32 + (len(yubi_prefix) * 2)
            elif yubi_prefix_random:
                yubi_otplen = 32 + (yubi_prefix_random * 2)
            # According to http://www.openauthentication.org/oath-id/prefixes/
            # The OMP of Yubico is UB
            # As TokenType we use AM (AES mode)
            submit_param = {'type': 'yubikey',
                   'serial':"UBAM%s_%s" % (serial, yubi_slot),
                   'otpkey':otpkey,
                   'otplen':yubi_otplen,
                   'description':description}

        else:
            print "Unknown Yubikey mode"
            pass
        if 'realm' in proc_params:
            submit_param['realm'] = proc_params.get('realm')
        r1 = lotpc.inittoken(submit_param)
        showresult(r1)


def cifs_push(config, text):
    '''
    Push the the data text to a cifs share

    :param config: dictionary with the fields cifs_server, cifs_share, cifs_dir, cifs_user, cifs_password
    :type config: dict
    :param text: text to be pushed to the windows share
    :type text: string

    '''
    ret = False
    err = ""
    FILENAME = datetime.datetime.now().strftime("/tmp/%y%m%d-%H%M%S_linotpadm.out")
    f = open(FILENAME, 'w')
    f.write(text)
    f.close()

    filename = os.path.basename(FILENAME)

    print "Pushing %s to %s//%s/%s" % (filename,
                                       config.get("cifs_server"),
                                       config.get("cifs_share", ""),
                                       config.get("cifs_dir"))

    args = ["smbclient", "//%s\\%s" % (config.get("cifs_server"), config.get("cifs_share", "")),
            "-U", "%s%%%s" % (config.get("cifs_user"), config.get("cifs_password")), "-c",
            "put %s %s\\%s" % (FILENAME, config.get("cifs_dir", "."), filename) ]


    p = subprocess.Popen(args, cwd=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    (result, error) = p.communicate()
    rcode = p.returncode
    print result
    print error

    try:
        os.remove(FILENAME)
    except Exception, e:
        print ("couldn't remove push test file: %r" % e)


def sendmail(config, text):
    '''
    Send an email with the text

    :param config: dictionary with the fields mail_from, mail_to, mail_host, mail_subject
    :type config: dict
    :param text: text to be sent via mail
    :type text: string

    '''
    if not config.get("mail_to"):
        Exception("mail_to required!")

    if not config.get("mail_host"):
        Exception("mail_host required!")

    print "sending mail to %s" % config.get("mail_to")
    msg = MIMEText(text)
    sender = config.get("mail_from")
    recipient = config.get("mail_to")
    msg['Subject'] = config.get("mail_subject")
    msg['From'] = sender
    msg['To'] = recipient

    s = smtplib.SMTP(config.get("mail_host"))
    s.sendmail(sender, [recipient], msg.as_string())
    s.quit()


def read_config(config_file):
    '''
    Read the configuration/parameters from a config file
    '''
    cfg = ConfigParser.SafeConfigParser()
    cfg_dict = {}
    cfg.read(config_file)
    for key, value in cfg.items("Default"):
        cfg_dict[key] = value

    return cfg_dict


##### main

def main():
    config = {
              "host" : None,
              "command" : None,
              "file" : None,
              "admin" : None,
              "password" : None,
              "disable_ssl_certificate_validation": False,
              "param" : {},
              "etng" : False,
              "pytoken" : False,
              "certificate" : None,
              "key" : None,
              "protocol" : "http",
              "authtype" : "Digest",
              "yubi_prefix" : None,
              "yubi_prefix_random" : 0,
              "yubi_mode" : YUBI_OATH_MODE,
              "yubi_slot" : 1,
              "yubi_prefix_serial" : False,
              "yubi_cr" : False,
              "realm": None,
              "csv" : False,
              "export_fields" : None,
              "mail_from" : "linotp@localhost",
              "mail_to" : None,
              "mail_subject" : "LinOTP notification",
              "mail_host" : None
    }
    config_file = None
    _ask_password = None

    try:
        opts, args = getopt(sys.argv[1:], "hvxU:a:C:k:c:f:u:s:p:d:ew:t:w:m:H:r:",
                ["help", "version", "disable_ssl_certificate_validation", "url=", "admin=", "cert=", "key=", "command=", "file=",
                "user=", "serial=", "pin=", "otpkey=", "description=", "etng", "maxfailcount=",
                "syncwindow=", "otplen=", "otp1=", "otp2=", "pytoken", "type=", "otppin=",
                "config=",
                'realm=', 'resolver=', 'rtype=',
                'module=',
                'label=', 'authtype=',
                'yubiprefix=', 'yubiprefixrandom=', 'yubimode=', 'yubislot=',
                'yubiprefixserial', 'yubiCR',
                'password=', 'csv', 'export_fields=',
                'automate=', 'realm='] + file_opts + ldap_opts)

    except GetoptError:
        print "There is an error in your parameter syntax:"
        usage()
        sys.exit(1)

##### Creating Parameter list
    param = {}

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit(0)
        elif opt in ('-x', '--disable_ssl_certificate_validation'):
            config['disable_ssl_certificate_validation'] = True
        elif opt in ('-U', '--url'):

            if arg.startswith('https://'):
                config["protocol"] = "https"
                config["host"] = arg[8:].rstrip('/')
            elif arg.startswith('http://'):
                config["protocol"] = "http"
                config["host"] = arg[7:].rstrip('/')
            else:
                print "Malformed url format. You need to start with http or https [" + arg + "]"
                sys.exit(1)

        elif opt in ('-a', '--admin'):
            config["admin"] = arg
            if _ask_password is None:
                # if _ask_password is already set to false, since it was specified, we must not set it
                _ask_password = True
        elif opt in ('--password'):
            config["password"] = arg
            _ask_password = False
        elif opt in ('-c', '--cert'):
            config["certificate"] = arg
        elif opt in ('-k', '--key'):
            config["key"] = arg
        elif opt in ('-C', '--command'):
            config["command"] = arg
        elif opt in ('-f', '--file'):
            config["file"] = arg
        # user, serial (needed for assigntoken)
        elif opt in ('-u', '--user'):
            param['user'] = arg
        elif opt in ('-s', '--serial'):
            param['serial'] = arg
        # pin, hmac, description (needed for inittoken)
        elif opt in ('-p', '--pin'):
            param['pin'] = arg
        elif opt in ('-H', '--otpkey'):
            param['otpkey'] = arg
        elif opt in ('-m', '--maxfailcount'):
            param['maxfailcount'] = arg
        elif opt in ('-w', '--window'):
            param['syncwindow'] = arg
        elif opt in ('--otplen'):
            param['otplen'] = arg
        elif opt in ('--otp1'):
            param['otp1'] = arg
        elif opt in ('--otp2'):
            param['otp2'] = arg
        elif opt in ('-d', '--description'):
            param['description'] = arg
        elif opt in ('--label'):
            param['label'] = arg
        elif opt in ('--etng'):
            if EDITION == "ETNG":
                config["etng"] = True
        elif opt in ('--pytoken'):
            config["pytoken"] = True
        elif opt in ('-t', '--type'):
            param['type'] = arg
        elif opt in ('--otppin'):
            param['otppin'] = arg
        elif opt in ('-v', '--version'):
            print "linotpadm.py " + __version__
            sys.exit(0)
        elif opt in ('--config'):
            key, value = arg.rsplit('=', 2)
            param[key] = value
        elif opt in ('--realm'):
            param['realm'] = arg
        elif opt in ('--resolver'):
            param['resolver'] = arg
        elif opt in ('--rtype'):
            param['rtype'] = arg

        elif opt in ('--rf_file'):
            param['rf_file'] = arg
        elif opt in ('--authtype'):
            config["authtype"] = arg
        elif opt in ('--module='):
            param['module'] = arg
        elif opt in ('--yubiprefix='):
            config["yubi_prefix"] = arg
        elif opt in ('--yubiprefixrandom='):
            config["yubi_prefix_random"] = int(arg)
        elif opt in ('--yubimode='):
            if arg.lower() == "yubico":
                config["yubi_mode"] = YUBI_AES_MODE
            elif arg.lower() == "static":
                config["yubi_mode"] = YUBI_STATIC_MODE
            elif arg.lower() == "oath":
                config["yubi_mode"] = YUBI_OATH_MODE
            else:
                print "No matching yubimode. Using OATH as default."
        elif opt in ('--yubislot='):
            config["yubi_slot"] = int(arg)
        elif opt in ('--yubiprefixserial'):
            config["yubi_prefix_serial"] = True
        elif opt in ('--yubiCR'):
            config["yubi_cr"] = True

        elif opt in ('--csv'):
            config["csv_format"] = True
        elif opt in ('--export_fields='):
            config["export_fields"] = arg
        elif opt in ('--automate='):
            config_file = arg
        elif opt in ('--realm='):
            param["realm"] = arg


        for l_opt in ldap_opts:
            o = l_opt.split('=')
            if opt in ("--%s" % o[0]):
                param[o[0]] = arg

    if _ask_password:
        config["password"] = getpass.getpass(prompt="Please enter password "
                                             "for '%s':" % config["admin"])

    if config_file:
        config_from_file = read_config(config_file)
        config.update(config_from_file)

    if not (config["host"] and config["command"]):
        print "Missing arguments. See --help"
        usage()
        sys.exit(0)

    if config["command"] not in COMMANDS:
        print "Unknown command. See --help"
        usage()
        sys.exit(0)

    # Create the linotpclient instance
    lotpc = linotpclient(config.get("protocol"),
                         config.get("host"),
                         admin=config.get("admin"),
                         adminpw=config.get("password"),
                         cert=config.get("certificate"),
                         key=config.get("key"),
                         disable_ssl_certificate_validation=
                            config.get('disable_ssl_certificate_validation',
                            False),
                         authtype=config.get("authtype"))

##### The commands

    if (config.get("command") == "listtoken"):
        # At the moment we support the export to cifs share or sending by mail
        # for the command "listtoken". As fallback the listtoken result is
        # written to stderr, so that it could be redirected to a dedicated file
        # TODO: csv output to file
        if config.get("csv_format"):
            param['outform'] = 'csv'
            if config.get("export_fields"):
                param['user_fields'] = config.get("export_fields")
            r1 = lotpc.connect('/admin/show', {}, param, json_format=False)
            if config.get("mail_host") and config.get("mail_to"):
                sendmail(config, r1)
            elif config.get("cifs_server") and config.get("cifs_user") and config.get("cifs_password"):
                cifs_push(config, r1)
            else:
                sys.stderr.write(r1)
        else:
            r1 = lotpc.listtoken(param)
            result = r1['result']

            tabsize = [4, 25, 40, 25, 20, 4, 4, 4, 4]
            tabstr = ["%4s", "%16s", "%12s", "%20s", "%20s", "%4s", "%4s", "%4s", "%4s", "%4s"]
            tabdelim = '|'
            tabvisible = [0, 1, 2, 3, 4, 5, 6, 7, 8]
            tabhead = ['Id', 'Desc', 'S/N', 'User', 'Resolver', 'MaxFail', 'Active', 'FailCount', 'Window']
            tabentry = ['LinOtp.TokenId',
                         'LinOtp.TokenDesc',
                         'LinOtp.TokenSerialnumber',
                         'User.username',
                         'LinOtp.IdResClass',
                         'LinOtp.MaxFail',
                         'LinOtp.Isactive',
                         'LinOtp.FailCount',
                         'LinOtp.SyncWindow']
            dumpresult(result['status'], result['value']['data'], { 'tabsize' : tabsize, 'tabstr' : tabstr,
                        'tabdelim' : tabdelim, 'tabvisible': tabvisible,
                        'tabhead' : tabhead, 'tabentry' : tabentry })
    elif (config.get("command") == "listuser"):
        r1 = lotpc.userlist({'username':'*'})
        result = r1['result']
        tabentry = ['username',
                     'surname',
                     'userid',
                     'phone',
                     'mobile',
                     'email',
                     ]
        tabsize = [20, 20, 20, 20, 20, 20]
        tabstr = ["%20s", "%20s", "%20s", "%20s", "%20s", "%20s"]
        tabdelim = '|'
        tabvisible = [0, 1, 2, 3, 4, 5]
        tabhead = ['login', 'surname', 'Id', 'phone', 'mobile', 'email']
        dumpresult(result['status'], result['value'], { 'tabsize' : tabsize, 'tabstr' : tabstr,
                    'tabdelim' : tabdelim, 'tabvisible': tabvisible,
                    'tabhead' : tabhead, 'tabentry' : tabentry })
    elif (config.get("command") == "getconfig"):
        r1 = lotpc.readserverconfig({})
        showresult(r1)
    elif (config.get("command") == "setconfig"):
        print param
        r1 = lotpc.writeserverconfig(param)
        showresult(r1)
    elif (config.get("command") == "assigntoken"):
        if 'user' not in param or 'serial' not in param :
            print "To assign a token, we need a username and a tokenserial:"
            print "   --command=assigntoken --user=<username> --serial=<tokenserial>"
            sys.exit(1)
        r1 = lotpc.assigntoken(param)
        showresult(r1)
    elif (config.get("command") == "unassigntoken"):
        if 'serial' not in param :
            print "To unassign a token, we need a tokenserial:"
            print "   --command=unassigntoken --serial=<tokenserial>"
            sys.exit(1)
        r1 = lotpc.unassigntoken(param)
        showresult(r1)
    elif (config.get("command") == "yubikey_mass_enroll"):
        yubi_mass_enroll(lotpc, param,
                         config.get("yubi_mode"),
                         config.get("yubi_slot"),
                         config.get("yubi_prefix_serial"),
                         config.get("yubi_prefix"),
                         config.get("yubi_prefix_random"),
                         config.get("yubi_cr"),
                         )


    elif (config.get("command") == "etokenng_mass_enroll"):
        print "Mass-Enrolling eToken NG OTP. Beware the tokencontents of all tokens will be deleted."
        print "Random User PINs and SO-PINs will be set. The SO-PIN will be stored in the Token-Database."
        print
        while 0 == 0:
            answer = raw_input("Please insert the next eToken NG and press enter (x=Exit): ")
            if "x" == answer.lower():
                break
            tokenlabel = param.get('label', "LinOTPToken")
            description = param.get('description', 'eTokenNG mass enrolled')
            tdata = initetng({ 'label': tokenlabel, 'debug' : False,
                               'description' : description })
            if not tdata['userpin']  or not tdata['hmac'] or not tdata['serial']:
                print "No token was added to LinOTP:", tdata['error']
                sys.exit(1)
            param['serial'] = tdata['serial']
            param['otpkey'] = tdata['hmac']
            param['userpin'] = tdata['userpin']
            param['sopin'] = tdata['sopin']
            r1 = lotpc.inittoken(param)
            showresult(r1)

    elif (config.get("command") == "inittoken"):
        if etng:
            tokenlabel = param.get('user', param.get('label', "LinOTPeToken"))
            tdata = initetng({ 'label': tokenlabel, 'debug' : True })
            if not tdata['userpin']  or not tdata['hmac'] or not tdata['serial']:
                print "No token was added to LinOTP:", tdata['error']
                sys.exit(1)
            param['serial'] = tdata['serial']
            param['otpkey'] = tdata['hmac']
            param['userpin'] = tdata['userpin']
            param['sopin'] = tdata['sopin']
            print "FIXME: what shall we do with the eToken password and SO PIN:", tdata['userpin'], tdata['sopin']
        elif config.get("pytoken"):
            if 'user' not in param:
                print "To initialize a pyToken, please provide a username"
                sys.exit(1)
            pyTemplate = "FAIL"
            pyTemplateList = ('pytoken.template.py',
                    '/usr/share/pyshared/linotpadminclientcli/pytoken.template.py',
                    '/usr/local/lib/python2.6/dist-packages/linotpadminclientcli/pytoken.template.py',
                    '/usr/lib/python2.6/dist-packages/linotpadminclientcli/pytoken.template.py',
                )
            for pT in pyTemplateList:
                if os.path.isfile(pT):
                    pyTemplate = pT
                    break
            if pyTemplate == "FAIL":
                print "Could not find any pytoken template!"
                sys.exit(1)
            else:
                pyTok = pyToken(keylen=256, template=pyTemplate)
                pyTokenfile = pyTok.createToken(param['user'])
                param['otpkey'] = pyTok.getHMAC()
                param['serial'] = pyTok.getSerial()
                print pyTokenfile
        else:
            if 'user' not in param or 'serial' not in param or 'otpkey' not in param:
                print "To initialize a token, we need at least a username, a tokenserial and an OTPkey/HMAC:"
                print "   --command=inittoken --user=<username> --serial=<tokenserial> --hmac=<HMAC>"
                sys.exit(1)
        r1 = lotpc.inittoken(param)
        showresult(r1)
    elif (config.get("command") == "importtoken"):
        if not file:
            print "To import tokens, we need a filename!"
            sys.exit(1)
        lotpc.importtoken ({ 'file': file })
    elif (config.get("command") == "disabletoken"):
        r1 = lotpc.disabletoken (param)
        showresult (r1)
    elif (config.get("command") == "removetoken"):
        r1 = lotpc.removetoken (param)
        showresult (r1)
    elif (config.get("command") == "enabletoken"):
        r1 = lotpc.enabletoken (param)
        showresult (r1)
    elif (config.get("command") == "resynctoken"):
        r1 = lotpc.resynctoken (param)
        showresult (r1)
    elif (config.get("command") == "set"):
        if 'user' not in param and 'serial' not in param:
            print "Please provide either or user or a serial to set the pin."
            sys.exit(1)
        r1 = lotpc.set(param)
        showresult(r1)
    elif (config.get("command") == "getrealms"):
        r1 = lotpc.getrealms({})
        showresult (r1)
    elif (config.get("command") == "setrealm"):
        if "realm" not in param or "resolver" not in param:
            print "You need to provide a realm and resolvers."
            sys.exit(1)
        param['resolvers'] = param['resolver']
        r1 = lotpc.setrealm(param)
        showresult (r1)
    elif (config.get("command") == "deleterealm"):
        if "realm" not in param:
            print "You need to provide a realm."
            sys.exit(1)
        r1 = lotpc.deleterealm(param)
        showresult (r1)
    elif (config.get("command") == "securitymodule"):
        r1 = {}
        if "module" in param:
            password = getpass.getpass(prompt="Please enter password for security module '%s':" % param["module"])
            print "Setting the password of your security module %s" % param['module']
            r1 = lotpc.securitymodule(param={ "hsm_id" : param["module"],
                                                "password" : str(password) })
        else:
            print "This is the configuration of your active Security module:"
            print
            r1 = lotpc.securitymodule(param={})
        showresult(r1)
    elif (config.get("command") == "setdefaultrealm"):
        if "realm" not in param:
            print "You need to provide a realm."
            sys.exit(1)
        r1 = lotpc.setdefaultrealm(param)
        showresult (r1)
    elif (config.get("command") == "getresolvers"):
        r1 = lotpc.getresolvers({})
        showresult (r1)
    elif (config.get("command") == "deleteresolver"):
        if "resolver" not in param:
            print param
            print "You need to provide a resolver."
            sys.exit(1)
        r1 = lotpc.deleteresolver(param)
    elif (config.get("command") == "setresolver"):
        if not "rtype" in param:
            print "your need to specify a type of the resolver."
            sys.exit(1)
        if param['rtype'] == 'LDAP':
            for opt in ldap_opts:
                o = opt.split('=')
                if o[0] not in param:
                    print "you need to specify --%s for ldap resolvers" % o[0]
                    sys.exit(1)
        elif param['rtype'] == 'SQL':
            print "TODO: SQL parameters not implemented yet"
            sys.exit(1)
        elif param['rtype'] == 'FILE':
            if 'rf_file' not in param:
                print "you need to specify --rf_file!"
                sys.exit(1)
        r1 = lotpc.setresolver(param)
        showresult(r1)
    elif (config.get("command") == "loadtokens"):
        filename = 'plain-value-pskc.xml'
        f = open(filename, 'r')
        xml_data = f.read()
        ret = lotpc.connect("/admin/loadtokens", {},
                    { 'type' : 'pskc',
                        'file' : xml_data,
                        'pskc_type' : 'plain',
                        'pskc_password' : None,
                        'pskc_preshared': None })
        showresult(ret)

    else:
        print "Nothing to do and nothing done."


if __name__ == '__main__':
    main()


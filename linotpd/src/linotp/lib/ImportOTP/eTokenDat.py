# -*- coding: utf-8 -*-
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
"""eToken dat file importer"""

import sys
import datetime
from getopt import getopt, GetoptError
import urllib
import urllib2
import logging
import json
import Cookie
import httplib2
import getpass



LOG = logging.getLogger(__name__)



def parse_datetime(d_string):
    '''
    parse an date string and try to convert it to an datetime object

    :param d_string: date string
    :return: datetime object
    '''

    startdate = None
    fmts = ['%d.%m.%Y+%H:%M', '%d.%m.%Y %H:%M', '%d.%m.%Y %H:%M:%S', '%d.%m.%Y',
            '%Y-%m-%d+%H:%M', '%Y-%m-%d %H:%M', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d']

    if d_string is not None and len(d_string) > 0:
        for fmt in fmts:
            try:
                startdate = datetime.datetime.strptime(d_string, fmt)
                break
            except ValueError:
                startdate = None

    return startdate

def parse_dat_data(data, d_string=None):
    '''
    this function is called from the web-ui and parses an eToken data file

    :param data: data from the web-ui file upload

    :return: It returns a dictionary of serial : { /admin/init parameters }
    '''
    from linotp.lib.ImportOTP  import ImportException

    #the result set
    tokens = {}


    try:
        startdate = parse_datetime(d_string)
        LOG.debug("START SET: %r" % startdate)

        ## collect all token info in an array
        lines = []

        for line in data.splitlines():
            line = line.strip()

            ## if line is empty, we take all already defined lines and
            ## create an token out of it
            if len(line) == 0:
                token = create_token(lines, startdate)
                ## if we get a token, we can preserve this for
                ## later, to store them
                if token is not None:
                    LOG.info("Token parsed: %r" % token)
                    serial = token.serial
                    tokens[serial] = token.get_initparams()
                del lines[:]
            else:
                lines.append(line)

        ## if finally there are lines left, try to create an additional token
        if len(lines) != 0:
            token = create_token(lines, startdate)
            if token is not None:
                LOG.info("Token parsed: %r" % token)
                serial = token.serial
                tokens[serial] = token.get_initparams()
            del lines[:]

    except Exception as err:
        raise ImportException(err)

    return tokens


class DatToken(object):
    '''
     eToken class which is equivalent to the token definition of the dat file
    '''

    def __init__(self):
        '''
        build up the default values
        '''

        ## the init_params are the definitions, which will be forwarded to the
        ## linotp server
        self.init_params = {}

        self.timestep = 30
        self.init_params['timeStep'] = self.timestep

        self.serial = "eToken"
        self.startdate = datetime.datetime(2000, 1, 1)
        # offset direction
        self.odir = -1

    def get_initparams(self):
        """ provide all init definitions """
        return self.init_params

    def set_startdate(self, startdate):
        '''
        put in the startdate after creating the token

        :param startdate: wehen the counter will start counting datetime format

        :return: - nothing -
        '''
        self.startdate = startdate

    def set(self, key, val):
        """
        generic setter, so that no attribute will get lost
        """
        setattr(self, key, val)
        return

    def add_info(self, line):
        """
        parse a config line into a class attribute by calling
        a dedicated or the generic setter for an key value pair

        :param line: config line which belong to one token

        :return: - nothing -
        """

        ## skip coment lines
        if line.startswith('#'):
            return
        ## skip comments at the line end
        if '#' in line:
            (line, _rest) = line.split('#', 2)

        ## the top level definition have a key value separator ':'
        LOG.debug("line: %s" % (line))
        if ':' in line:
            index = line.index(':')
            key = line[:index]
            val = line[index + 1:]
            key = key.strip()
            val = val.strip()

            if hasattr(self, 'set_' + key):
                getattr(self, 'set_' + key)(val)
            else:
                self.set(key, val)
        return

    def set_sccTokenData(self, value):
        """
        parse the detail token definition by calling again
        a specific setter (if exist) or the generic one

        :param line: config line which belong to one token

        :return: - nothing -
        """

        #sccKey=8c281387001e801dc0f5e1f08d0728d3d6dca3ce0febd931cf3374...4891;
        #sccMode=T;
        #sccPwLen=6;
        #sccTick=30;
        #sccPrTime=2011/05/03 02:46:54;
        #crypto=HmacSHA256;
        #sccVer=6.2;
        params = value.split(';')
        for param in params:
            if '=' in param:
                (key, val) = param.split('=')

                ## again call a secific attribute or generic setter
                if hasattr(self, 'set_' + key):
                    getattr(self, 'set_' + key)(val)
                else:
                    self.set(key, val)
        return

    ## below: more or less generic setters
    def set_sccAuthenticatorId(self, value):
        """
        take the sccAuthenticatorId for serial number

        :param value: value of the setter
        :return: - nothing -
        """
        self.serial = value
        self.init_params['serial'] = value
        return

    def set_sccTokenType(self, value):
        """
        take the sccTokenType as part of the token description

        :param value: value of the setter
        :return: - nothing -
        """

        if self.init_params.has_key('description'):
            value = self.init_params.get('description') + ' ' + value
        self.init_params['description'] = value
        return


    def set_sccTick(self, value):
        """
        take the sccTick as timeStep value

        :param value: value of the setter
        :return: - nothing -
        """

        self.timestep = int(value)
        self.init_params['timeStep'] = int(value)
        return

    def set_sccPwLen(self, value):
        """
        take the sccPwLen as otplen value

        :param value: value of the setter
        :return: - nothing -
        """
        self.init_params['otplen'] = int(value)
        return

    def set_sccPrTime(self, value):
        '''
        if the token definition hat this attribute, we can assume
        that we have a timebased eToken, which starts its counter
        which starts the timecount with 1.1.2000 and not in 1.1.1970
        as defined in the standard. So we have to set an offsett of 30 years

        :param value: value of the setter
        :return: - nothing -
        '''

        ## calculate the time delta into counter ticks
        counter = self.startdate.strftime("%s")
        LOG.debug("COUNTER %r " % counter)
        self.init_params['timeShift'] = self.odir * int(counter)

        ## the value e.g. 2011/05/03 02:46:54;, will be appended
        ## to the token description

        if self.init_params.has_key('description'):
            value = self.init_params.get('description') + ' ' + value
        self.init_params['description'] = value
        return

    def set_sccMode(self, value):
        """
        setter, if the token is counter based or event based

        :param value: value of the setter
        :return: - nothing -
        """

        typ = 'hmac'
        if value.upper() == 'T':
            typ = 'totp'
        elif value.upper() == 'E':
            typ = 'hmac'

        self.init_params['type'] = typ


    def set_sccKey(self, val):
        """
        set up the secret key

        :param value: value of the setter
        :return: - nothing -
        """
        self.init_params['otpkey'] = val

    def set_crypto(self, val):
        """
        setter of the hash lib

        :param value: value of the setter
        :return: - nothing -
        """
        if val == 'HmacSHA256':
            self.init_params['hashlib'] = 'sha256'
        return

    def __repr__(self):
        rep = "<eToken %s>" % self.init_params
        return rep

def create_token(lines, startdate=None):
    """
    take an array of lines and create a token out of it

    remark: the lines are split up on the caller level

    :param lines:
    """
    token = None
    for line in lines:
        if line.startswith('#'):
            continue
        if token == None:
            token = DatToken()
            if startdate is not None:
                token.set_startdate(startdate)
        token.add_info(line)
    return token

def get_session(lino_url, user=None, pwd=None):
    '''
    return an LinOTP Session context, which is
    the session and the cookie in the header

    :param lino_url: the linotp base url
    :param user: the session for the user
    :param pwd: the password of the user

    :return: tuple of session and header
    '''

    http = httplib2.Http(disable_ssl_certificate_validation=True)

    session = None
    if user != None:
        url = lino_url + 'admin/getsession'
        http.add_credentials(user, pwd)
        resp, content = http.request(url, 'POST')

        LOG.debug("response %r:\n Content:\n%s" % (resp, content))
        if resp['status'] != '200':
            LOG.error('Admin login failed: %r' % resp)
            sys.exit(1)

        try:
            session = \
               Cookie.SimpleCookie(resp['set-cookie'])['admin_session'].value
        except Exception as exception:
            LOG.error('Konnte keine Session holen: %r' % exception)
            raise exception

    ## add headers, as they transefer the cookies
    headers = {}
    if session is not None:
        headers['Cookie'] = resp['set-cookie']
        LOG.debug('session: %r' % session)

    return (session, headers)

def submit_tokens(lino_url, tokens, user=None, pwd=None):
    """
    submit an /admin/init request to create the token
    in the linotp server

    :param linotp_url: the url, where linotp resides
    :param tokens: the array of tokens
    :param user: the admin user -required to get a session
    :param pwd: the admin password -required to get a session

    """
    http = httplib2.Http(disable_ssl_certificate_validation=True)

    (session, headers) = get_session(lino_url, user=user, pwd=pwd)

    for token in tokens:
        # Prepare the data
        query_args = token.get_initparams()
        if session is not None:
            query_args['session'] = session
        data = urllib.urlencode(query_args)

        try:
            # Send HTTP GET request
            url = lino_url + "admin/init?" + data
            http.add_credentials(user, pwd)
            resp, content = http.request(url, headers=headers)

        except urllib2.HTTPError as http_error:
            LOG.error("%r: %s" % (http_error, http_error.code))
            break

        LOG.debug("%s" % content)

        if resp['status'] == '200':
            res = json.loads(content)
            suc = res.get('result').get("value")

            LOG.info("Storing %s: %r" % (query_args.get('serial'), suc))
            if suc is False:
                LOG.error("%s" % content)
        else:
            # Print response
            LOG.error("Response:%r\nContent:\n%s" % (resp, content))

    return

def process_file(filename, startdate, lino_url=None, user=None, password=None):
    """
    read the eToken dat file and split it up into a bunch
    of lines, that define one token. An empty line is considered
    as separator.

    :param filename: the eToken dat file
    :param lino_url: if defined, the tokens will be created in linotp
    """

    tokens = []
    lines = []

    fil = file(filename, "r")
    for line in fil:
        line = line.strip()

        ## if line is empty, we take all already defined lines and
        ## create an token out of it
        if len(line) == 0:
            token = create_token(lines, startdate)
            ## if we get a token, we can preserve this for
            ## later, to store them
            if token is not None:
                LOG.info("Token parsed: %r" % token)
                tokens.append(token)
            del lines[:]
        else:
            lines.append(line)
    fil.close()

    ## if finally there are lines left, try to create an additional token
    if len(lines) != 0:
        token = create_token(lines, startdate)
        if token is not None:
            LOG.info("Token parsed: %r" % token)
            tokens.append(token)
        del lines[:]

    ## finally create tokens in the LinOTP
    if lino_url != None:
        submit_tokens(lino_url, tokens, user=user, pwd=password)

    return

def main():
    '''
    main - parse the args and start the processing
    '''
    try:
        opts, _args = getopt(sys.argv[1:], "hdc:f:u:s:",
                ["help", "debug", "create", "file", "user",
                 "startdate"])

    except GetoptError:
        print "There is an error in your parameter syntax:"
        usage()
        sys.exit(1)

    ## initialize parameters
    url = None
    filename = None
    user = None
    password = None
    startdate = datetime.datetime(2000, 1, 1)

    for opt, arg in opts:

        if opt in ('-h', '--help'):
            usage()
            sys.exit(0)

        elif opt in ('-c', '--create'):
            url = arg

        elif opt in ('-f', "--file"):
            filename = arg

        elif opt in ('-d', "--debug"):
            LOG.setLevel(logging.DEBUG)

        elif opt in ('-u', "--user"):
            user = arg
            password = getpass.getpass()

        elif opt in ('-s', "--startdate"):
            d_string = arg
            startdate = parse_datetime(d_string)
            LOG.debug("START SET: %r" % startdate)


    if filename is None:
        print ("Missing token filename parameter!")
        usage()
        sys.exit(1)

    process_file(filename, startdate=startdate, lino_url=url,
                 user=user, password=password)

    return

def usage():
    """
    print usage message
    """

    usage_def = """
    importDat - eToken dat file importer

    -f, --file <name>   : define the to be loaded file
    -c, --create <url>  : upload all tokens to the LinOTP url (optional)
    -d, --debug         : print debug output
    -u, --user <usename>: user to create the admin session for admin/init
    -s, --startdate <date>: Counter start date '%d.%m.%Y+%H:%M' or '%d.%m.%Y'

    """

    print usage_def

if __name__ == '__main__':
    LOG = logging.getLogger()
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

    main()


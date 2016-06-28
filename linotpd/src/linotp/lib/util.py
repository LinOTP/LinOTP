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
""" contains utility functions """

import binascii
import string
import re
from datetime import timedelta
import logging
import netaddr
import logging

from pylons import config
from pylons.controllers.util import abort

from linotp.lib.crypt import (urandom,
                              geturandom
                              )

from linotp.lib.selftest import isSelfTest
from linotp.lib.error import ParameterError
from linotp.lib.config import getFromConfig

from linotp import (__version__ as linotp_version,
                    __copyright__ as linotp_copyright,
                    __product__ as linotp_product,
                    )

try:
    from linotp import __api__ as linotp_api
except ImportError:
    linotp_api = 2.0

SESSION_KEY_LENGTH = 32
hostname_regex = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
duration_regex = re.compile(r'((?P<hours>\d+?)h)?((?P<minutes>\d+?)m)?'
                   '((?P<seconds>\d+?)s)?')

log = logging.getLogger(__name__)

optional = True
required = False


def get_api_version():
    '''
    return the api version number
    '''
    return linotp_api

def get_version_number():
    '''
    returns the linotp version
    '''
    return linotp_version


def get_version():
    '''
    This returns the version, that is displayed in the WebUI and
    self service portal.
    '''
    return "%s %s" % (linotp_product, linotp_version)


def get_copyright_info():
    '''
    This returns the copyright information displayed in the WebUI
    and selfservice portal.
    '''
    return linotp_copyright


def getParam(param, which, optional=True):
    """
    getParam()
    input:
     - param (hash set): the set, which contains all parameters
     - which (lteral): the entry lookup
     - optional (boolean): defines if this parameter is optional or not
                 - an exception is thrown if the parameter is required
                 - otherwise: nothing done!

    return:
     - the value (literal) of the parameter if exists or nothing
       in case the parameter is optional, otherwise throw an exception
    """
    ret = None

    if which in param:
        ret = param[which]
    else:
        if (optional is False):
            raise ParameterError("Missing parameter: %r" % which, id=905)

    return ret


def getLowerParams(param):
    ret = {}
    for key in param:
        lkey = key.lower()
        # strip the session parameter!
        if "session" != lkey:
            lval = param[key]
            ret[lkey] = lval
            log.debug("[getLowerParams] Parameter key:%s=%s", lkey, lval)
    return ret


def uniquify(doubleList):
    # uniquify the realm list
    uniqueList = []
    for e in doubleList:
        if e.lower() not in uniqueList:
            uniqueList.append(e.lower())

    return uniqueList


def generate_otpkey(key_size=20):
    '''
    generates the HMAC key of keysize. Should be 20 or 32
    THe key is returned as a hexlified string
    '''
    log.debug("generating key of size %s" % key_size)
    return binascii.hexlify(geturandom(key_size))


def generate_password(size=6, characters=None):
    if not characters:
        characters = string.ascii_lowercase + \
                     string.ascii_uppercase + string.digits

    return ''.join(urandom.choice(characters) for _x in range(size))


def check_session(request):
    '''
    This function checks the session cookie for management API
    and compares it to the session parameter
    '''
    if isSelfTest():
        return

    # check if the client is in the allowed IP range
    no_session_clients = []
    for no_session_client in config.get("linotpNoSessionCheck", "").split(","):
        no_session_clients.append(no_session_client.strip())

    client = request.environ.get('REMOTE_ADDR', None)
    log.debug("[check_session] checking %s in %s"
              % (client, no_session_clients))
    for network in no_session_clients:
        if not network:
            continue
        try:
            if netaddr.IPAddress(client) in netaddr.IPNetwork(network):
                log.debug("skipping session check since client"
                          " %s in allowed: %s" % (client, no_session_clients))
                return
        except Exception as ex:
            log.warning("misconfiguration in linotpNoSessionCheck: "
                        "%r - %r" % (network, ex))

    if request.path.lower() == '/admin/getsession':
        log.debug('[check_session] requesting a new session cookie')
    else:
        cookie = request.cookies.get('admin_session')
        session = request.params.get('session')
        # doing any other request, we need to check the session!
        log.debug("[check_session]: session: %s" % session)
        log.debug("[check_session]: cookie:  %s" % cookie)
        if session is None or session == "" or session != cookie:
            log.error("The request did not pass a valid session!")
            abort(401, "You have no valid session!")
            pass


def check_selfservice_session(cookies=None, params=None, url=None):
    '''
    This function checks the session cookie for the
    selfservice / userservice session
    '''
    cookie = cookies.get('linotp_selfservice', '').strip('"')
    session = params.get('session', '').strip('"')

    log.debug("session: %r" % session)
    log.debug("cookie:  %r" % cookie)

    if not session or not cookie:
        log.warning("failed to check selfservice session")
        return False

    if session[:40] != cookie[:40]:
        log.error("The request %r did not pass a valid session!" % url)
        return False

    return True


def remove_session_from_param(param):
    '''
    Some low level functions like the userlisting do not like to have a
    session parameter in the param dictionary.
    So we remove the session from the params.
    '''
    return_param = {}
    for key in param.keys():
        if "session" != key.lower():
            return_param[key] = param[key]

    return return_param


###############################################################################
# Client overwriting stuff
def _get_client_from_request(request=None):
    '''
    This function returns the client as it is passed in the HTTP Request.
    This is the very HTTP client, that contacts the LinOTP server.
    '''

    client = request.environ.get('REMOTE_ADDR',
                                 request.environ.get('HTTP_REMOTE_ADDR', None))

    x_forwarded_for = config.get('client.X_FORWARDED_FOR', '')
    if x_forwarded_for.lower().strip() == 'true':
        # check, if the request passed by a qualified proxy
        remote_addr = request.environ.get('REMOTE_ADDR', None)
        x_forwarded_proxy = config.get('client.FORWARDED_PROXY', None)
        if x_forwarded_proxy and x_forwarded_proxy == remote_addr:
            ref_clients = request.environ.get('HTTP_X_FORWARDED_FOR', '')
            for ref_client in ref_clients.split(','):
                # the first ip in the list is the originator
                client = ref_client.strip()
                break

    #"Forwarded" Header
    #
    # In 2014 RFC 7239 standardized a new Forwarded header with similar purpose
    # but more features compared to XFF.[28] An example of a Forwarded header
    # syntax:
    #
    # Forwarded: for=192.0.2.60; proto=http; by=203.0.113.43

    forwarded = config.get('client.FORWARDED', '')
    if forwarded.lower().strip() == 'true':
        # check, if the request passed by a qaulified proxy
        remote_addr = request.environ.get('REMOTE_ADDR', None)
        forwarded_proxy = config.get('client.FORWARDED_PROXY', None)
        if forwarded_proxy and forwarded_proxy == remote_addr:
            # example is:
            # "Forwarded: for=192.0.2.43, for=198.51.100.17"
            entries = request.environ.get('HTTP_FORWARDED', '')
            forwarded_dict = {}
            entries = entries.replace("Forwarded:", "")
            for entry in entries.split(';'):
                key, value = entry.split('=', 1)
                forwarded_dict[key.strip().lower()] = value.strip()
            if 'for' in forwarded_dict:
                client = forwarded_dict.get('for')
                # support for multiple 'for' format
                # but we only take the first client
                if 'for' in client and ',' in client:
                    client = client.split(',', 1)[0]

    log.debug("got the client %s" % client)
    return client


def get_client(request):
    '''
    This function returns the client.

    It first tries to get the client as it is passed as the HTTP Client
    via REMOTE_ADDR.

    If this client Address is in a list, that is allowed to overwrite its
    client address (like e.g. a FreeRADIUS server, which will always pass the
    FreeRADIUS address but not the address of the RADIUS client) it checks for
    the existance of the client parameter.
    '''
    may_overwrite = []
    over_client = getFromConfig("mayOverwriteClient", "")
    log.debug("config entry mayOverwriteClient: %s" % over_client)
    try:
        may_overwrite = [c.strip() for c in over_client.split(',')]
    except Exception as e:
        log.warning("evaluating config entry 'mayOverwriteClient': %r" % e)

    client = _get_client_from_request(request)
    log.debug("got the original client %s" % client)

    params = {}
    params.update(request.params)
    if client in may_overwrite or client is None:
        log.debug("client %s may overwrite!" % client)
        if "client" in params:
            client = params["client"]
            log.debug("client overwritten to %s" % client)

    log.debug("returning %s" % client)
    return client


def normalize_activation_code(activationcode, upper=True, convert_o=True,
                              convert_0=True):
    '''
    This normalizes the activation code.
    1. lower letters are capitaliezed
    2. Oh's in the last two characters are turned to zeros
    3. zeros before the last 2 characters are turned to Ohs
    '''
    if upper:
        activationcode = activationcode.upper()
    if convert_o:
        activationcode = activationcode[:-2] + \
                         activationcode[-2:].replace("O", "0")
    if convert_0:
        activationcode = activationcode[:-2].replace("0", "O") + \
                         activationcode[-2:]

    return activationcode


def is_valid_fqdn(hostname, split_port=False):
    '''
    Checks if the hostname is a valid FQDN
    '''
    if split_port:
        hostname = hostname.split(':')[0]
    if len(hostname) > 255:
        return False
    # strip exactly one dot from the right, if present
    if hostname[-1:] == ".":
        hostname = hostname[:-1]

    
    return all(hostname_regex.match(x) for x in hostname.split("."))


def remove_empty_lines(doc):
    '''
    remove empty lines from the input document

    :param doc: documemt containing long multiline text
    :type  doc: string

    :return: data without empty lines
    :rtype:  string
    '''
    data = '\n'.join([line for line in doc.split('\n') if line.strip() != ''])
    return data

##
## Modhex calculations for Yubikey
##
hexHexChars = '0123456789abcdef'
modHexChars = 'cbdefghijklnrtuv'

hex2ModDict = dict(zip(hexHexChars, modHexChars))
mod2HexDict = dict(zip(modHexChars, hexHexChars))


def modhex_encode(s):
    return ''.join(
        [hex2ModDict[c] for c in s.encode('hex')]
    )
# end def modhex_encode


def modhex_decode(m):
    return ''.join(
        [mod2HexDict[c] for c in m]
    ).decode('hex')
# end def modhex_decode


def checksum(msg):
    crc = 0xffff
    for i in range(0, len(msg) / 2):
        b = int(msg[i * 2] + msg[(i * 2) + 1], 16)
        crc = crc ^ (b & 0xff)
        for _j in range(0, 8):
            n = crc & 1
            crc = crc >> 1
            if n != 0:
                crc = crc ^ 0x8408
    return crc


def str2unicode(input_str):
    """
    convert as binary string into a unicode string by trying various encodings
    :param input_str: input binary string
    :return: unicode output
    """

    output_str = input_str
    conversions = [{},
                   {'encoding':'utf-8'},
                   {'encoding':'iso-8859-1'},
                   {'encoding':'iso-8859-15'}
                   ]
    for param in conversions:
        try:
            output_str = unicode(input_str, **param)
            break
        except UnicodeDecodeError as exx:
            if param == conversions[-1]:
                log.info('no unicode conversion found for %r' % input_str)
                raise exx

    return output_str


def unicode_compare(x, y):
    """
    locale and unicode aware comparison operator - for usage in sorted()

    :param x: left value
    :param y: right value
    :return: the locale aware comparison result
    """
    return cmp(str2unicode(x), str2unicode(y))



def dict_copy(dict_):

    """ recursively copies a dict """

    # we use an recursive approach instead of an
    # iterative one, because our dicts are only
    # 3 to 4 levels deep.

    copy = {}
    for key, value in dict_.iteritems():
        if isinstance(value, dict):
            fragment = {key: dict_copy(value)}
        else:
            fragment = {key: value}
        copy.update(fragment)
    return copy


def parse_duration(duration_str):
    """
    transform a duration string into a time delta object

    from:
        http://stackoverflow.com/questions/35626812/how-to-parse-timedelta-from-strings

    :param duration_str:  duration string like '1h' '3h 20m 10s' '10s'
    :return: timedelta
    """
    # remove all white spaces for easier parsing
    duration_str = ''.join(duration_str.split())

    parts = duration_regex.match(duration_str.lower())
    if not parts:
        return
    parts = parts.groupdict()
    time_params = {}
    for (name, param) in parts.iteritems():
        if param:
            time_params[name] = int(param)

    return timedelta(**time_params)

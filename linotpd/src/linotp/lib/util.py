# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
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
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#
""" contains utility functions """

import binascii
import string
import re

import netaddr

import logging
import secrets

from linotp.flap import config, abort

from linotp.lib.crypto.utils import geturandom

from linotp.lib.error import ParameterError
from linotp.lib.error import InvalidFunctionParameter
from linotp.lib.config import getFromConfig

from linotp.lib.type_utils import boolean
from linotp.lib.type_utils import get_ip_network
from linotp.lib.type_utils import get_ip_address

from linotp import (__version__ as linotp_version,
                    __copyright__ as linotp_copyright,
                    __product__ as linotp_product,
                    )

from linotp import __api__ as linotp_api


SESSION_KEY_LENGTH = 32
hostname_regex = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

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

def  get_request_param(request, key, default=None):
    """
    Returns the get / post / etc. param with the given key dependent on
    the content type
    """

    if request.is_json:
        return request.json.get(key, default)
    else:
        return request.values.get(key, default)

def getLowerParams(param):
    ret = {}
    for key in param:
        lkey = key.lower()
        # strip the session parameter!
        if "session" != lkey:
            lval = param[key]
            ret[lkey] = lval
    return ret


def uniquify(doubleList):
    # uniquify the realm list
    uniqueList = []
    for e in doubleList:
        if e.lower() not in uniqueList:
            uniqueList.append(e.lower())

    return uniqueList


def generate_otpkey(key_size:int = 20) -> str:
    '''
    generates the HMAC key of keysize. Should be 20 or 32
    THe key is returned as a hexlified string
    '''
    log.debug("generating key of size %s" % key_size)
    return geturandom(key_size).hex()


def generate_password(size=6, characters=None):
    if not characters:
        characters = string.ascii_lowercase + \
                     string.ascii_uppercase + string.digits

    return ''.join(secrets.choice(characters) for _x in range(size))


def check_session(request, scope='admin'):
    '''
    This function checks the session cookie and compares it to
    the session parameter

    :param request: the request object
    :param scope: by default the admin scope, but used to as well
                  for the scope helpdesk with the helpdesk_session
                  cookie name

    :return: boolean
    '''

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

    cookie = request.cookies.get(scope + '_session')
    session = get_request_param(request, 'session')
    # doing any other request, we need to check the session!
    log.debug("[check_session]: session: %s" % session)
    log.debug("[check_session]: cookie:  %s" % cookie)
    if session is None or session == "" or session != cookie:
        log.error("The request did not pass a valid session!")
        abort(401, "You have no valid session!")

    cookie = request.cookies.get(scope + '_session')
    session = get_request_param(request, 'session')
    # doing any other request, we need to check the session!
    log.debug("[check_session]: session: %s" % session)
    log.debug("[check_session]: cookie:  %s" % cookie)
    if session is None or session == "" or session != cookie:
        log.error("The request did not pass a valid session!")
        abort(401, "You have no valid session!")

def check_selfservice_session(cookies=None, params=None, url=None):
    '''
    This function checks the session cookie for the
    selfservice / userservice session
    '''
    cookie = cookies.get('linotp_selfservice', '').strip('"')
    session = params.get('session', '').strip('"')

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
    for key in list(param.keys()):
        if "session" != key.lower():
            return_param[key] = param[key]

    return return_param


###############################################################################
# Client overwriting stuff


def _is_addr_in_network(addr, network):
    """
    helper method to check if a client is in the proxy network range

    :param addr: the client address
    :param network: the network range description
    :return: boolean - True if match is given
    """

    ip_network = get_ip_network(network)
    if ip_network is None:
        log.error('no valid ip_network: %r', network)
        return False

    ip_addr = get_ip_address(addr)
    if ip_addr is None:
        log.error('no valid ip_address: %r', addr)
        return False

    return ip_addr in ip_network


def _get_client_from_request(request=None):
    '''
    This function returns the client as it is passed in the HTTP Request.
    This is the very HTTP client, that contacts the LinOTP server.
    '''

    client = request.environ.get(
                    'REMOTE_ADDR', request.environ.get(
                        'HTTP_REMOTE_ADDR', None))

    x_forwarded_for = boolean(config.get(
                        'client.X_FORWARDED_FOR',  getFromConfig(
                            'client.X_FORWARDED_FOR', 'False')))

    if x_forwarded_for:
        # check, if the request passed by a qualified proxy

        remote_addr = client
        x_forwarded_proxies = config.get(
                    'client.FORWARDED_PROXY', getFromConfig(
                        'client.FORWARDED_PROXY', '')).split(',')

        for x_forwarded_proxy in x_forwarded_proxies:
            if _is_addr_in_network(remote_addr, x_forwarded_proxy):

                ref_clients = request.environ.get('HTTP_X_FORWARDED_FOR', '')
                for ref_client in ref_clients.split(','):

                    # the first ip in the list is the originator
                    client = ref_client.strip()
                    break

    # "Forwarded" Header
    #
    # In 2014 RFC 7239 standardized a new Forwarded header with similar purpose
    # but more features compared to XFF.[28] An example of a Forwarded header
    # syntax:
    #
    # Forwarded: for=192.0.2.60; proto=http; by=203.0.113.43

    forwarded = boolean(config.get(
                    'client.FORWARDED', getFromConfig(
                        'client.FORWARDED', 'false')))

    if forwarded:
        # check, if the request passed by a qaulified proxy

        remote_addr = client
        forwarded_proxies = config.get(
                    'client.FORWARDED_PROXY', getFromConfig(
                            'client.FORWARDED_PROXY', '').split(','))

        for forwarded_proxy in forwarded_proxies:
            if _is_addr_in_network(remote_addr, forwarded_proxy):

                # example is:
                # "Forwarded: for=192.0.2.43, for=198.51.100.17"

                entries = request.environ.get(
                    'HTTP_FORWARDED', request.environ.get(
                        'Forwarded', ''))

                forwarded_set = []
                entries = entries.replace("Forwarded:", "")
                for entry in entries.split(','):
                    if entry.lower().startswith('for'):
                        value = entry.split('=')[1]
                        value = value.split(';')[0].strip()
                        if ']' in value:
                            ipvalue = value.split(']')[0].split('[')[1]
                        elif ':' in value:
                            ipvalue = value.split(':')[0]
                        else:
                            ipvalue = value
                        forwarded_set.append(ipvalue.strip('"'))

                for originator in forwarded_set:
                    client = originator
                    break

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
    try:
        may_overwrite = [c.strip() for c in over_client.split(',')]
    except Exception as e:
        log.warning("evaluating config entry 'mayOverwriteClient': %r" % e)

    client = _get_client_from_request(request)

    if client in may_overwrite or client is None:
        log.debug("client %s may overwrite!" % client)

        client = get_request_param(request, "client")
        if client:
            log.debug("client overwritten to %s" % client)

    log.debug("returning client %s" % client)
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

hex2ModDict = dict(list(zip(hexHexChars, modHexChars)))
mod2HexDict = dict(list(zip(modHexChars, hexHexChars)))


def modhex_encode(s: str) -> str:
    return ''.join([hex2ModDict[c] for c in s])


def modhex_decode(m: str) -> str:
    return ''.join([mod2HexDict[c] for c in m])

def checksum(msg: bytes) -> int:
    crc = 0xffff
    for b in msg:
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
            output_str = str(input_str, **param)
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
    return x == y



def dict_copy(dict_):

    """ recursively copies a dict """

    # we use an recursive approach instead of an
    # iterative one, because our dicts are only
    # 3 to 4 levels deep.

    copy = {}
    for key, value in dict_.items():
        if isinstance(value, dict):
            fragment = {key: dict_copy(value)}
        else:
            fragment = {key: value}
        copy.update(fragment)
    return copy

def int_from_bytes(bytes_, byteorder='little'):

    """
    converts bytes to an integer

    :param bytes_: The bytes, that should be converted
    :param byteorder: 'little' for little endian (default)
        or 'big' for big endian
    """

    if byteorder not in ['little', 'big']:
        raise InvalidFunctionParameter('byteorder', 'byte order can only '
                                       'be \'little\' or \'big\'')

    order = -1 if byteorder == 'little' else 1

    # we calculate the result by interpreting data as coefficients of the
    # polynomial
    #
    #   p(X) := data[15] * X^15  + ... + data[1] * X + data[0]
    #
    # and evulating p(2^8) using horner's scheme.

    res = 0
    for byte in bytes_[::order]:
        res *= 256
        res += byte

    return res

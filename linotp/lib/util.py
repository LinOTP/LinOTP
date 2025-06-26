#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""contains utility functions"""

import copy
import logging
import re
import secrets
import string
from typing import Any

from linotp import __api__ as linotp_api
from linotp import __copyright__ as linotp_copyright
from linotp import __product__ as linotp_product
from linotp import __version__ as linotp_version
from linotp.flap import config
from linotp.lib.config import getFromConfig
from linotp.lib.crypto.utils import geturandom
from linotp.lib.error import InvalidFunctionParameter, ParameterError
from linotp.lib.type_utils import (
    boolean,
    get_ip_address,
    get_ip_network,
    is_ip_address_dotted_quad,
)
from linotp.settings import _config_schema

hostname_regex = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

log = logging.getLogger(__name__)

optional = True
required = False


def get_api_version():
    """
    return the api version number
    """
    return linotp_api


def get_version_number():
    """
    returns the linotp version
    """
    return linotp_version


def get_version():
    """
    This returns the version, that is displayed in the WebUI and
    self service portal.
    """
    return f"{linotp_product} {linotp_version}"


def get_copyright_info():
    """
    This returns the copyright information displayed in the WebUI
    and selfservice portal.
    """
    return linotp_copyright


def get_log_level(app) -> str:
    """Returns the apps `LOG_LEVEL`
    This is a workaround until deprecated `LOGGING_LEVEL` is removed.

    Note: Potential errors are not caught intentionally to fail
          tests after we removed `LOGGING_LEVEL`.
          So that we can remove this function.
    """
    logging_level_default = _config_schema.find_item("LOGGING_LEVEL").default
    if app.config["LOGGING_LEVEL"] != logging_level_default:
        return app.config["LOGGING_LEVEL"]

    return app.config["LOG_LEVEL"]


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
        if optional is False:
            msg = f"Missing parameter: {which!r}"
            raise ParameterError(msg, id=905)

    return ret


def get_request_param(request, key, default=None):
    """
    Returns the get / post / etc. param with the given key dependent on
    the content type
    """

    if request.is_json:
        return request.json.get(key, default)
    else:
        return request.values.get(key, default)


def getLowerParams(param):
    return {key.lower(): val for key, val in param.items() if key.lower() != "session"}


def uniquify(doubleList):
    # uniquify the realm list
    return list(set(map(str.lower, doubleList)))


def generate_otpkey(key_size: int = 20) -> str:
    """
    generates the HMAC key of keysize. Should be 20 or 32
    THe key is returned as a hexlified string
    """
    log.debug("generating key of size %s", key_size)
    return geturandom(key_size).hex()


def generate_password(size=6, characters=None):
    if not characters:
        characters = string.ascii_letters + string.digits

    return "".join(secrets.choice(characters) for _x in range(size))


def check_selfservice_session(cookies=None, params=None, url=None):
    """
    This function checks the session cookie for the
    selfservice / userservice session
    """
    cookie = cookies.get("linotp_selfservice", "").strip('"')
    session = params.get("session", "").strip('"')

    if not session or not cookie:
        log.warning("failed to check selfservice session")
        return False

    if session[:40] != cookie[:40]:
        log.error("The request %r did not pass a valid session!", url)
        return False

    return True


def remove_session_from_param(param):
    """
    Some low level functions like the userlisting do not like to have a
    session parameter in the param dictionary.
    So we remove the session from the params.
    """
    return {key: value for key, value in param.items() if key.lower() != "session"}


###############################################################################
# Client overwriting stuff


def is_addr_in_network(addr, network):
    """
    helper method to check if a client is in the proxy network range

    :param addr: the client address
    :param network: the network range description
    :return: boolean - True if match is given
    """

    ip_network = get_ip_network(network)
    if ip_network is None:
        log.error("no valid ip_network: %r", network)
        return False

    ip_addr = get_ip_address(addr)
    if ip_addr is None:
        log.error("no valid ip_address: %r", addr)
        return False

    return ip_addr in ip_network


def _get_client_from_request(request=None):
    """
    This function returns the client as it is passed in the HTTP Request.
    This is the very HTTP client, that contacts the LinOTP server.
    """

    client = request.environ.get(
        "REMOTE_ADDR", request.environ.get("HTTP_REMOTE_ADDR", None)
    )

    if not is_TRUSTED_PROXIES_active():
        if is_x_forwarded_for_active():
            # check, if the request passed by a qualified proxy

            remote_addr = client
            x_forwarded_proxies = getFromConfig("client.FORWARDED_PROXY", "").split(",")

            for x_forwarded_proxy in x_forwarded_proxies:
                if is_addr_in_network(remote_addr, x_forwarded_proxy):
                    xff: str = request.environ.get("HTTP_X_FORWARDED_FOR", "")
                    ref_clients = [
                        client.strip() for client in xff.split(",") if client.strip()
                    ]
                    if ref_clients:
                        # the first ip in the list is the originator
                        client = ref_clients[0]
                        break

        if is_http_forwarded_active():
            # Check if the request passed through a qualified proxy

            remote_addr = client
            forwarded_proxies = getFromConfig("client.FORWARDED_PROXY", "").split(",")

            for forwarded_proxy in forwarded_proxies:
                if not is_addr_in_network(remote_addr, forwarded_proxy):
                    continue
                # Example: "Forwarded: for=192.0.2.43, for=198.51.100.17"
                entries: str = request.environ.get(
                    "HTTP_FORWARDED", request.environ.get("Forwarded", "")
                )
                entries = [
                    entry.strip()
                    for entry in entries.replace("Forwarded:", "").split(",")
                    if entry.strip()
                ]

                ipvalue = None
                for entry in entries:
                    if entry.lower().startswith("for"):
                        value = entry.split("=")[1].split(";")[0].strip()
                        if "]" in value:
                            ipvalue = value.split("]")[0].split("[")[1]
                        elif ":" in value:
                            ipvalue = value.split(":")[0]
                        else:
                            ipvalue = value
                        ipvalue = ipvalue.strip('"')
                        break

                if ipvalue is not None:
                    client = ipvalue
                    break

    return client


def is_http_forwarded_active():
    # "Forwarded" Header
    #
    # In 2014 RFC 7239 standardized a new Forwarded header with similar purpose
    # but more features compared to XFF.[28] An example of a Forwarded header
    # syntax:
    #
    # Forwarded: for=192.0.2.60; proto=http; by=203.0.113.43

    return boolean(getFromConfig("client.FORWARDED", False))


def is_x_forwarded_for_active():
    return boolean(getFromConfig("client.X_FORWARDED_FOR", False))


def is_TRUSTED_PROXIES_active():
    trusted_proxies_settings = config["TRUSTED_PROXIES"]
    if trusted_proxies_settings:
        return True
    return False


def get_client(request):
    """This function returns the client.

    It first tries to get the client as it is passed as the HTTP Client
    via REMOTE_ADDR.

    If this client Address is in a list, that is allowed to overwrite
    its client address (like e.g. a FreeRADIUS server, which will
    always pass the FreeRADIUS address but not the address of the
    RADIUS client) it checks for the existance of the client parameter
    as long as the `GET_CLIENT_ADDRESS_FROM_POST_DATA` configuration
    entry is set to `True`.
    """
    client = _get_client_from_request(request)

    if config["GET_CLIENT_ADDRESS_FROM_POST_DATA"]:
        may_overwrite = []
        over_client = getFromConfig("mayOverwriteClient", "")
        try:
            may_overwrite = [c.strip() for c in over_client.split(",")]
        except Exception as e:
            log.warning("evaluating config entry 'mayOverwriteClient': %r", e)

        if client in may_overwrite:
            client_from_post = get_request_param(request, "client")
            if client_from_post:  # not `None` nor an empty string
                log.warning(
                    "DEPRECATION WARNING: "
                    "Passing the client IP address in POST data is "
                    "deprecated. Change your client code!"
                )
                log.debug(
                    "Client IP address %r overwritten by %r",
                    client,
                    client_from_post,
                )
                client = client_from_post

    if not is_ip_address_dotted_quad(client):
        msg = f"client address is not a dotted quad: {client!r}"
        raise ValueError(msg)

    log.debug("get_client: client is %s", client)
    return client


def normalize_activation_code(
    activationcode, upper=True, convert_o=True, convert_0=True
):
    """
    This normalizes the activation code.
    1. lower letters are capitaliezed
    2. Oh's in the last two characters are turned to zeros
    3. zeros before the last 2 characters are turned to Ohs
    """
    if upper:
        activationcode = activationcode.upper()
    if convert_o:
        activationcode = activationcode[:-2] + activationcode[-2:].replace("O", "0")
    if convert_0:
        activationcode = activationcode[:-2].replace("0", "O") + activationcode[-2:]

    return activationcode


def is_valid_fqdn(hostname, split_port=False):
    """
    Checks if the hostname is a valid FQDN
    """
    if split_port:
        hostname = hostname.split(":")[0]
    if len(hostname) > 255:
        return False
    # strip exactly one dot from the right, if present
    if hostname[-1:] == ".":
        hostname = hostname[:-1]

    return all(hostname_regex.match(x) for x in hostname.split("."))


def remove_empty_lines(doc):
    """
    remove empty lines from the input document

    :param doc: documemt containing long multiline text
    :type  doc: string

    :return: data without empty lines
    :rtype:  string
    """
    data = "\n".join([line for line in doc.split("\n") if line.strip() != ""])
    return data


##
# Modhex calculations for Yubikey
##
hexHexChars = "0123456789abcdef"
modHexChars = "cbdefghijklnrtuv"

hex2ModDict = dict(zip(hexHexChars, modHexChars, strict=True))
mod2HexDict = dict(zip(modHexChars, hexHexChars, strict=True))


def modhex_encode(s: str) -> str:
    return "".join([hex2ModDict[c] for c in s])


def modhex_decode(m: str) -> str:
    return "".join([mod2HexDict[c] for c in m])


def checksum(msg: bytes) -> int:
    # Initial CRC value
    crc = 0xFFFF

    # Iterate through each byte in the message
    for byte in msg:
        crc = crc ^ (byte & 0xFF)

        # Iterate through each bit in the byte
        for _ in range(8):
            # Check the least significant bit
            lsb = crc & 1
            crc = crc >> 1
            if lsb != 0:
                # XOR with the polynomial if the lsb is 1
                crc = crc ^ 0x8408

    return crc


def str2unicode(input_str):
    """
    convert as binary string into a unicode string by trying various encodings
    :param input_str: input binary string
    :return: unicode output
    """

    conversions = [
        {},
        {"encoding": "utf-8"},
        {"encoding": "iso-8859-1"},
        {"encoding": "iso-8859-15"},
    ]
    for param in conversions:
        try:
            return str(input_str, **param)
        except UnicodeDecodeError:
            pass

    log.error("No Unicode conversion found for %r", input_str)
    msg = "Unable to convert binary string to Unicode."
    raise UnicodeDecodeError(msg)


def unicode_compare(x, y):
    """
    locale and unicode aware comparison operator - for usage in sorted()

    :param x: left value
    :param y: right value
    :return: the locale aware comparison result
    """
    return x == y


def dict_copy(dict_):
    """recursively copies a dict"""

    # we use an recursive approach instead of an
    # iterative one, because our dicts are only
    # 3 to 4 levels deep.

    return copy.deepcopy(dict_)


# courtesies to pydantic:
def deep_update(
    mapping: dict[str, Any], *updating_mappings: dict[str, Any]
) -> dict[str, Any]:
    updated_mapping = mapping.copy()
    for updating_mapping in updating_mappings:
        for k, v in updating_mapping.items():
            if (
                isinstance(v, dict)
                and k in updated_mapping
                and isinstance(updated_mapping[k], dict)
            ):
                updated_mapping[k] = deep_update(updated_mapping[k], v)
            else:
                updated_mapping[k] = v
    return updated_mapping


def int_from_bytes(bytes_, byteorder="little"):
    """
    converts bytes to an integer

    :param bytes_: The bytes, that should be converted
    :param byteorder: 'little' for little endian (default)
        or 'big' for big endian
    """

    if byteorder not in ["little", "big"]:
        msg = "byteorder"
        raise InvalidFunctionParameter(msg, "byte order can only be 'little' or 'big'")

    order = -1 if byteorder == "little" else 1

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

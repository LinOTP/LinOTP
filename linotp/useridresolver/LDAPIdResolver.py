#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010-2019 KeyIdentity GmbH
#
#   This file is part of LinOTP userid resolvers.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU Affero General Public
#   License, version 3, as published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the
#              GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#   E-mail: info@linotp.de
#   Contact: www.linotp.org
#   Support: www.linotp.de
#
"""This module implements the communication
              and data mapping to LDAP servers.
              The LinOTPd imports this module to
              use LDAP servers as a userstore.

Dependencies: UserIdResolver
"""

import json
import logging
import sys
from datetime import datetime

import ldap
import ldap.filter

from linotp.lib.util import get_log_level

try:
    from ldap import LDAP_CONTROL_PAGE_OID

    ldap_api_version = 2.3
except ImportError:
    ldap_api_version = 2.4

import click
from flask import current_app
from flask.cli import with_appcontext
from ldap.controls import SimplePagedResultsControl

from linotp.lib.resources import ResourceScheduler, string_to_list
from linotp.lib.type_utils import boolean, encrypted_data
from linotp.useridresolver import resolver_registry
from linotp.useridresolver.UserIdResolver import (
    ResolverLoadConfigError,
    ResolverNotAvailable,
    ResParamsType,
    UserIdResolver,
)

log = logging.getLogger(__name__)

log.info("using the %r cursoring api.", ldap_api_version)

# resolver config default / fallback values

DEFAULT_UID_TYPE = "DN"  # can be entryUUID, GUID, objectGUID or DN
ENCODING = "utf-8"
DEFAULT_SIZELIMIT = 500
DEFAULT_EnforceTLS = False
BIND_NOT_POSSIBLE_TIMEOUT = 30
TIMEOUT_NO_LIMIT = -1


# -------------------------------------------------------------------------- --


def escape_hex_for_search(hex_value: str) -> str:
    r"""
    transform an hex string for a byte search in ldap, especially used for objectGUID

    From: https://ldapwiki.com/wiki/ObjectGUID

    ObjectGUID LDAP in SearchFilters

    In order to form an LDAP SearchFilter that searches based on an ObjectGUID,
    the GUID value must be entered in a special syntax in the filter - where
    each byte in the hexadecimal representation of the GUID must be escaped
    with a Backslash (\) symbol.

    To provide an example, in order to search for an object with hexadecimal
        GUID "90395F191AB51B4A9E9686C66CB18D11",
    the corresponding filter should be set as:
        (objectGUID=\90\39\5F\19\1A\B5\1B\4A\9E\96\86\C6\6C\B1\8D\11)

    :param hex_value: e.g. the objectGuid in hex representation
    :return: str escaped hex representation, to be used for search
    """

    return "\\" + "\\".join(
        [hex_value[idx : idx + 2] for idx in range(0, len(hex_value), 2)]
    )


# -------------------------------------------------------------------------- --


@resolver_registry.class_entry("useridresolver.LDAPIdResolver.IdResolver")
@resolver_registry.class_entry("useridresolveree.LDAPIdResolver.IdResolver")
@resolver_registry.class_entry("useridresolver.ldapresolver")
@resolver_registry.class_entry("ldapresolver")
class IdResolver(UserIdResolver):
    """
    LDAP User Id resolver
    """

    nameDict: dict[str, str] = {}
    conf = ""
    db_prefix = "useridresolver.LDAPIdResolver.IdResolver"

    # The mapping of these search fields to the ldap attributes is
    # stored in self.userinfo

    fields = {
        "username": 1,
        "userid": 1,
        "description": 0,
        "phone": 0,
        "mobile": 0,
        "email": 0,
        "givenname": 0,
        "surname": 0,
        "gender": 0,
    }

    searchFields = {
        "username": "text",
        "userid": "text",
        "description": "text",
        "email": "text",
        "givenname": "text",
        "surname": "text",
    }

    critical_parameters = ["LDAPBASE", "BINDDN", "LDAPURI"]

    crypted_parameters = ["BINDPW"]
    primary_key = "UIDTYPE"

    resolver_parameters: ResParamsType = {
        "LDAPURI": (True, None, str),
        "LDAPBASE": (True, None, str),
        "BINDDN": (True, None, str),
        "BINDPW": (True, None, encrypted_data),
        "LOGINNAMEATTRIBUTE": (True, None, str),
        "LDAPFILTER": (True, None, str),
        "LDAPSEARCHFILTER": (True, None, str),
        "USERINFO": (True, True, str),
        "UIDTYPE": (False, DEFAULT_UID_TYPE, str),
        "EnforceTLS": (False, True, boolean),
        "only_trusted_certs": (False, True, boolean),
        "NOREFERRALS": (False, False, boolean),
        "PROXY": (False, False, boolean),
        "TIMEOUT": (False, TIMEOUT_NO_LIMIT, str),
        "SIZELIMIT": (False, DEFAULT_SIZELIMIT, int),
    }

    resolver_parameters.update(UserIdResolver.resolver_parameters)

    @classmethod
    def primary_key_changed(cls, new_params, previous_params):
        """
        check if during the parameter update the primary key has changed

        :param new_params: the set of new parameters
        :param previous_params: the set of previous parameters

        :return: boolean
        """

        new_id = new_params.get(cls.primary_key, "")
        prev_id = previous_params.get(cls.primary_key, "")

        return new_id != prev_id

    @classmethod
    def setup(cls, config=None, cache_dir=None):
        """
        this setup hook is triggered, when the server starts to serve the
        first request

        :param config: the linotp config
        :return: -nothing-
        """
        log.debug("Setting up LDAPIdResolver")
        return

    @classmethod
    def connect(cls, uri, caller, trace_level=0):
        """
        helper - to build up the initial ldap / ldaps connection

        :param uri: the ldap url
        :return: the ldap connection object
        """

        def init_ldap(uri, trace_level):
            # prepare the ldap for connection

            try:
                l_obj = ldap.initialize(uri, trace_level=trace_level)
            except ldap.LDAPError as exx:
                log.error(f"couldn't connect to {uri}: {exx!r}")
                raise exx

            # Set LDAP protocol version used
            l_obj.protocol_version = ldap.VERSION3

            # `network_timeout` is used by the OpenLDAP client lib to limit
            # waiting for a network response. `timeout` is used in the
            # `python-ldap` wrapper library to limit waiting for any response.

            l_obj.network_timeout = caller.network_timeout
            l_obj.timeout = caller.response_timeout

            return l_obj

        log.debug("Try to connect to %r", uri)

        # uri's starting or ending with 'whitespace' are not supported
        uri = uri.strip()

        # check that the uri is only a valid ldap uri
        if "," in uri:
            log.warning("unsupported multiple urls in ldap uri %r", uri)

        if not uri.startswith(("ldaps://", "ldap://")):
            log.error("unsuported protocol %r", uri)
            raise Exception(f"unsuported protocol {uri!r}")

        l_obj = init_ldap(uri, trace_level)

        if uri.startswith("ldaps://") or caller.enforce_tls:
            # If we establish an ldaps connection, we currently accept
            # untrusted server certificates - default has to be switched.
            # With the option 'only_trusted_certs' the server certificate
            # will be verified and only verified servers will be connected

            # Note that on Debian GNU/Linux, the OpenLDAP client library
            # is linked against GnuTLS and doesn't support
            # `ldap.OPT_X_TLS_CACERTDIR`.

            ca_cert_file = current_app.config["TLS_CA_CERTIFICATES_FILE"]
            l_obj.set_option(ldap.OPT_X_TLS_CACERTFILE, ca_cert_file)
            cert_req = (
                ldap.OPT_X_TLS_DEMAND
                if caller.only_trusted_certs
                else ldap.OPT_X_TLS_NEVER
            )
            log.debug(
                f"Using root-level CA certificates from {ca_cert_file}"
                ", server certificates "
                f"{'must' if caller.only_trusted_certs else 'need not'} "
                "be valid."
            )
            l_obj.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, cert_req)
            l_obj.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

        if uri.startswith("ldap://"):
            if caller.enforce_tls:
                # Try to upgrade the LDAP connection to TLS, and
                # complain fiercely if this fails.

                # Whether we insist on a server certificate that checks
                # out depends on the value of `caller.only_trusted_certs`,
                # and the previous `if` has set the proper LDAP TLS options
                # for us.

                log.debug(f"Attempting STARTTLS on {uri} (as configured)")
                try:
                    l_obj.start_tls_s()
                except ldap.LDAPError as exx:
                    log.error(f"Couldn't STARTTLS on {uri}: {exx!r}")
                    raise exx

            else:
                # Use a plain unencrypted and unauthenticated LDAP
                # connection. This sucks but, presumably, needs must.
                # (For transparency's sake, we got rid of the
                # gratuitous unsolicited STARTTLS that this code used
                # to do. The UI now defaults to having “Enforce TLS”
                # set to “yes”, so you can only get here if you actively
                # set that to “no”, and we do hope that you have thought
                # of the consequences.

                log.warning("Plain LDAP connection (THIS IS INSECURE!!!)")

        # At this point we should have either an LDAPS connection, or an
        # LDAP connection that has been upgraded to TLS, or a plain LDAP
        # connection.

        # Output the name of the cipher being used, if any, if `python-ldap`
        # volunteers that information. (According to the documentation, it
        # should, but even the newest version doesn't seem to follow the
        # documentation.)

        if uri.startswith("ldaps://") or caller.enforce_tls:
            cipher = (
                l_obj.get_option("OPT_X_TLS_CIPHER")
                if hasattr(l_obj, "OPT_X_TLS_CIPHER")
                else "Unknown"
            )
            log.info(f"LDAP TLS: using cipher={cipher}")

        if caller.noreferrals:
            log.debug("using noreferrals: %r", caller.noreferrals)
            l_obj.set_option(ldap.OPT_REFERRALS, 0)

        return l_obj

    @classmethod
    def testconnection(cls, params, silent=False):
        """
        This is used to test if the given parameter set will do a successful
        LDAP connection.

        :param params:
            - BINDDN
            - BINDPW
            - LDAPURI
            - TIMEOUT
            - LDAPBASE
            - LOGINNAMEATTRIBUTE': 'sAMAccountName',
            - LDAPSEARCHFILTER': '(sAMAccountName=*)(objectClass=user)',
            - LDAPFILTER': '(&(sAMAccountName=%s)(objectClass=user))',
            - USERINFO': '{ "username": "sAMAccountName", "phone" :
                "telephoneNumber", "mobile" : "mobile",
                "email" : "mail", "surname" : "sn",
                "givenname" : "givenName" }'
            - SIZELIMIT
            - NOREFERRALS
            - EnforceTLS
        """

        status = "success"
        resultList = []

        l_obj = None

        # for the testconection we are using a simple class
        # where we could assign the members. This will allow us to
        # call the static method 'connect' with the caller class as
        # first parameter, while its as well possible to use the connect
        # method from the LDAPResolver instance

        class Caller:
            pass

        caller = Caller()

        l_config, missing = IdResolver.filter_config(params)

        caller.noreferrals = True

        caller.enforce_tls = l_config["EnforceTLS"]
        caller.only_trusted_certs = l_config["only_trusted_certs"]

        try:
            # do a bind
            uri = l_config["LDAPURI"]

            caller.noreferrals = l_config["NOREFERRALS"]

            timeout = l_config["TIMEOUT"]
            (
                caller.network_timeout,
                caller.response_timeout,
            ) = IdResolver.parse_timeout(timeout)

            trace_level = params.get("trace_level", 0)
            if trace_level != 0:
                ldap.set_option(ldap.OPT_DEBUG_LEVEL, 4095)

            failed = None

            for s_uri in uri.split(","):
                log.info("testing connection with uri %r", s_uri)

                try:
                    l_obj = IdResolver.connect(s_uri, caller, trace_level=trace_level)

                    # try to authenticate to server:
                    # this will establish the first connection

                    bind_dn = l_config["BINDDN"]
                    bind_pw = l_config["BINDPW"].get_unencrypted()

                    l_obj.simple_bind_s(bind_dn, bind_pw)

                    # simple_bind will raise an exception if the server
                    # could not be reached or an error occurs - thus the
                    # break is only reached, when everything is ok

                    break

                except Exception as exx:
                    failed = exx

            if failed is not None:
                raise failed

            # get a userlist:
            searchFilter = "(&" + l_config["LDAPSEARCHFILTER"] + ")"
            sizelimit = int(DEFAULT_SIZELIMIT)

            sizelimit = l_config["SIZELIMIT"]

            ldap_result_id = l_obj.search_ext(
                l_config["LDAPBASE"],
                ldap.SCOPE_SUBTREE,
                filterstr=searchFilter,
                sizelimit=sizelimit,
            )
            while True:
                userdata = {}
                result_type, result_data = l_obj.result(ldap_result_id, 0)
                if result_data == []:
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        # compose response as we like it
                        userdata["userid"] = result_data[0][0]
                        resultList.append(userdata)

        except ldap.SIZELIMIT_EXCEEDED as exx:
            if len(resultList) < sizelimit:
                status = "success SIZELIMIT_EXCEEDED"
                log.warning("[testconnection] LDAP Error: %r", exx)

        except ldap.CONNECT_ERROR as err:
            status = "error"
            if not silent:
                log.error("[testconnection] LDAP Error: %r", err)
            return (status, f"Connection Error: {err}")

        except ldap.LDAPError as err:
            status = "error"
            if not silent:
                log.error("[testconnection] LDAP Error: %r", err)
            return (status, str(err))

        except Exception as err:
            status = "error"
            log.error("[testconnection] Error: %r", err)
            return (status, str(err))

        finally:
            if l_obj:  # unbind
                l_obj.unbind_s()

        return status, resultList

    def __init__(self):
        """
        Initialize the ldap resolver class
        """
        self.filter = ""
        self.searchfilter = ""
        self.ldapuri = ""
        self.base = ""
        self.binddn = ""
        self.bindpw = ""
        self.loginnameattribute = ""
        self.userinfo = {}
        self.network_timeout = 10
        self.bind_not_possible = False
        self.bind_not_possible_time = datetime.now()
        self.response_timeout = TIMEOUT_NO_LIMIT
        self.brokenconfig = False
        self.brokenconfig_text = ""
        self.sizelimit = 5
        self.noreferrals = False
        self.enforce_tls = True
        self.proxy = False
        self.uidType = DEFAULT_UID_TYPE
        self.l_obj = None
        self.only_trusted_certs = True

    def close(self):
        """
        closes method is called, when the request ends
        - here we close the ldap connection by unbind
        """

        try:
            if self.l_obj is not None:
                self.l_obj.unbind_s()

        except ldap.LDAPError as error:
            log.warning("[unbind] LDAP error: %r", error)

        finally:
            self.l_obj = None

    def bind(self):
        """
        bind() - this function starts an ldap conncetion
        """

        if self.l_obj is not None:
            return self.l_obj

        # iterate through the ldap uris

        urilist = string_to_list(self.ldapuri)
        log.debug("[bind] trying to bind to one of the servers: %r", urilist)

        resource_scheduler = ResourceScheduler(tries=2, uri_list=urilist)

        for uri in next(resource_scheduler):
            try:
                l_obj = IdResolver.connect(uri, caller=self)

                l_obj.simple_bind_s(self.binddn, self.bindpw.get_unencrypted())

                self.l_obj = l_obj
                return l_obj

            except ldap.LDAPError as _error:
                resource_scheduler.block(uri, delay=30)
                log.error("[bind] LDAP error")

        # if we reach this point, we were not able to do a successful bind! :-(

        log.error("Failed to bind to any resource %r", urilist)

        raise ResolverNotAvailable(f"Unable to bind to servers {urilist!r}")

    def unbind(self, lobj):
        """
        unbind() - this function formarly freed the ldap connection
        which is now done in the class destructor __del__()

        :param l: ldap object
        :return: -nothing-
        """
        return

    def getUserId(self, loginname):
        """
        return the userId which mappes to an loginname

        :param loginName: login name of the user
        :type loginName:  string

        :return: userid - unique idenitfier for this unser
        :rtype:  string
        """

        log.debug(
            "[getUserId] resolving userid for %r: %r",
            type(loginname),
            loginname,
        )

        if not loginname:
            return ""

        user_filter_expression = self._replace_macros(self.filter)

        # ------------------------------------------------------------------ --

        # the login name replacement '%s' could occur multiple times in the
        # user filter, e.g.:
        #
        # (&(|(sAMAccountName=%s)(userPrincipalName=%s))(objectClass=user))
        #
        # thus we build up the format_values array with the login name

        format_values = [loginname] * user_filter_expression.count("%s")

        user_filter_string = ldap.filter.filter_format(
            user_filter_expression, format_values
        )

        l_obj = self.bind()

        if not l_obj:
            return ""

        # ----------------------------------------------------------------- --

        # prepare the list of attributes that we wish to receive
        # Remark: the elements each must be of type string utf-8

        attrlist = []
        if self.uidType.lower() != "dn":
            attrlist.append(self.uidType)

        # ----------------------------------------------------------------- --

        resultList = None
        try:
            # log.error("%r : %r" % (self.uidType, attrlist))
            l_id = l_obj.search_ext(
                self.base,
                ldap.SCOPE_SUBTREE,
                filterstr=user_filter_string,
                sizelimit=self.sizelimit,
                attrlist=attrlist,
                timeout=self.response_timeout,
            )

            resultList = l_obj.result(l_id, all=1)[1]

        except ldap.LDAPError as exc:
            log.error("[getUserId] LDAP error: %r", exc)
            resultList = None

        finally:
            self.unbind(l_obj)

        if not resultList:
            log.info("[getUserId] : empty result ")
            return ""

        #
        # AD returns an result set where the first entry of the tuple is None
        # so we check here if there is any relevant entry

        relevant_entries = False
        for entry in resultList:
            if isinstance(entry, tuple) and len(entry) > 0 and entry[0] is not None:
                relevant_entries = True

        if not relevant_entries:
            log.info("[getUserId] : empty result ")
            return ""

        log.debug("[getUserId] : resultList :%r: ", resultList)
        log.debug("[getUserId] : uidType: %r ", self.uidType)

        # [0][0] is the distinguished name

        userid = self._get_uid_from_result(resultList[0], self.uidType)

        if not userid:
            log.info(
                "[getUserId] : empty result for  %r - uidtype: %r",
                loginname,
                self.uidType.lower(),
            )
        else:
            log.debug("[getUserId] userid: %r:%r", type(userid), userid)

        return userid

    def getUsername(self, userid):
        """
        get the loginname from the given userid

        :param userId: userid descriptor
        :type userId: string

        :return: loginname
        :rtype:  string
        """

        username = ""

        l_user = self.getUserLDAPInfo(userid, attrlist=[self.loginnameattribute])

        if self.loginnameattribute in l_user:
            username = l_user[self.loginnameattribute]
        return username

    def getUserLDAPInfo(self, userid, attrlist=None):
        """
        getUserLDAPInfo(UserId)

        This function returns all user information for a given user object
        identified by UserID. In LDAP case this is the DN, but could also be
        'objectguid' or uidtype

        :param userid: user identifier (in unicode)
        :type  userid: unicode or str

        :param attrlist: the list of attributes, which should be returned
                         if None, the attributes are not filtered on the server
                         side and all are returned
        :type attrlist: list

        :return: user info dict
        :rtype: dict

        """
        log.debug("[getUserLDAPInfo]")

        if attrlist:
            attrlist.append(self.uidType)

        # -------------------------------------------------------------- --

        # setup the search parameters

        s_base = self.base
        s_scope = ldap.SCOPE_SUBTREE
        s_filter = f"({self.uidType}={userid})"

        if self.uidType.lower() == "dn":
            s_base = userid
            s_scope = ldap.SCOPE_BASE
            s_filter = None

        elif self.uidType.lower() == "objectguid":
            s_base = f"<guid={userid}>"
            s_scope = ldap.SCOPE_BASE
            s_filter = None

            if self.proxy:
                s_base = self.base
                s_scope = ldap.SCOPE_SUBTREE
                s_filter = f"(objectGuid={escape_hex_for_search(userid)})"

        # ------------------------------------------------------------------ --

        # do the search

        l_obj = None

        try:
            l_obj = self.bind()

            if not l_obj:
                return {}

            l_id = l_obj.search_ext(
                s_base,
                s_scope,
                filterstr=s_filter,
                attrlist=attrlist,
                sizelimit=self.sizelimit,
                timeout=self.response_timeout,
            )

            result_data = l_obj.result(l_id, all=1)[1]

        except ldap.LDAPError as _error:
            log.error("[getUserLDAPInfo] LDAP error")
            return {}

        except Exception as exx:
            log.error("[getUserLDAPInfo] LDAP error")
            raise exx

        finally:
            if l_obj is not None:
                self.unbind(l_obj)

        if not result_data:
            return {}

        # ------------------------------------------------------------------ --

        # process result and put it in the userinfo dict

        userinfo = {}

        result = result_data[0]

        # add the dn which is the first entry
        userinfo["dn"] = [result[0]]

        # add the the other key, [values] from the second result entry
        for key, uval in result[1].items():
            entries = []
            for udata in uval:
                if key == "objectGUID":
                    udata = udata.hex()

                if isinstance(udata, bytes):
                    try:
                        udata = udata.decode()
                    except Exception as _exx:
                        log.info("Failed to decode entry %r: %r", key, udata)

                entries.append(udata)

            userinfo[key] = entries

        return userinfo

    def getUserInfo(self, userid):
        """
        return all user related information

        :param userId: specified user
        :type userId: string

        :return: dictionary, containing all user related info
        :rtype: dict

        The return is a dictionary with well defined keys::

            fields = {
                "username": 1,
                "userid": 1,
                "description": 0,
                "phone": 0,
                "mobile": 0,
                "email": 0,
                "givenname": 0,
                "surname": 0,
                "gender": 0
            }
        """
        log.debug("[getUserInfo]")

        user = self.getUserLDAPInfo(userid, attrlist=list(self.userinfo.values()))

        if not user:
            return {}

        ret = {}

        ret["userid"] = userid

        # we will add all userinfo fields!

        for f in self.userinfo:
            val = ""
            if self.userinfo[f] in user:
                val = user[self.userinfo[f]][0]

                if isinstance(val, bytes):
                    try:
                        val = val.decode()
                    except BaseException:
                        log.info("unable to decode bytes %r", val)

            ret[f] = val

        return ret

    def getResolverId(self):
        """
        getResolverId - provide the resolver identifier

        :return: returns the resolver identifier string or empty string
                    if not exist
        :rtype: string

        """
        log.debug("[getResolverId]")
        resolver = "LDAPIdResolver.IdResolver"
        if self.conf != "":
            resolver = resolver + "." + self.conf
        return resolver

    @classmethod
    def getResolverClassType(cls):
        return "ldapresolver"

    def getResolverType(self):
        """
        getResolverType - return the type of the resolver

        :return: returns the string 'ldapresolver'
        :rtype:  string
        """
        return IdResolver.getResolverClassType()

    @classmethod
    def getResolverClassDescriptor(cls):
        """
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        """

        log.debug("[getResolverDescriptor]")

        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor["clazz"] = "useridresolver.LDAPIdResolver.IdResolver"
        descriptor["config"] = {
            "LDAPFILTER": "string",
            "LDAPSEARCHFILTER": "string",
            "LDAPURI": "string",
            "LDAPBASE": "string",
            "BINDDN": "string",
            "BINDPW": "password",
            "LOGINNAMEATTRIBUTE": "string",
            "USERINFO": "string",
            "TIMEOUT": "float",
            "SIZELIMIT": "int",
            "NOREFERRALS": "string",
        }
        return {typ: descriptor}

    def getResolverDescriptor(self):
        return IdResolver.getResolverClassDescriptor()

    @classmethod
    def parse_timeout(cls, timeout, div=2.0):
        if ";" in timeout:
            network_timeout, response_timeout = timeout.split(";")
            network_timeout = float(network_timeout) / div
            response_timeout = float(response_timeout) / div
        else:
            network_timeout = float(timeout) / div
            response_timeout = TIMEOUT_NO_LIMIT

        return float(network_timeout), float(response_timeout)

    def loadConfig(self, config, conf=""):
        """
        loadConfig - load the config of the resolver

        :param config: configuration dictionary, could be parameter or
                       linotp config format
        :param conf: configuration identifier

        """

        self.conf = conf

        # ------------------------------------------------------------------ --

        # parse the config entries, extract and type convert the entries

        try:
            l_config, missing = self.filter_config(config, conf)

        except Exception as exx:
            log.error("failed to parse configuration: %r", exx)
            raise ResolverLoadConfigError(
                f"failed to parse configuration: {exx!r}"
            ) from exx

        if missing:
            log.error("missing config entries: %r", missing)
            raise ResolverLoadConfigError(f" missing config entries: {missing!r}")

        # ------------------------------------------------------------------ --

        # process and assign the config entries

        self.ldapuri = l_config["LDAPURI"]
        self.base = l_config["LDAPBASE"]
        self.binddn = l_config["BINDDN"]
        self.bindpw = l_config["BINDPW"]

        self.filter = l_config["LDAPFILTER"]
        self.searchfilter = l_config["LDAPSEARCHFILTER"]

        self.loginnameattribute = l_config["LOGINNAMEATTRIBUTE"]
        self.uidType = l_config["UIDTYPE"]

        try:
            self.userinfo = json.loads(l_config["USERINFO"])
        except ValueError as exx:
            raise ResolverLoadConfigError(
                f"Invalid userinfo - no json document: {l_config['USERINFO']!r} {exx!r}"
            ) from exx

        # ------------------------------------------------------------------ --

        # certificate related parameters

        self.enforce_tls = l_config["EnforceTLS"]
        self.only_trusted_certs = l_config["only_trusted_certs"]

        # ------------------------------------------------------------------ --

        # connection related parameters

        # support to setup both timeouts: network timeout and response timeout
        #  separator ';' splits network from response timeout
        timeout = l_config["TIMEOUT"]
        self.network_timeout, self.timeout = self.parse_timeout(timeout)

        self.sizelimit = l_config["SIZELIMIT"]
        self.noreferrals = l_config["NOREFERRALS"]
        self.proxy = l_config["PROXY"]

        return self

    def getSearchFields(self, searchDict=None):
        """
        return all fields on which a search could be made

        :return: dictionary of the search fields and their types - not used!!
        :rtype:  dict
        """
        log.debug("[getSearchFields]")
        return self.searchFields

    def _getUserDN(self, uid):
        """
        This function takes the UID and returns the DN of the user object
        """
        user_info = self.getUserLDAPInfo(uid, attrlist=["dn"])
        return user_info["dn"][0]

    def checkPass(self, uid, password):
        """
        checkPass - checks the password for a given uid.

        :param uid: userid to be checked
        :type  uid: string
        :param password: user password
        :type  password: string

        :return :  true in case of success, false if password does not match
        :rtype :   boolean

        :attention: First the UID needs to be converted to the DN, in
                        case the Uid is not the DN
        """

        log.debug("[checkPass]")

        # simple bind allows anonymous authentication which raises no
        # exception, so we return immediately if no password is given

        if password is None or len(password) == 0:
            return False

        log.debug("[checkPass] uidType: %r", self.uidType)
        if self.uidType.lower() == "dn":
            DN = uid
        else:
            DN = self._getUserDN(uid)

        log.debug("[checkPass] DN: %r", DN)

        urilist = string_to_list(self.ldapuri)

        log.debug(
            "[checkPass] we will try to authenticate to these LDAP servers: %r",
            urilist,
        )

        last_error = None
        resource_scheduler = ResourceScheduler(tries=1, uri_list=urilist)

        for uri in next(resource_scheduler):
            l_obj = None
            try:
                log.info(
                    "[checkPass] check password for user %r on LDAP server %r",
                    DN,
                    uri,
                )
                l_obj = IdResolver.connect(uri, caller=self)

                l_obj.simple_bind_s(DN, password)
                log.info("[checkPass] ldap bind for %r successful", DN)
                return True

            except ldap.INVALID_CREDENTIALS as error:
                log.warning("[checkPass] invalid credentials: %r", error)
                return False

            except ldap.LDAPError as error:
                log.warning("[checkPass] checking password failed: %r", error)
                resource_scheduler.block(uri, delay=30)
                last_error = error

            finally:
                if l_obj is not None:
                    l_obj.unbind_s()

        log.error("[checkPass] failed to connect to any resource %r", urilist)

        if last_error:
            log.error("[checkPass] access to resource failed: %r", last_error)

        raise ResolverNotAvailable(f"unable to bind to servers {urilist!r}")

    def _is_ad(self):
        """
        this is a heuristic approach to check if we are running against an AD
        check is running against the ldap config where we expect to have an
        sAMAccountname in any filter or login attribute
        """
        ret = False
        if (
            "sAMAccountName" in self.loginnameattribute
            or "sAMAccountName" in self.searchfilter
            or "sAMAccountName" in self.filter
        ):
            ret = True
        return ret

    def now_timestamp(self):
        """
        now - insert the now timestamp

        as AD starts it's time count at 31/12/1601, when the vigent gregorian
        cycle in our calendar is started,  we have to add the diff to
        the unix now timestamp, which starts at 1/1/1970

        accExp: expiry date of an user, in which case we count since 31/12/1601
                not since 01/01/1601; so we add 86400 seconds to the final
                result. As we use this timestamp only for the account expiry,
                we set this as default
        """
        # unix timestamp, which starts at 1/1/1970
        now = int(datetime.now().strftime("%s"))
        if self._is_ad():
            # 116444736000000000 = 31/12/1601
            add_seconds = 116444736000000000
            # we only care for account expiration
            account_expiry = True
            if account_expiry:
                add_seconds += 86400
            now = (now * 10000000) + add_seconds
        return now

    def _replace_macros(self, expression):
        """
        replace macros in string expression

        we support special replacements in search expressions like
        %(now)s which will be replaced by the windows or unix timestamp

        :param expression: string where macros should be replaced
        :return: substituted string
        """
        substitute = expression
        special_dict = {}
        special_dict["now"] = self.now_timestamp()

        try:
            for key, val in list(special_dict.items()):
                search_st = "%(" + key + ")s"
                if search_st in substitute:
                    substitute = substitute.replace(search_st, val)
        except KeyError as key_error:
            log.error("Key replacement error %r", key_error)
            raise key_error
        return substitute

    def getUserList(self, searchDict):
        """
        retrieve a list of users

        :param searchDict: dictionary of the search criterias
        :type  searchDict: dict
        :return: resultList, a dict with user info
        """

        # TODO: check if field is searchable
        # several filters are & concatenated:
        #   (&(objectClass=inetOrgPerson)(uid=theodor))
        # if we got an empty search dictionary, we will get all users!

        log.debug("[getUserList]")

        # add specialdict replacements, to support the "%(now)s" expression
        searchFilter = self._replace_macros(self.searchfilter)

        log.debug("[getUserList] searchfilter: %r", searchFilter)

        # add searchfilter attributes of searchDict
        searchFilter = self._create_search_filter(
            searchFilter=searchFilter, searchDict=searchDict
        )

        l_obj = self.bind()

        if not l_obj:
            return []

        log.debug("[getUserList] doing search with filter %r", searchFilter)
        log.debug("[getUserList] type of searchfilter: %r", type(searchFilter))

        resultList = []
        try:
            # ---------------------------------------------------------- --

            # prepare the list of attributes that we wish to recieve
            # Remark: the elememnts each must be of type string utf-8

            attrlist = list(self.userinfo.values())

            if self.uidType.lower() != "dn":
                attrlist.append(self.uidType)

            # ---------------------------------------------------------- --

            ldap_result_id = l_obj.search_ext(
                self.base,
                ldap.SCOPE_SUBTREE,
                filterstr=searchFilter,
                sizelimit=self.sizelimit,
                attrlist=attrlist,
                timeout=self.response_timeout,
            )

            log.debug("[getUserList] uidType: %r", self.uidType)

            while True:
                userdata = {}

                result_type, result_data = l_obj.result(
                    ldap_result_id, 0, timeout=self.response_timeout
                )

                if result_type != ldap.RES_SEARCH_ENTRY or not result_data:
                    break

                userdata = self._process_result(result_data[0])

                if userdata:
                    resultList.append(userdata)

        except ldap.LDAPError as _exce:
            log.error("[getUserList] LDAP error")

        except Exception as _exce:
            log.error("[getUserList] error during LDAP access")

        finally:
            self.unbind(l_obj)

        return resultList

    def _prepare_searchFilter(self, searchDict):
        """
        prepare the search Expression for the userListIterator

        :param searchDict: dictionary of the search criterias
        :type  searchDict: dict
        :return: resultList, a dict with user info
        """

        # TODO: check if field is searchable
        # several filters are & concatenated:
        #   (&(objectClass=inetOrgPerson)(uid=theodor))
        # if we got an empty search dictionary, we will get all users!

        log.debug("[getUserList]")

        # we support special replacements in search expressions like
        # %(now)s which will be replaced by the windows or unix timestamp
        special_dict = {}
        special_dict["now"] = self.now_timestamp()

        searchFilter = self.searchfilter
        # add specialdict replacements, to support the "%(now)s" expression
        try:
            searchFilter = searchFilter % special_dict
        except KeyError as key_error:
            log.error("Key replacement error %r", key_error)
            raise key_error

        log.debug("[getUserList] searchfilter: %r", searchFilter)

        # add searchfilter attributes of searchDict
        searchFilter = self._create_search_filter(
            searchFilter=searchFilter, searchDict=searchDict
        )
        return searchFilter

    def _create_search_filter(self, searchFilter, searchDict):
        # add searchfilter attributes of searchDict
        try:
            # OR filter
            searchFilterOr = ""
            searchTermValue = searchDict.get("searchTerm")
            if searchTermValue:
                for ldapKey in self.userinfo.values():
                    searchFilterOr += f"({ldapKey}={searchTermValue})"
            # AND filter
            for searchKey, searchValue in searchDict.items():
                if searchKey == "searchTerm":
                    # already handled in OR filter
                    continue
                log.debug("[getUserList] searchkeys: %r / %r", searchKey, searchValue)
                if searchKey in self.userinfo:
                    ldapKey = self.userinfo[searchKey]
                    # value and searchFilter are Unicode!
                    searchFilter += f"({ldapKey}={searchValue})"
                else:
                    log.warning("[getUserList] Unknown searchkey: %r", searchKey)

            # finaly embedd the filter in the ldap query string
            if searchFilterOr:
                searchFilter = f"(&(|{searchFilterOr}){searchFilter})"
            else:
                searchFilter = f"(&{searchFilter})"
            log.debug("[getUserList] searchfilter: %r", searchFilter)
        except Exception as exep:
            log.error("[getUserList] Error creating searchFilter: %r", exep)
            raise exep
        return searchFilter

    def _set_cursor(
        self, searchFilter, attrlist, l_obj=None, lc=None, serverctrls=None
    ):
        """
        helper function to setup the paging query and shift the cursor

        :param searchFilter: restict the search through the searchFilter
        :param attrlist: list of attributes, which should be returned
        :param l_obj: the ldap connection object - if none, we bind() it
        :param lc: the page result controller
        :param serverctrls: the srv.ctrl response of the ldap.result3
        :return: tupple of (message id, ldap connection object and page
                 controller)
        """
        page_size = 100
        # we take the sizelimit as hint for the page size
        if hasattr(self, "sizelimit"):
            page_size = self.sizelimit // 4

        # first request: if lc is not set, we are initializing
        if lc is None:
            l_obj = self.bind()
            if ldap_api_version == 2.4:
                lc = SimplePagedResultsControl(True, size=page_size, cookie="")
            elif ldap_api_version == 2.3:
                PAGE_OID = LDAP_CONTROL_PAGE_OID
                lc = SimplePagedResultsControl(PAGE_OID, True, (page_size, ""))

        else:
            cookie = None
            pctrls = []

            if ldap_api_version == 2.4:
                for c in serverctrls:
                    if c.controlType == SimplePagedResultsControl.controlType:
                        pctrls.append(c)
                        cookie = c.cookie
                        lc.cookie = cookie

            elif ldap_api_version == 2.3:
                for c in serverctrls:
                    if c.controlType == LDAP_CONTROL_PAGE_OID:
                        pctrls.append(c)
                        cookie = c.controlValue[1]
                        lc.controlValue = (page_size, cookie)

            if not pctrls:
                raise Exception("Warning: Server ignores RFC 2696 control.")

            if not cookie:
                return (None, None, None)

        # submit search request
        msgid = l_obj.search_ext(
            self.base,
            ldap.SCOPE_SUBTREE,
            filterstr=searchFilter,
            attrlist=attrlist,
            serverctrls=[lc],
            timeout=self.response_timeout,
        )

        return (msgid, l_obj, lc)

    def getUserListIterator(self, searchDict, limit_size=True):
        """
        iterator based access to get the list of users
        to prevent server response of sizelimit exceeded

        :param searchDict: the dict with a search filter expression
        :param limit_size: restrict the returned data size to size_limit
        :return: generator object (that yields userlist arrays).
        """
        searchFilter = self._prepare_searchFilter(searchDict)
        log.debug("[getUserListIterator] doing search with filter %r", searchFilter)

        # ------------------------------------------------------------------ --

        # prepare the list of attributes that we wish to recieve
        # Remark: the elememnts each must be of type string utf-8

        attrlist = list(self.userinfo.values())

        # add the requested unique identifier if it is not the dn

        if self.uidType.lower() != "dn":
            attrlist.append(self.uidType)

        # ------------------------------------------------------------------ --

        (msgid, l_obj, lc) = self._set_cursor(searchFilter, attrlist)

        done = False
        results_size = 0
        try:
            log.debug("uidType: %r", self.uidType)
            while not done:
                if limit_size and results_size >= self.sizelimit:
                    break

                lres = l_obj.result3(msgid)

                if not lres:
                    break

                (result_type, result_data, _rmsgid, serverctrls) = lres

                # shift the cursor to the next page
                (msgid, l_obj, lc) = self._set_cursor(
                    searchFilter,
                    attrlist,
                    l_obj=l_obj,
                    lc=lc,
                    serverctrls=serverctrls,
                )

                if not msgid:
                    done = True

                if result_type != ldap.RES_SEARCH_RESULT:
                    continue

                # process the result into array of dict
                user_list = []
                for result_entry in result_data:
                    user_info = self._process_result(result_entry)

                    if user_info:
                        user_list.append(user_info)

                results_size = results_size + len(user_list)
                yield user_list

        except ldap.LDAPError as exce:
            log.error("LDAP error: %r", exce)
            raise exce

        except Exception as exce:
            log.error("Error during LDAP access: %r", exce)
            raise exce

        # we do no unbind here, as this is done at the request end

    @staticmethod
    def _get_uid_from_result(result, uidType):
        """
        extract the uid from the ldap result

        the uid type is defined in the resolver defintion
        which in normal case could be: dn, objectguid, entryUUID or uPn

        the ldap result is a tuple of dn and an atrribute dict, where in
        the dict the value are of type list

        :param result: the ldap result entry
        :param uidType: the specified uid type of the resolver
        :return: uid as string
        """

        result_dn = result[0]
        result_data = result[1]

        # ------------------------------------------------------------------ --

        # the dn is always the first entry in the result tuple and is
        # not of type list

        if uidType.lower() == "dn":
            userid = result_dn

            return userid

        # ------------------------------------------------------------------ --

        # other uid types like entryUUID or userPrincipalname ar part of the
        # result_data dict, where we do a case insensitve search for the
        # userid type especially for the objectguid or the userPrincipalName

        userid = None
        for entry_key in result_data.keys():
            if uidType.lower() == entry_key.lower():
                userid = result_data.get(entry_key)[0]

        if not userid:
            raise Exception("No Userid found")

        # objectguid is converted to hex

        if uidType.lower() == "objectguid":
            return userid.hex()

        if isinstance(userid, bytes):
            userid = userid.decode()

        return userid

    def _process_result(self, result_data):
        """
        process the result of the iterator request into a user info dict

        :param result_data: one data entry of the ldap search response
        :return: userdata as dict
        """
        userdata = {}
        # access account DN as 1. tupple member
        # access account info dict as 2. tupple member
        account_dn = result_data[0]
        account_info = result_data[1]

        # in case of no DN - we skip the object
        if not account_dn:
            return {}

        userdata["userid"] = self._get_uid_from_result(result_data, self.uidType)

        # finally add all existing userinfos (wrt the mapping)
        for user_key, ldap_key in self.userinfo.items():
            if ldap_key in account_info:
                # An attribute can hold more than 1 value
                # So we only take the first one at the moment
                #   result_data[0][1][v][0]
                # If we want to get all
                #   result_data[0][1][v] gives us a list

                udata = account_info[ldap_key][0]

                if ldap_key == "objectGUID":
                    udata = udata.hex()

                if isinstance(udata, bytes):
                    try:
                        udata = udata.decode()
                    except BaseException:
                        log.warning("Failed to convert entry %r: %r", ldap_key, udata)

                userdata[user_key] = udata

        return userdata


def resolver_request(params, silent=False):
    def pr(s):
        if not silent:
            print(s)

    current_app.preprocess_request()

    pr(f"Trying to connect to {params['LDAPURI']!r}.")
    status, results = IdResolver.testconnection(params, silent)
    pr(f"Status: {status!r}")

    if results:
        pr("Result:")

        if status != "success":
            pr(f"{results!r}")
            return False

        for result in results:
            if not result:
                pr(f"{result!r}")
            else:
                for key, value in list(result.items()):
                    pr(f"{key} : {value}")

    return True


# ----------------------------------------------------------------------


@click.command("ldap-test", help="Test LDAP user-ID resolver connection.")
@click.option("--url", "-u", help="URL for LDAP server", required=True)
@click.option("--base", "-b", help="LDAP search base DN", required=True)
@click.option("--binddn", "-d", help="LDAP bind DN", required=True)
@click.option(
    "--bindpw",
    "-p",
    prompt="LDAP bind password",
    hide_input=True,
    help="LDAP bind password",
)
@click.option("--enforce_tls", "--enforce-tls", "-e", is_flag=True, help="Enforce TLS")
@click.option(
    "--trace_level",
    "--trace-level",
    "-t",
    type=int,
    default=0,
    help="LDAP trace level, 0..255",
)
@click.option(
    "--only_trusted_certs",
    "--only-trusted-certs",
    "-c",
    is_flag=True,
    help="Disallow untrusted or self-signed certificates",
)
@click.option(
    "--ldap_type",
    "--ldap-type",
    type=click.Choice(["ad", "ldap"], case_sensitive=False),
    default="ldap",
    help="LDAP server type",
)
@click.option("--cert_file", "--cert-file", help="Use CA certificate from file")
@click.option("--filter", help="Define object filter")
@click.option("--searchfilter", help="Define object search filter")
@click.option(
    "--loginattribute",
    default="uid",
    help="define user login attribute, default is uid",
)
@click.option(
    "--all-cases",
    is_flag=True,
    help=(
        "Exhaustively test all non-TLS/TLS connection options. "
        "This means that the `-e`, `-c`, and `-s` flags and the "
        "protocol part of the LDAP server URL are ignored."
    ),
)
@with_appcontext
def ldap_test(
    url,
    base,
    binddn,
    bindpw,
    enforce_tls,
    trace_level,
    only_trusted_certs,
    ldap_type,
    cert_file,
    filter,
    searchfilter,
    loginattribute,
    all_cases,
):
    user_mapping = {
        "username": "uid",
        "phone": "telephoneNumber",
        "mobile": "mobile",
        "email": "mail",
        "surname": "sn",
        "givenname": "givenName",
    }

    ldap_search = {
        "LDAPFILTER": "(&(uid=%s)(objectClass=inetOrgPerson))",
        "LDAPSEARCHFILTER": "(&(uid=*)(objectClass=inetOrgPerson))",
        "LOGINNAMEATTRIBUTE": "uid",
    }

    ad_search = {
        "LDAPFILTER": "(&(sAMAccountName=%s)(objectClass=user))",
        "LDAPSEARCHFILTER": "(&(sAMAccountName=*)(objectClass=user))",
        "LOGINNAMEATTRIBUTE": "sAMAccountName",
    }

    params = {
        "LDAPURI": url,
        "LDAPBASE": base,
        "BINDDN": binddn,
        "BINDPW": bindpw,
        "trace_level": trace_level,
        "NOREFERRALS": "True",
        "EnforceTLS": enforce_tls,
        "only_trusted_certs": only_trusted_certs,
        "SIZELIMIT": "500",
        "TIMEOUT": "5",
        "USERINFO": json.dumps(user_mapping),
    }

    search = ad_search if ldap_type == "ad" else ldap_search
    params.update(search)

    if filter:
        params["LDAPFILTER"] = filter
    if searchfilter:
        params["LDAPSEARCHFILTER"] = searchfilter
    if loginattribute:
        params["LOGINNAMEATTRIBUTE"] = loginattribute

    log_level = get_log_level(current_app)
    if not all_cases or log_level == "DEBUG":
        log.setLevel(logging.DEBUG)
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s: [%(name)s] %(message)s"
        )
        ch.setFormatter(formatter)
        log.addHandler(ch)

    if all_cases:
        # This does an exhaustive test of all possible combinations of
        # LDAP, LDAP+STARTTLS, LDAPS, with or without certificate checking
        # and with or without available CA certificates. The root-level CA
        # certificate for the LDAP server used for testing should be
        # specified using the `TLS_CA_CERTIFICATES_FILE` configuration
        # setting.

        ca_cert_file = current_app.config["TLS_CA_CERTIFICATES_FILE"]
        cases = [
            # proto   S-TLS  certs         checking  should connect?
            # ---------------------------------------------------------
            ("ldap", False, "/dev/null", False, True),
            ("ldap", True, "/dev/null", False, True),
            ("ldap", True, "/dev/null", True, False),
            ("ldap", True, ca_cert_file, False, True),
            ("ldap", True, ca_cert_file, True, True),
            ("ldaps", False, "/dev/null", False, True),
            ("ldaps", False, "/dev/null", True, False),
            ("ldaps", False, ca_cert_file, False, True),
            ("ldaps", False, ca_cert_file, True, True),
        ]

        print("> Proto  STARTTLS  CA cert      Checking  Result        Happy?")
        print("> ------------------------------------------------------------")
        ok_cases = 0
        for proto, start_tls, cert_file, checking, expected in cases:
            params0 = params.copy()
            uri = params["LDAPURI"]
            params0["LDAPURI"] = proto + uri[uri.find(":") :]
            params0["EnforceTLS"] = start_tls
            current_app.config["TLS_CA_CERTIFICATES_FILE"] = cert_file
            params0["only_trusted_certs"] = checking
            with current_app.test_request_context():
                try:
                    result = resolver_request(params0, silent=True)
                except ldap.SERVER_DOWN:
                    pass
                cf_available = (
                    "Unavailable" if cert_file == "/dev/null" else "Available"
                )
                print(
                    f". {proto:5s}   {start_tls!r:5s}    {cf_available:11s} "
                    f" {'Enabled' if checking else 'Disabled':8s} "
                    f" {'Connected' if result else 'Not connected':13s} "
                    f" {'Yes' if result == expected else 'No'}"
                )
                if result == expected:
                    ok_cases += 1
        print(f"\n{ok_cases} out of {len(cases)} cases correct")
        sys.exit(1 - (ok_cases == len(cases)))  # 0=OK, 1=failure

    with current_app.test_request_context():
        result = resolver_request(params, silent=current_app.echo.verbosity == 0)
        sys.exit(0 if result else 1)


# eof #########################################################################

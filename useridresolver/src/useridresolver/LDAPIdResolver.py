# -*- coding: utf-8 -*-

#
#   LinOTP - the open source solution for two factor authentication
#   Copyright (C) 2010 - 2016 LSE Leading Security Experts GmbH
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
#   E-mail: linotp@lsexperts.de
#   Contact: www.linotp.org
#   Support: www.lsexperts.de
#
""" This module implements the communication
                and data mapping to LDAP servers.
                The LinOTPd imports this module to
                use LDAP servers as a userstore.

  Dependencies: UserIdResolver
"""

import logging
import ldap
import ldap.filter
from json import loads

import binascii
from hashlib import sha1
from datetime import datetime
import tempfile

from ldap.controls import SimplePagedResultsControl

from useridresolver.UserIdResolver import UserIdResolver
from useridresolver.UserIdResolver import ResolverLoadConfigError
from useridresolver.UserIdResolver import getResolverClass


log = logging.getLogger(__name__)

DEFAULT_UID_TYPE = "DN"  # can be entryUUID, GUID, objectGUID or DN
# DEFAULT_UID_TYPE = "entryUUID"
ENCODING = 'utf-8'
DEFAULT_SIZELIMIT = 500
BIND_NOT_POSSIBLE_TIMEOUT = 30
TIMEOUT_NO_LIMIT = -1


def escape_filter_chars(filterstr):
    """
    Replace all special characters found in filterstr by quoted notation
    - used especially for search with guid - which consists of binary data
    from http://sourceforge.net/p/python-ldap/feature-requests/7/

    :param filterstr: the unescaped filte string
    :return: escaped filter string
    """
    ret = []
    for c in filterstr:
        if c < '0' or c > 'z' or c in "\\*()":
            c = "\\%02x" % ord(c)
        ret.append(c)
    return ''.join(ret)


def _set_cacertificate(cacertificates, ca_dir=None):
    '''
    This function sets the CA certfificate.
    It creates a temporary file if it does not exist.

    :param cacertificate: CA certificates that should be used for
                          LDAP connections
    :type cacertificate: list
    :return: the cert file name or None
    '''
    ca_file = None
    if len(cacertificates) == 0:
        log.debug("[_set_cacertificate] No CA certificate.")
        return ca_file

    # Either set the ca file to be located in the linotp cache_dir or if it
    # does not exist, in a temporaty directory.
    if ca_dir is None:
        ca_dir = tempfile.gettempdir()
    ca_file = "%s/linotp_ldap_cacerts.pem" % ca_dir

    # As the CA certificate can be written on every first request
    # after the server start, we do not need to verify the old certificate.
    try:
        fil = open(ca_file, "w")
        for cacert in cacertificates:
            cert = cacert.strip()
            if ("-----BEGIN CERTIFICATE-----" in cert and
               "-----END CERTIFICATE-----" in cert):
                fil.write(cert)
                fil.write("\n")
        fil.close()
    except Exception as exc:
        log.exception("[_set_cacertificate] Error creating CA certificate"
                      " file: %r. %r" % (ca_file, exc))
        raise exc

    log.debug("[_set_cacertificate] setting file %s" % ca_file)
    reload(ldap)
    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, ca_file)
    ca_file = ldap.get_option(ldap.OPT_X_TLS_CACERTFILE)

    return ca_file


class IdResolver (UserIdResolver):
    '''
    LDAP User Id resolver
    '''

    nameDict = {}
    conf = ""

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

    searchFields = {
          "username": "text",
          "userid": "text",
          "description": "text",
          "email": "text",
          "givenname": "text",
          "surname": "text"
          }

    # The mapping of these search fields to the ldap attributes it
    # stored in self.userinfo

    CERTFILE = None

    ca_certs = set()
    ca_dir = None

    @classmethod
    def setup(cls, config=None, cache_dir=None):
        '''
        this setup hook is triggered, when the server
        starts to serve the first request

        On this first call the CA certificate for the LDAP module is
        verified and set - if the CA certificate is specified.

        :param config: the linotp config
        :type  config: the linotp config dict
        '''

        log.info("[setup] Setting up the LDAPResolver")
        log.info("[setup] Finding CA certificate")

        ca_resolvers = []

        cls.ca_dir = cache_dir

        log.info("Setting up the LDAPResolver")
        if config is not None:
            for entry in config:
                if entry.startswith('linotp.ldapresolver.CACERTIFICATE'):
                    cacertificate = config.get(entry)
                    if (cacertificate is not None and
                        len(cacertificate) > 0 and
                        "-----BEGIN CERTIFICATE-----" in cacertificate and
                       "-----END CERTIFICATE-----" in cacertificate):
                        cert = cacertificate.strip().replace('\r\n', '\n')
                        cls.ca_certs.add(cert)
                        ca_resolvers.append(entry.split('.')[3])

        if len(cls.ca_certs) > 0:
            if cls.ca_dir is None:
                cls.ca_dir = tempfile.gettempdir()
            cls.CERTFILE = _set_cacertificate(cls.ca_certs, ca_dir=cls.ca_dir)
            log.info("[setup] Using CA certificate from the following"
                     " resolvers %r", ca_resolvers)
        else:
            cls.CERTFILE = None

        return

    @classmethod
    def testconnection(cls, params):
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
            - CACERTIFICATE
        """

        old_cert_file = None
        l = None
        status = "success"

        try:
            # do a bind
            uri = params['LDAPURI']
            l = ldap.initialize(uri, trace_level=0)

            if uri.startswith('ldaps'):
                # for test purpose, we create a temporary file
                # with only this cert
                old_cert_file = ldap.get_option(ldap.OPT_X_TLS_CACERTFILE)

                # put all certs in a set
                test_set = set()
                test_set.update(cls.ca_certs)
                # including the test one
                cert = params.get('CACERTIFICATE')
                test_set.add(cert.strip().replace('\r\n', '\n'))

                cls.CERTFILE = _set_cacertificate(test_set, ca_dir=cls.ca_dir)

            # referrals for AD
            log.debug("[testconnection] checking noreferrals: %s",
                      params.get('NOREFERRALS', "False"))

            if "True" == params.get('NOREFERRALS', "False"):
                l.set_option(ldap.OPT_REFERRALS, 0)

            timeout = params['TIMEOUT']
            if ";" in timeout:
                network_timeout, response_timeout = timeout.split(';')
                network_timeout = float(network_timeout.strip())
                response_timeout = float(response_timeout.strip())
            else:
                network_timeout = float(timeout.strip())
                response_timeout = TIMEOUT_NO_LIMIT

            l.network_timeout = network_timeout
            l.timeout = response_timeout

            dn_encode = params['BINDDN'].encode(ENCODING)
            pw_encode = params['BINDPW'].encode(ENCODING)
            l.simple_bind_s(dn_encode, pw_encode)

            # get a userlist:
            resultList = []
            searchFilter = "(&" + params['LDAPSEARCHFILTER'] + ")"
            sizelimit = int(DEFAULT_SIZELIMIT)

            try:
                sizelimit = int(params.get("SIZELIMIT", DEFAULT_SIZELIMIT))
            except ValueError:
                sizelimit = int(DEFAULT_SIZELIMIT)

            ldap_result_id = l.search_ext(params['LDAPBASE'],
                                          ldap.SCOPE_SUBTREE,
                                          filterstr=searchFilter,
                                          sizelimit=sizelimit)
            while 1:
                userdata = {}
                result_type, result_data = l.result(ldap_result_id, 0)
                if (result_data == []):
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

        except ldap.LDAPError as err:
            status = "error"
            log.exception("[testconnection] LDAP Error: %r", err)
            return (status, str(err))

        finally:
            # unbind
            if l:
                l.unbind_s()
            # restore the old_cert_file
            if old_cert_file is not None:
                cls.CERTFILE = _set_cacertificate(cls.ca_certs,
                                                  ca_dir=cls.ca_dir)

        return (status, resultList)

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
        self.proxy = False
        self.uidType = DEFAULT_UID_TYPE
        self.l_obj = None

    def close(self):
        """
        closes method is called, when the request ends
        - here we close the ldap connection by unbind
        """

        try:
            if self.l_obj is not None:
                self.l_obj.unbind_s()

        except ldap.LDAPError as  error:
            log.warning("[unbind] LDAP error: %r", error)

        finally:
            self.l_obj = None

    def bind(self):
        """
        bind() - this function starts an ldap conncetion
        """

        if self.l_obj is not None:
            return self.l_obj

        if self.bind_not_possible:
            t2 = datetime.now()
            tdelta = t2 - self.bind_not_possible_time
            # If we try a bind within 30 seconds, we will
            # bail out!
            if tdelta.seconds > BIND_NOT_POSSIBLE_TIMEOUT or tdelta.days > 1:
                log.info("[bind] Resetting the bind_not_possible timeout.")
                self.bind_not_possible = False
            else:
                log.error("[bind] LDAP bind timed out the last time. "
                          "So we do not try to bind again at this moment. "
                          "Skipping for performance sake! "
                          "Trying a real bind again in %r seconds"
                          % (BIND_NOT_POSSIBLE_TIMEOUT - tdelta.seconds))
                return False

        uri = ""
        urilist = self.ldapuri.split(',')
        i = 0
        log.debug("[bind] trying to bind to one of the servers: %r" % urilist)
        l_obj = None
        while i < len(urilist):
            uri = urilist[i]
            try:
                log.debug("[bind] LDAP: Try to bind to %r", uri)
                l_obj = ldap.initialize(uri, trace_level=0)

                if uri.startswith('ldaps'):
                    # the setting of the CERTFILE is required only once
                    old_cert_file = ldap.get_option(ldap.OPT_X_TLS_CACERTFILE)
                    if self.CERTFILE is not None and old_cert_file is None:
                        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,
                                        self.CERTFILE)

                # referrals for AD
                log.debug("[bind] checking noreferrals: %r" % self.noreferrals)
                if self.noreferrals:
                    l_obj.set_option(ldap.OPT_REFERRALS, 0)

                # setup both timeouts, for network and response
                l_obj.network_timeout = self.network_timeout
                l_obj.timeout = self.response_timeout

                # This is HIGH debug
                # log.debug("[bind] %s, %s" %(self.binddn, self.bindpw))
                dn_encode = self.binddn.encode(ENCODING)
                pw_encode = self.bindpw.encode(ENCODING)
                l_obj.simple_bind_s(dn_encode, pw_encode)
                if i > 0:
                    urilist[i] = urilist[0]
                    urilist[0] = uri
                    self.ldapuri = ','.join(urilist)

                self.l_obj = l_obj
                return l_obj
            except ldap.LDAPError as  e:
                log.exception("[bind] LDAP error: %r" % e)
                i = i + 1
        # We were not able to do a successful bind! :-(
        self.bind_not_possible = True
        self.bind_not_possible_time = datetime.now()
        self.l_obj = l_obj
        return l_obj

    def unbind(self, lobj):
        """
        unbind() - this function formarly freed the ldap connection
        which is now done in the class destructor __del__()

        :param l: ldap object
        :return: empty string
        """

        return

    def getUserId(self, loginname):
        '''
        return the userId which mappes to an loginname

        :param loginName: login name of the user
        :type loginName:  string

        :return: userid - unique idenitfier for this unser
        :rtype:  string
        '''

        userid = ''

        log.debug("[getUserId] resolving userid for %r: %r"
                  % (type(loginname), loginname))

        if type(loginname) == unicode:
            # we are called from external by an unicode string
            LoginName = loginname.encode(ENCODING)

        elif type(loginname) == str:
            # we might be called internaly, so the loginname is of utf-8 str
            LoginName = loginname

        else:
            log.error("[getUserId] Unsopported type of loginname (%r): %s"
                      % (loginname, type(loginname)))
            return userid

        if len(loginname) == 0:
            return userid

        log.debug("[getUserId] type of LoginName %s", type(LoginName))
        ufilter = self._replace_macros(self.filter)
        fil = ldap.filter.filter_format(ufilter,
                                        [LoginName.decode(ENCODING)])
        fil = fil.encode(ENCODING)
        l_obj = self.bind()

        if not l_obj:
            return userid

        attrlist = []
        if self.uidType.lower() != "dn":
            attrlist.append(self.uidType)

        resultList = None
        try:
            # log.error("%r : %r" % (self.uidType, attrlist))
            l_id = l_obj.search_ext(self.base,
                                    ldap.SCOPE_SUBTREE,
                                    filterstr=fil,
                                    sizelimit=self.sizelimit,
                                    attrlist=attrlist,
                                    timeout=self.response_timeout)

            resultList = l_obj.result(l_id, all=1)[1]
        except ldap.LDAPError as exc:
            log.exception("[getUserId] LDAP error: %r", exc)
            resultList = None

        finally:
            self.unbind(l_obj)

        if not resultList:
            log.info("[getUserId] : empty result ")
            return userid
        log.debug("[getUserId] : resultList :%r: ", resultList)
        log.debug('[getUserId] : uidType: %r ', self.uidType)

        # [0][0] is the distinguished name

        res = None

        if self.uidType.lower() == "dn":
            res = resultList[0][0]
            if res is not None:
                userid = unicode(res, ENCODING)

        elif self.uidType.lower() == "objectguid":
            res = resultList[0][1]
            if res is not None:
                userid = None
                # we have to check the objectguid key case insentitiv !!!
                for key in res:
                    if key.lower() == self.uidType.lower():
                        guid = res.get(key)[0]
                        userid = self.guid2str(guid)
                if userid is None:
                    # should never be reached:
                    raise Exception('[getUserId] - objectguid: no userid '
                                    'found %r' % (res))
        else:
            # Ticket #754
            if len(resultList) == 0:
                log.info("[getUserId] resultList is empty")
            else:
                res = resultList[0][1]
                if res is not None:
                    for key in res:
                        if key.lower() == self.uidType.lower():
                            userid = res.get(key)[0]

        if res is None or not userid:
            log.info("[getUserId] : empty result for  %r - uidtype: %r"
                     % (loginname, self.uidType.lower()))
        else:
            log.debug("[getUserId] userid: %r:%r" % (type(userid), userid))
            uname_hash = sha1(userid.encode("utf-8")).digest()
            log.debug(binascii.hexlify(uname_hash))

        return userid

    def getUsername(self, userid):
        '''
        get the loginname from the given userid

        :param userId: userid descriptor
        :type userId: string

        :return: loginname
        :rtype:  string
        '''

        log.debug("[getUsername]")

        username = u''

        # getUserLDAPInfo returns (now) a list of unicode values
        l_user = self.getUserLDAPInfo(userid)

        if self.loginnameattribute in l_user:
            username = l_user[self.loginnameattribute]
        return username

    def getUserLDAPInfo(self, userid):
        """
        getUserLDAPInfo(UserId)

        This function returns all user information for a given user object
        identified by UserID. In LDAP case this is the DN, but could also be
        'objectguid' or uidtype

        :param userid: user identifier (in unicode)
        :type  userid: unicode or str

        :return: user info dict
        :rtype: dict

        """
        log.debug("[getUserLDAPInfo]")

        # change unicode to utf-8 str
        UserId = userid.encode(ENCODING)

        resultList = {}

        l_id = 0
        l_obj = self.bind()

        if l_obj:
            try:
                if self.uidType.lower() == "dn":
                    l_id = l_obj.search_ext(UserId,
                                            ldap.SCOPE_BASE,
                                            filterstr="ObjectClass=*",
                                            sizelimit=self.sizelimit)

                elif self.uidType.lower() == "objectguid":
                    if not self.proxy:
                        l_id = l_obj.search_ext("<guid=%s>" % (UserId),
                                                ldap.SCOPE_BASE,
                                                sizelimit=self.sizelimit,
                                                timeout=self.response_timeout)
                    else:
                        e_u = escape_filter_chars(binascii.unhexlify(UserId))
                        filterstr = "(ObjectGUID=%s)" % (e_u)
                        l_id = l_obj.search_ext(self.base,
                                                ldap.SCOPE_SUBTREE,
                                                filterstr=filterstr,
                                                sizelimit=self.sizelimit,
                                                timeout=self.response_timeout)
                else:
                    # Ticket #754
                    filterstr = "(%s=%s)" % (self.uidType, UserId)
                    l_id = l_obj.search_ext(self.base,
                                            ldap.SCOPE_SUBTREE,
                                            filterstr=filterstr,
                                            sizelimit=self.sizelimit,
                                            timeout=self.response_timeout)

                r = l_obj.result(l_id, all=1)[1]

                if r:
                    resList = r[0][1]
                    resList["dn"] = [r[0][0]]

                    resultList = {}

                    # now convert the resList to unicode:
                    #   dict of list(UTF-8)
                    for key in resList:
                        val = resList.get(key)
                        rval = val

                        if type(val) == list:
                            # val should be a list of utf str
                            rval = []
                            for v in val:
                                try:
                                    if type(v) == str:
                                        rval.append(v.decode(ENCODING))
                                    else:
                                        rval.append(v)
                                except:
                                    rval.append(v)
                                    log.debug('[getUserLDAPInfo] failed to '
                                              'decode data type %r: %r'
                                              % (type(v), v))

                        elif type(val) == str:
                            # or val might be a direct utf-8 str
                            try:
                                rval = val.decode(ENCODING)
                            except:
                                rval = val
                                log.debug('[getUserLDAPInfo] failed to decode '
                                          'data type %r: %r'
                                          % (type(val), val))
                        else:
                            # this should not be reached -
                            # so anything different is treated as unknown
                            rval = val
                            log.warning('[getUserLDAPInfo] unknown and '
                                        'unsupported LDAP return data type'
                                        ' %r: %r' % (type(val), val))

                        resultList[key] = rval

            except ldap.LDAPError as  e:
                log.exception("[getUserLDAPInfo] LDAP error: %s" % str(e))

            finally:
                if l_obj is not None:
                    self.unbind(l_obj)

        return resultList

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

        ret = {}

        user = self.getUserLDAPInfo(userid)

        if len(user) > 0:
            ret['userid'] = userid
            '''
            for f in self.fields:
                if f in self.userinfo:
                    if self.userinfo[f] in user:
                        # FIXME: when we return [0], we return only the first
                        # value of a possible list i.e. if there are 2
                        # telephoneNumbers, we return only the first one.
                        ret[ f ] = user[ self.userinfo[f] ][0]
                    else:
                        ret[ f ] = ''

            # Now add the values from the userinfo/mapping
            # which are NOT in the self.fields.
            for f in self.userinfo:
                if f not in self.fields:
                    if self.userinfo[f] in user:
                        ret[ f ] = user[ self.userinfo[f] ][0]
                    else:
                        ret[ f ] = ''

            Bottom-line: we will add all userinfo fields!
            '''
            for f in self.userinfo:
                if self.userinfo[f] in user:
                    ret[f] = user[self.userinfo[f]][0]
                else:
                    ret[f] = ''

        return ret

    def getResolverId(self):
        '''
        getResolverId - provide the resolver identifier

        :return: returns the resolver identifier string or empty string
                    if not exist
        :rtype : string

        '''
        log.debug("[getResolverId]")
        resolver = u"LDAPIdResolver.IdResolver"
        if self.conf != "":
            resolver = resolver + "." + self.conf
        return resolver

    def getConfigEntry(self, config, key, conf, required=True, default=""):
        '''
        getConfigEntry - retrieve an entry from the config

        :param config: dict of all configs
        :type  config: dict
        :param key: key which is searched
        :type key: string
        :param conf: scope of the config eg. connect.sql
        :type conf: string
        :param required: if this value ist true and the key is not defined, an
                         exception sill be raised
        :type required:  boolean
        :param default: fallback value if confg has no such entry
        :type default: any

        :return: the value of the specified key
        :rtype:  value type - in most cases string ;-)

        '''
        log.debug("[getConfigEntry]")

        ckey = key
        cval = default
        config_found = False
        log.debug("[getConfigEntry] searching key %r in config %r"
                  % (key, conf))
        if conf:
            ckey = ckey + "." + conf
            if ckey in config:
                config_found = True
                cval = config[ckey]

        if cval == "":
            if key in config:
                config_found = True
                cval = config[key]

        if required and not config_found:
            log.error("[getConfigEntry] missing config entry %s in config %s"
                      % (key, conf))
            self.brokenconfig = True
            self.brokenconfig_text = ("Broken Config: missing config entry "
                                      "%s in config %s" % (key, conf))
            raise Exception("missing config entry: %s in config %s"
                            % (key, config))

        return cval

    @classmethod
    def getResolverClassType(cls):
        return 'ldapresolver'

    def getResolverType(self):
        '''
        getResolverType - return the type of the resolver

        :return: returns the string 'ldapresolver'
        :rtype:  string
        '''
        return IdResolver.getResolverClassType()

    @classmethod
    def getResolverClassDescriptor(cls):
        '''
        return the descriptor of the resolver, which is
        - the class name and
        - the config description

        :return: resolver description dict
        :rtype:  dict
        '''

        log.debug("[getResolverDescriptor]")

        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor['clazz'] = "useridresolver.LDAPIdResolver.IdResolver"
        descriptor['config'] = {'LDAPFILTER': 'string',
                                'LDAPSEARCHFILTER': 'string',
                                'LDAPURI': 'string',
                                'LDAPBASE': 'string',
                                'BINDDN': 'string',
                                'BINDPW': 'password',
                                'LOGINNAMEATTRIBUTE': 'string',
                                'USERINFO': 'string',
                                'TIMEOUT': 'float',
                                'SIZELIMIT': 'int',
                                'NOREFERRALS': 'string',
                                }
        return {typ: descriptor}

    def getResolverDescriptor(self):
        return IdResolver.getResolverClassDescriptor()

    def loadConfig(self, config, conf=""):
        '''
        loadConfig - load the config for the resolver
            The calling applications passes the LDAP configuration:
            FILTER
            LDAPURI
            BASE
            BINDDN
            BINDPW

        :param config: configuration for the sqlresolver
        :type  config: dict
        :param conf: configuration postfix
        :type  conf: string
        '''

        log.debug("[loadConfig] Config:  %r" % config)
        log.debug("[loadConfig] Conf  :  %r" % conf)
        self.conf = conf
        self.filter = self.getConfigEntry(config,
                                          "linotp.ldapresolver.LDAPFILTER",
                                          conf)
        self.searchfilter = self.getConfigEntry(config,
                                                "linotp.ldapresolver."
                                                "LDAPSEARCHFILTER", conf)
        self.ldapuri = self.getConfigEntry(config,
                                           "linotp.ldapresolver.LDAPURI", conf)
        self.base = self.getConfigEntry(config,
                                        "linotp.ldapresolver.LDAPBASE", conf)
        self.binddn = self.getConfigEntry(config,
                                          "linotp.ldapresolver.BINDDN", conf,
                                          required=False)

        self.loginnameattribute = self.getConfigEntry(config,
                                                      "linotp.ldapresolver."
                                                      "LOGINNAMEATTRIBUTE",
                                                      conf)
        userinfo = self.getConfigEntry(config,
                                       "linotp.ldapresolver.USERINFO", conf)
        try:
            self.userinfo = loads(userinfo)
        except ValueError as exx:
            raise ResolverLoadConfigError("Invalid userinfo - no json "
                                          "document: %s %r" % (userinfo, exx))

        # support to setup both timeouts: network timeout and response timeout
        #  separator ';' splits network from response timeout
        timeout = self.getConfigEntry(config,
                                      "linotp.ldapresolver.TIMEOUT", conf)
        if ';' in timeout:
            network_timeout, response_timeout = timeout.split(';')
            network_timeout = float(network_timeout)
            response_timeout = float(response_timeout)
        else:
            network_timeout = float(timeout)
            response_timeout = TIMEOUT_NO_LIMIT

        self.network_timeout = float(network_timeout)
        self.timeout = float(response_timeout)

        sizelimit = self.getConfigEntry(config,
                                        "linotp.ldapresolver.SIZELIMIT",
                                        conf, required=False,
                                        default=DEFAULT_SIZELIMIT)

        self.uidType = self.getConfigEntry(config,
                                           "linotp.ldapresolver.UIDTYPE",
                                           conf, required=False,
                                           default=DEFAULT_UID_TYPE)

        if self.uidType is None or self.uidType.strip() == "":
            self.uidType = DEFAULT_UID_TYPE
        if type(self.uidType) in [unicode]:
            log.info("[loadConfig] conversion of self.uidType: %r to str()",
                     self.uidType)
            self.uidType = str(self.uidType)

        try:
            self.sizelimit = int(sizelimit)
        except ValueError:
            self.sizelimit = int(DEFAULT_SIZELIMIT)
        except TypeError:
            self.sizelimit = int(DEFAULT_SIZELIMIT)
        log.debug("[loadConfig: the sizelimit is: %s, %i"
                  % (sizelimit, self.sizelimit))

        noreferrals = self.getConfigEntry(config,
                                          "linotp.ldapresolver.NOREFERRALS",
                                          conf,
                                          required=False, default="False")
        self.noreferrals = ("True" == noreferrals)

        proxy = self.getConfigEntry(config,
                                    "linotp.ldapresolver.PROXY", conf,
                                    required=False, default="False")
        self.proxy = ("True" == proxy)

        try:
            self.bindpw = self.getConfigEntry(config,
                                              "enclinotp.ldapresolver.BINDPW",
                                              conf)
        except:
            # if no enclinotp, the password obviously is not encrypted!
            self.bindpw = self.getConfigEntry(config,
                                              "linotp.ldapresolver.BINDPW",
                                              conf, required=False)

        self.cacertificate = self.getConfigEntry(config,
                                                 "linotp.ldapresolver."
                                                 "CACERTIFICATE", conf,
                                                 required=False, default=None)

        return self

    def getSearchFields(self, searchDict=None):
        '''
        return all fields on which a search could be made

        :return: dictionary of the search fields and their types - not used!!
        :rtype:  dict
        '''
        log.debug("[getSearchFields]")
        return self.searchFields

    def searchLDAPUserList(self, key, value):
        """
        finds the user objects, that have the term 'value' in the
                user object field 'key'

        :param key: The key may be an ldap attribute like 'loginname'
                      or 'email'.
        :type  key: string
        :param value: The value is a regular expression.
        :type value:string

        :return:  a list of dictionaries (each dictionary contains a
                    user object) or an empty string if no object is found.
        :rtype: list
        """

        log.debug("[searchLDAPUserList]")

        searchFilter = key + "=" + value
        resultList = []
        l_obj = self.bind()
        if l_obj:
            try:
                ldap_result_id = l_obj.search_ext(self.base,
                                                  ldap.SCOPE_SUBTREE,
                                                  filterstr=searchFilter,
                                                  sizelimit=self.sizelimit,
                                                  timeout=self.response_timeout
                                                  )
                while 1:
                    result_type, result_data = l_obj.result(ldap_result_id, 0,
                                                            timeout=self.response_timeout)
                    if (result_data == []):
                        break
                    else:
                        if result_type == ldap.RES_SEARCH_ENTRY:
                            resultList.append(result_data)

            except ldap.LDAPError as exc:
                log.exception("[searchLDAPUserList] LDAP error: %r", exc)

            self.unbind(l_obj)
            if resultList:
                return resultList
        return resultList

    def _getUserDN(self, uid):
        '''
        This function takes the UID and returns the DN of the user object
        '''
        DN = self.getUserLDAPInfo(uid).get("dn")[0]
        return DN

    def checkPass(self, uid, password):
        '''
        checkPass - checks the password for a given uid.

        :param uid: userid to be checked
        :type  uid: string
        :param password: user password
        :type  password: string

        :return :  true in case of success, false if password does not match
        :rtype :   boolean

        :attention: First the UID needs to be converted to the DN, in
                        case the Uid is not the DN
        '''

        # Patch:
        #   simple bind allows anonymous authentication which raises no
        #   exception, so we return immediately if no password is given
        #

        log.debug("[checkPass]")

        if password is None or len(password) == 0:
            return False

        if type(password) == unicode:
            password = password.encode(ENCODING)

        if type(uid) == unicode:
            uid = uid.encode(ENCODING)

        log.debug("[checkPass] uidType: %r", self.uidType)
        if self.uidType.lower() == 'dn':
            DN = uid
        else:
            DN = self._getUserDN(uid)

        if type(DN) == unicode:
            DN = DN.encode(ENCODING)

        log.debug("[checkPass] DN: %r", DN)

        uri = ""
        urilist = self.ldapuri.split(',')

        i = 0

        log.debug("[checkPass] we will try to authenticate to these LDAP "
                  "servers: %r", urilist)

        while i < len(urilist):
            uri = urilist[i]
            l = None
            try:
                log.info("[checkPass] check password for user %r "
                         "on LDAP server %r" % (DN, uri))
                l = ldap.initialize(uri, trace_level=0)

                # referrals for AD
                log.debug("[checkPass] checking noreferrals: %s",
                          self.noreferrals)

                if self.noreferrals:
                    l.set_option(ldap.OPT_REFERRALS, 0)

                # set the network connection timeout
                l.network_timeout = self.network_timeout

                # set the response timeout
                l.timeout = self.response_timeout

                l.simple_bind_s(DN, password)
                log.info("[checkPass] ldap bind for %r successful", DN)
                return True

            except ldap.INVALID_CREDENTIALS as exc:
                log.warning("[checkPass] invalid credentials: %r", exc)
                break

            except ldap.LDAPError as  exc:
                log.warning("[checkPass] checking password failed: %r", exc)

            finally:
                if l is not None:
                    l.unbind_s()

            i = i + 1
        return False

    def guid2str(self, guid):
        '''
        convert the binary MS AD GUID to something that could be displayed
          http://support.microsoft.com/kb/325649

        :param guid: binary value
        :type  guid: binary

        :return: string representation of the guid
        :rtype:  string
        '''
        log.debug("[guid2str] converting MS AD GUID: %r", guid)
        res = binascii.hexlify(guid)
        return res

    def _is_ad(self):
        """
        this is a heuristic approach to check if we are running against an AD
        check is running against the ldap config where we expect to have an
        sAMAccountname in any filter or login attribute
        """
        ret = False
        if ('sAMAccountName' in self.loginnameattribute or
            'sAMAccountName' in self.searchfilter or
           'sAMAccountName' in self.filter):
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
            now = ((now * 10000000) + add_seconds)
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
        special_dict['now'] = self.now_timestamp()

        try:
            for key, val in special_dict.items():
                search_st = "%(" + key + ")s"
                if search_st in substitute:
                    substitute = substitute.replace(search_st, val)

        except KeyError as key_error:
            log.exception('Key replacement error %r', key_error)
            raise key_error

        return substitute

    def getUserList(self, searchDict):
        '''
        retrieve a list of users

        :param searchDict: dictionary of the search criterias
        :type  searchDict: dict
        :return: resultList, a dict with user info
        '''

        # TODO: check if field is searchable
        # several filters are & concatenated:
        #   (&(objectClass=inetOrgPerson)(uid=theodor))
        # if we got an empty search dictionary, we will get all users!

        log.debug("[getUserList]")

        # add specialdict replacements, to support the "%(now)s" expression
        searchFilter = self._replace_macros(self.searchfilter)

        log.debug("[getUserList] searchfilter: %r", searchFilter)

        # add searchfilter attributes of searchDict
        try:
            for skey, sval in searchDict.iteritems():
                log.debug("[getUserList] searchekys: %r / %r" % (skey, sval))
                if skey in self.userinfo:
                    key = self.userinfo[skey]
                    value = searchDict[skey]
                    # value and searchFilter are Unicode!
                    searchFilter += u"(%s=%s)" % (key, value)
                else:
                    log.warning("[getUserList] Unknown searchkey: %r", skey)

            # finaly embedd the filter in the ldap query string
            searchFilter = u"(& %s )" % searchFilter
            log.debug("[getUserList] searchfilter: %r", searchFilter)

        except Exception as exep:
            log.exception("[getUserList] Error creating searchFilter: %r",
                          exep)
            raise exep

        resultList = []
        l_obj = self.bind()

        if l_obj:
            try:
                log.debug("[getUserList] doing search with filter %r",
                          searchFilter)
                log.debug("[getUserList] type of searchfilter: %r",
                          type(searchFilter))

                attrlist = []
                for ukey, uval in self.userinfo.iteritems():
                    attrlist.append(str(uval))
                if self.uidType.lower() != "dn":
                    attrlist.append(self.uidType)

                searchFilterStr = searchFilter.encode(ENCODING)
                ldap_result_id = l_obj.search_ext(self.base,
                                                  ldap.SCOPE_SUBTREE,
                                                  filterstr=searchFilterStr,
                                                  sizelimit=self.sizelimit,
                                                  attrlist=attrlist,
                                                  timeout=self.response_timeout
                                                  )

                log.debug('[getUserList] uidType: %r' % self.uidType)
                while 1:
                    userdata = {}
                    result_type, result_data = l_obj.result(ldap_result_id, 0,
                                                            timeout=self.response_timeout)
                    # print result_type, ldap.RES_SEARCH_ENTRY, result_data
                    if (result_data == []):
                        break
                    else:
                        if result_type == ldap.RES_SEARCH_ENTRY:
                            # compose response as we like it
                            if self.uidType.lower() == "dn":
                                userdata["userid"] = \
                                        unicode(result_data[0][0], ENCODING)

                            elif self.uidType.lower() == "objectguid":
                                # res =
                                # result_data[0][1].get(self.uidType,[None])[0]
                                userid = None
                                # resDN  = result_data[0][0]
                                resData = result_data[0][1]

                                # in case of objectguid, we have to
                                # check case insensitiv!!!
                                for key in resData:
                                    if key.lower() == self.uidType.lower():
                                        res = resData.get(key)[0]
                                        userid = self.guid2str(res)

                                if userid != None:
                                    userdata["userid"] = userid
                                else:
                                    # should never be reached!!
                                    raise Exception('No Userid found')
                            else:
                                # Ticket #754
                                userdata["userid"] = \
                                 result_data[0][1].get(self.uidType, [None])[0]

                            for ukey, uval in self.userinfo.iteritems():
                                if uval in result_data[0][1]:
                                    # An attribute can hold more than 1 value
                                    # So we only take the first one at the
                                    # moment
                                    #   result_data[0][1][v][0]
                                    # If we want to get all
                                    #   result_data[0][1][v] gives us a list
                                    rdata = result_data[0][1][uval][0]
                                    try:
                                        udata = rdata.decode(ENCODING)
                                    except:
                                        udata = rdata
                                    userdata[ukey] = udata

                            resultList.append(userdata)

            except ldap.LDAPError as exce:
                log.exception("[getUserList] LDAP error: %r", exce)

            except Exception as exce:
                log.exception("[getUserList] error during LDAP access: %r",
                              exce)

            self.unbind(l_obj)

            if resultList:
                return resultList

        return ""

    def _prepare_searchFilter(self, searchDict):
        '''
        prepare the search Expression for the userListIterator

        :param searchDict: dictionary of the search criterias
        :type  searchDict: dict
        :return: resultList, a dict with user info
        '''

        # TODO: check if field is searchable
        # several filters are & concatenated:
        #   (&(objectClass=inetOrgPerson)(uid=theodor))
        # if we got an empty search dictionary, we will get all users!

        log.debug("[getUserList]")

        # we support special replacements in search expressions like
        # %(now)s which will be replaced by the windows or unix timestamp
        special_dict = {}
        special_dict['now'] = self.now_timestamp()

        searchFilter = self.searchfilter
        # add specialdict replacements, to support the "%(now)s" expression
        try:
            searchFilter = searchFilter % special_dict
        except KeyError as key_error:
            log.exception('Key replacement error %r', key_error)
            raise key_error

        log.debug("[getUserList] searchfilter: %r", searchFilter)

        # add searchfilter attributes of searchDict
        try:
            for skey, sval in searchDict.iteritems():
                log.debug("[getUserList] searchekys: %r / %r" % (skey, sval))
                if skey in self.userinfo:
                    key = self.userinfo[skey]
                    value = searchDict[skey]
                    # value and searchFilter are Unicode!
                    searchFilter += u"(%s=%s)" % (key, value)
                else:
                    log.warning("[getUserList] Unknown searchkey: %r", skey)

            # finaly embedd the filter in the ldap query string
            searchFilter = u"(& %s )" % searchFilter
            log.debug("[getUserList] searchfilter: %r", searchFilter)
        except Exception as exep:
            log.exception("[getUserList] Error creating searchFilter: %r",
                          exep)
            raise exep
        return searchFilter

    def _set_cursor(self, searchFilter, attrlist, l_obj=None, lc=None,
                    serverctrls=None, api_ver=2.4):
        """
        helper function to setup the paging query and shift the cursor

        :param searchFilter: restict the search through the searchFilter
        :param attrlist: list of attributes, which should be returned
        :param l_obj: the ldap connection object - if none, we bind() it
        :param lc: the page result controller
        :param serverctrls: the srv.ctrl response of the ldap.result3
        :param api_ver: either 2.3 or 2.4, the ldap api changed in between :-(
        :return: tupple of (message id, ldap connection object and page
                 controller)
        """
        page_size = 100
        # we take the sizelimit as hint for the page size
        if hasattr(self, "sizelimit"):
            page_size = self.sizelimit / 4

        # first request: if lc is not set, we are initializing
        if lc is None:
            l_obj = self.bind()
            if api_ver == 2.4:
                lc = SimplePagedResultsControl(True, size=page_size, cookie='')
            elif api_ver == 2.3:
                PAGE_OID = ldap.LDAP_CONTROL_PAGE_OID
                lc = SimplePagedResultsControl(PAGE_OID, True, (page_size, ''))

        else:
            cookie = None
            pctrls = []

            if api_ver == 2.4:
                for c in serverctrls:
                    if c.controlType == SimplePagedResultsControl.controlType:
                        pctrls.append(c)
                        cookie = c.cookie
                        lc.cookie = cookie

            elif api_ver == 2.3:
                for c in serverctrls:
                    if c.controlType == ldap.LDAP_CONTROL_PAGE_OID:
                        pctrls.append(c)
                        cookie = c.controlValue[1]
                        lc.controlValue = (page_size, cookie)

            if not pctrls:
                raise Exception("Warning: Server ignores RFC 2696 control.")

            if not cookie:
                return (None, None, None)

        # submit search request
        msgid = l_obj.search_ext(self.base,
                                 ldap.SCOPE_SUBTREE,
                                 filterstr=searchFilter.encode(ENCODING),
                                 attrlist=attrlist,
                                 serverctrls=[lc],
                                 timeout=self.response_timeout
                                 )

        return (msgid, l_obj, lc)

    def _api_version(self):
        """
        helper method to detect if the python ldap module supports cursoring
         * debian python-ldap==2.3.11 has support, while pip python-ldap-2.4.19
           has not :-(
        :return: True or False
        """
        ret = 2.3
        try:
            _PAGE_OID = ldap.LDAP_CONTROL_PAGE_OID
        except AttributeError as _exx:
            log.info('using the 2.4 cursoring api.')
            ret = 2.4
        return ret

    def getUserListIterator(self, searchDict, limit_size=True):
        """
        iterator based access to get the list of users
        to prevent server response of sizelimit exceeded

        :param searchDict: the dict with a search filter expression
        :param limit_size: restrict the returned data size to size_limit
        :return: generator object (that yields userlist arrays).
        """
        searchFilter = self._prepare_searchFilter(searchDict)
        log.debug("[getUserListIterator] doing search with filter %r",
                  searchFilter)

        attrlist = []
        for _ukey, uval in self.userinfo.iteritems():
            attrlist.append(str(uval))

        # add the requested unique identifier if it is not the dn
        if self.uidType.lower() != "dn":
            attrlist.append(self.uidType)

        # replace the method pointer to the right place
        api_ver = self._api_version()

        (msgid, l_obj, lc) = self._set_cursor(searchFilter,
                                              attrlist,
                                              api_ver=api_ver)

        done = False
        results_size = 0
        try:

            log.debug('uidType: %r' % self.uidType)
            while not done:

                if limit_size and results_size >= self.sizelimit:
                    raise StopIteration()

                (result_type, result_data,
                 _rmsgid, serverctrls) = l_obj.result3(msgid)

                # shift the cursor to the next page
                (msgid,
                 l_obj, lc) = self._set_cursor(searchFilter,
                                               attrlist,
                                               l_obj=l_obj, lc=lc,
                                               serverctrls=serverctrls,
                                               api_ver=api_ver)

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
            log.exception("LDAP error: %r" % exce)
            raise exce

        except StopIteration as exce:
            log.info("page size reached: (%r) %r" % (results_size, exce))
            raise exce

        except Exception as exce:
            log.exception("Error during LDAP access: %r", exce)
            raise exce

        # we do no unbind here, as this is done at the request end

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
            return userdata

        if self.uidType.lower() == "dn":
            userdata["userid"] = unicode(account_dn, ENCODING)

        elif self.uidType.lower() == "objectguid":
            userid = None
            # in case of objectguid, we have to
            # check case insensitiv if objectGUID is in dict
            for key in account_info:
                if key.lower() == self.uidType.lower():
                    res = account_info.get(key)[0]
                    userid = self.guid2str(res)
                    break
            if userid:
                userdata["userid"] = userid
            else:
                # should never be reached!!
                raise Exception('No Userid found')
        else:
            # suport for arbitrary object identifyier like
            # entryUUID, GUID, objectGUID
            userdata["userid"] = \
                account_info[self.uidType][0]

        # finally add all existing userinfos (wrt the mapping)
        for ukey, uval in self.userinfo.iteritems():
            if uval in account_info:
                # An attribute can hold more than 1 value
                # So we only take the first one at the moment
                #   result_data[0][1][v][0]
                # If we want to get all
                #   result_data[0][1][v] gives us a list
                rdata = account_info[uval][0]
                try:
                    udata = rdata.decode(ENCODING)
                except:
                    udata = rdata
                userdata[ukey] = udata
        return userdata

if __name__ == "__main__":

    print "LDAPIdResolver - IdResolver class test "
    DEFAULT_UID_TYPE = "entryUUID"

    y_res = getResolverClass("LDAPIdResolver", "IdResolver")()

    y_res.loadConfig({
        'linotp.ldapresolver.LDAPFILTER':
        '(&(uid=%s)(ObjectClass=inetOrgPerson))',
        # CKO: need this for getUsername aka loginname
        'linotp.ldapresolver.LDAPSEARCHFILTER':
        '(uid=*)(ObjectClass=inetOrgperson)',
        # this is the base search pattern for userlist
        'linotp.ldapresolver.LOGINNAMEATTRIBUTE': 'uid',
        # CKO: need this for getUserInfo
        'linotp.ldapresolver.USERINFO': (
          '{"username": "uid", "description": "", "phone": "telephoneNumber",'
          ' "groups": "o", "mobile": "mobile", "email": "email",'
          ' "surname": "sn", "givenname": "givenName", "gender" : "" }'),
        'linotp.ldapresolver.LDAPURI': 'ldap://localhost',
        'linotp.ldapresolver.LDAPBASE': 'dc=nodomain',
        'linotp.ldapresolver.BINDDN': 'cn=admin,dc=nodomain',
        'linotp.ldapresolver.BINDPW': 'LDpw.',
        'linotp.ldapresolver.TIMEOUT': '5',
        'linotp.ldapresolver.SIZELIMIT': '10',
        'linotp.ldapresolver.NOREFERRALS': 'False'
        }
        )

    print("- - - - - - - - - - - - - - - -")
    print("The fields that are to be returned:")
    print(y_res.fields)
    print("reId - " + y_res.getResolverId())
    print("- - - - - - - - - - - - - - - -")
    print("getUserId: Get the userId for a given loginname")
    gloginname = "maria"
    dn = y_res.getUserId(gloginname)
    print(gloginname + " --> " + dn)
    print("- - - - - - - - - - - - - - - -")
    print("getUsername: get the loginname for a given ID")
    print("Resolving username....")
    gusername = y_res.getUsername(dn)
    print(dn + " --> " + gusername)
    print("- - - - - - - - - - - - - - - -")
    print("getUserInfo: Infos zum Benutzer " + gloginname)
    print(y_res.getUserInfo(dn))
    print("- - - - - - - - - - - - - - - -")
    print("getUserLDAPInfo: Infos zum Benutzer " + gloginname)
    print(y_res.getUserLDAPInfo(dn))

    print("getUserList({}):")
    ulist = y_res.getUserList({})
    print(len(ulist))
    for user in ulist:
        print(user)

# eof #########################################################################

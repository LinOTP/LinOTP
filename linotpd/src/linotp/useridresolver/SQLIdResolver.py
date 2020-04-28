# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#
#    This file is part of LinOTP userid resolvers.
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
"""
This module implements the communication and data mapping to SQL servers.
The LinOTP server imports this module to use SQL databases as a userstore.

Dependencies: UserIdResolver
"""

import re
import base64
import hashlib
import urllib.request, urllib.parse, urllib.error
import json

import logging

# from sqlalchemy.event import listen

from sqlalchemy import create_engine
from sqlalchemy import types
from sqlalchemy.sql import expression
from sqlalchemy.sql import text as sql_text
from sqlalchemy import Table, MetaData
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import NoSuchColumnError

from typing import Any, Callable, Dict, Tuple, Union

from . import resolver_registry
from linotp.useridresolver.UserIdResolver import UserIdResolver
from linotp.useridresolver.UserIdResolver import ResolverLoadConfigError
from linotp.useridresolver.UserIdResolver import ResolverNotAvailable

from linotp.lib.type_utils import encrypted_data
from linotp.lib.type_utils import text

# ------------------------------------------------------------------------- --

from passlib.exc import MissingBackendError

# establish the passlib crypt context different password formats

from passlib.context import CryptContext

# format like {ssha1}adsadasdad - from the RFC 2307
Ldap_crypt_schemes = [
    "ldap_sha1", "ldap_salted_sha1", "ldap_sha1_crypt",
    "ldap_sha256_crypt", "ldap_sha512_crypt",
    "ldap_bcrypt", "ldap_des_crypt" , "ldap_bsdi_crypt",
    "ldap_md5_crypt", "ldap_md5", "ldap_salted_md5",
]

# format like {ssha1}adsadasdad but not in the RFC 2307
Ldap_similar_crypt_schemes = [
    "atlassian_pbkdf2_sha1", "fshp"
    ]

# format like $identifier$content - MCF: modular crypt format
MCF_crypt_schemes = [
    "md5_crypt", "bcrypt", "bsd_nthash",
    "sha512_crypt", "sha256_crypt", "sha1_crypt", "sun_md5_crypt"
    ]

# other application related password formats
Other_crypt_schemes = [
    "bcrypt_sha256", "phpass" # "argon2" # requires extra install
    ]

# db related password formats
DB_crypt_schemes = [
    "mssql2000", "mssql2005",
    "mysql323", "mysql41", # "postgres_md5", # requires extra install
    "oracle11",
    ]

# legacy password schemes partialy without identifier
Archaic_crypt_schemes = [
    "des_crypt", "bsdi_crypt", "bigcrypt"
    ]


LdapCrypt = CryptContext(
    schemes=Ldap_crypt_schemes + Ldap_similar_crypt_schemes)

MCFCrypt = CryptContext(schemes=MCF_crypt_schemes)

OtherCrypt = CryptContext(schemes=Other_crypt_schemes)

DBCrypt = CryptContext(schemes=DB_crypt_schemes)

ArchaicCrypt = CryptContext(schemes=Archaic_crypt_schemes)

# ------------------------------------------------------------------------- --

DEFAULT_ENCODING = "utf-8"

log = logging.getLogger(__name__)


def check_password(password, crypted_password, salt=None):
    """
    check the crypted password and the optional salt
    for various passsword schemes defining a passlib crypto context

    - {id}pwdata - LDAP format
    - $id$pwdata - modular crypt format
    - other format like the atlasian or php passwords
    - support db format
    - support for archaic formats like Des

    the defintions of the crypto context is made above in the schema lists

    the algorithm iterates over the crypto contexti to identify the type
    of the password and, if salt is provided, tries to verify with or
    without salt.

    :param password: plaintext password
    :param crypted_password: the crypted password
    :param salt: optional
    :return: boolean
    """

    for pw_hash in [LdapCrypt, MCFCrypt, OtherCrypt, DBCrypt, ArchaicCrypt]:

        if not pw_hash.identify(crypted_password):
            continue

        try:
            if salt:
                return pw_hash.using(salt=salt, relaxed=True
                                     ).verify(password, crypted_password)
            else:
                return pw_hash.verify(password, crypted_password)

        except ValueError as exx:
            log.error("Error while comparing password! %r", exx)
            return False
        except MissingBackendError as exx:
            log.error("Missing passlib backend: %s", exx)
            return False

    log.info("password does not match any password schema!")
    return False


def make_connect(driver, user, pass_, server, port, db, conParams=""):
    '''
    create a connect string from decicated parts
    - to build a SQLAlchemy Uri

    :param    driver: mysql, postgres, ...
    :type     driver: string
    :param    user:   database connection user
    :type     user:   string
    :param    pass_:  password of the database user
    :type     pass_:  string
    :param    server: servername
    :type     server: string
    :param    port:   database connection port
    :type     port:   string or int
    :param    db:     database name
    :type     db:     string
    :param    conParams: additional connection parameters
    :type     conParams: string
    '''

    connect = ""
    if "?odbc_connect=" in driver:

        # we have the need to support the odbc_connect mode
        # where the parameters of the drivers will be concated
        # The template for the odbc_connect string is submitted
        # in the field "Additional connection parameters:"
        param_str = conParams
        settings = {}
        settings["{PORT}"] = port

        if user:
            user = user.strip()
        settings["{DBUSER}"] = user

        if server:
            server = server.strip()

        settings["{SERVER}"] = server
        settings["{PASSWORT}"] = pass_
        settings["{DATABASE}"] = db
        for key, value in list(settings.items()):
            param_str = param_str.replace(key, value)

        url_quote = urllib.parse.quote_plus(param_str)
        connect = "%s%s" % (driver, url_quote)
    else:
        connect = build_simple_connect(driver, user, pass_,
                                       server, port, db, conParams)

    return connect


def build_simple_connect(driver, user=None, pass_=None,
                         server=None, port=None, db=None,
                         conParams=None):
    """
    build from the parameters the sql connect url

    :param driver: the url protocoll / prefix
    :param user: the database accessing user
    :param pass_: the password of database accessing user
    :param server: the hostname for the server could be empty
    :param port: the port on th server host, could be empty
    :param db: the database on the server
    :param conParams: additional and otpional database parameter

    return the connection string
    """

    connect = []

    # ------------------------------------------------------------------ --

    # add driver scope as protocoll

    connect.append('%s://' % driver)

    # ------------------------------------------------------------------ --

    # add the user and if avail the password

    if user and user.strip():
        user = user.strip()

        if pass_ and pass_.strip():
            connect.append('%s:%s' % (user, pass_))
        else:
            connect.append('%s' % user)

    # ------------------------------------------------------------------ --

    # add server and if available, the port -
    # - if no server, we have to add the '@' or the interpretation will
    #  fail with parding the password to be a port number

    if server and server.strip():
        server = server.strip()

        if port and port.strip():
            port = port.strip()
            connect.append('@%s:%d' % (server, int(port)))
        else:
            connect.append('@%s' % server)
    else:

        # in case of no server and a user, we have to append the empty @ sign
        # as otherwise the parser will interpret the :password as port which
        # will fail as it is not of type int

        if user and user.strip():
            connect.append('@')

    # ------------------------------------------------------------------ --

    # add database
    if db and db.strip():
        connect.append('/%s' % db.strip())

    # ------------------------------------------------------------------ --

    # add additional parameters

    if conParams:
        connect.append('?%s' % conParams)

    return ''.join(connect)


class dbObject():

    def __init__(self):
        '''
        constructor - initaialize the database object
        '''
        self.engine = None
        self.meta = None
        self.sess = None

        return None

    def connect(self, sqlConnect, timeout=5, verify=True):
        """
        create a db session with the sqlConnect string

        :param sqlConnect: sql url for the connection
        """

        args = {'echo': False, 'echo_pool': True}

        if 'sqlite' not in sqlConnect:
            args['pool_timeout'] = 30
            args['connect_args'] = { 'connect_timeout': timeout}

        self.engine = create_engine(sqlConnect, **args)

        # the repr of engine is does not show the password

        log.debug('[dbObject::connect] %r' % self.engine)

        self.meta = MetaData()

        Session = sessionmaker(bind=self.engine, autoflush=True,
                               autocommit=True, expire_on_commit=True)
        self.sess = Session()

        #if not verify:
        #    return

        # ------------------------------------------------------------------ --

        # verify that it's possible to connect

        try:

            self.engine.connect()
            return

        except Exception as exx:

            log.error("Connection error: %r", exx)

            msg = str(exx)

            if "timeout expired" in msg or "can't connect to" in msg:

                raise ResolverNotAvailable(msg)

            raise

    def getTable(self, tableName):
        log.debug('[dbObject::getTable] %s' % tableName)
        return Table(tableName, self.meta, autoload=True,
                     autoload_with=self.engine)

    def count(self, table, where=""):
        log.debug('[dbObject::count] %s:%s' % (table, where))
        num = 0
        if where != "":
            num = self.sess.query(table).filter(sql_text(where)).count()
        else:
            num = self.sess.query(table).count()
        return num

    def query(self, select):
        log.debug('[dbObject::query] %s' % (select))
        return self.sess.execute(select)

    def close(self):
        log.debug('[dbObject::close]')
        if self.sess is not None:
            self.sess.close()
        return


# connect callback - currently not used
def call_on_connect(dbapi_con, connection_record):
    log.debug("[call_on_connect] new DBAPI connection")
    return


def testconnection(params):
    """
    provide the old interface for backward compatibility
    """
    _status, desc = IdResolver.testconnection(params)

    return desc.get('rows', ''), desc.get('err_str', '')


@resolver_registry.class_entry('useridresolver.SQLIdResolver.IdResolver')
@resolver_registry.class_entry('useridresolveree.SQLIdResolver.IdResolver')
@resolver_registry.class_entry('useridresolver.sqlresolver')
@resolver_registry.class_entry('sqlresolver')
class IdResolver(UserIdResolver):

    db_prefix = 'useridresolver.SQLIdResolver.IdResolver'
    critical_parameters = ['Driver', 'Server', 'Port',
                           'Database', 'User', 'Table']

    crypted_parameters = ['Password']

    resolver_parameters: Dict[str, Tuple[bool, Union[str, bool, int, None], Callable[[Any], Any]]] = {
        "Connect": (False, "", text),
        "Driver": (False, None, text),
        "Server": (False, "", text),
        "Port": (False, "", text),
        "Database": (False, "", text),
        "User": (False, "", text),
        "conParams": (False, "", text),
        "Password": (True, "", encrypted_data),
        "Limit": (False, "1000", int),
        "Table": (False, "", text),
        "Where": (False, "", text),
        "Map": (False, "", text),
        "Encoding": (False, DEFAULT_ENCODING, text),
        }
    resolver_parameters.update(UserIdResolver.resolver_parameters)

    @classmethod
    def primary_key_changed(cls, new_params, previous_params):
        """
        check if during the  parameter update the primary key has changed

        :param new_params: the set of new parameters
        :param previous_params: the set of previous parameters

        :return: boolean
        """
        new_uid = json.loads(new_params.get('Map', '{}')).get('userid', '')
        prev_uid = json.loads(previous_params.get('Map', '{}')).get('userid', '')

        return new_uid != prev_uid

    @classmethod
    def testconnection(cls, parameters):
        """
        This is used to test if the given parameter set will do a successful
        SQL connection and return the number of found users
        params are:

        - Driver
        - Server
        - Port
        - Database
        - User
        - Password
        - Table
        """

        log.debug('[testconnection] %r', parameters)

        num = -1
        dbObj = dbObject()

        try:

            params, _missing = IdResolver.filter_config(parameters)

            passwd = params.get("Password").get_unencrypted()

            connect_str = make_connect(
                       driver=params.get("Driver"),
                       user=params.get("User"),
                       pass_=passwd,
                       server=params.get("Server"),
                       port=params.get("Port"),
                       db=params.get("Database"),
                       conParams=params.get('ConnectionParams', ""))

            log.debug("[testconnection] testing connection with "
                      "connect str: %r", connect_str)

            dbObj.connect(connect_str, verify=False)
            table = dbObj.getTable(params.get("Table"))
            num = dbObj.count(table, params.get("Where", ""))

        except Exception as exx:
            log.exception('[testconnection] Exception: %r', exx)
            return False, {'err_string': "%r" % exx, 'rows': num}

        finally:
            dbObj.close()
            log.debug('[testconnection] done')

        return True, {'rows': num, 'err_string': ""}

    @classmethod
    def setup(cls, config=None, cache_dir=None):
        '''
        this setup hook is triggered, when the server
        starts to serve the first request

        :param config: the linotp config
        :type  config: the linotp config dict
        '''
        log.info("Setting up the SQLResolver")
        return

    def __init__(self):
        ''' initialize the SQLResolver class '''
        self.sqlConnect = ''
        self.sqlTable = ''
        self.sqlWhere = ''
        self.sqlEncoding = ''
        self.sqlUserInfo = {}
        self.conf = ""
        self.driver = ""
        self.limit = 1000
        self.dbObj = None

    def connect(self, sqlConnect=None):
        """
        create a db connection and preserve session in self.dbObj

        :param sqlConnect: the sql connection string
        """

        if self.dbObj is not None:
            return self.dbObj

        if sqlConnect is None:
            sqlConnect = self.sqlConnect

        self.dbObj = dbObject()
        self.dbObj.connect(sqlConnect)

        return self.dbObj

    def close(self):
        """
        close the db connection - will be called at the end of the request
        """
        if self.dbObj is not None:
            self.dbObj.close()
            self.dbObj = None
        return

    def getResolverId(self):
        """
        getResolverId - provide the resolver identifier

        :return: returns the resolver identifier string
                 or empty string if not exist
        :rtype : string
        """
        resolver = "SQLIdResolver.IdResolver"
        if self.conf != "":
            resolver = resolver + "." + self.conf
        return resolver

    def checkPass(self, uid, password):
        '''
        checkPass - checks the password for a given uid.

        :param uid: userid to be checked
        :type  uid: string
        :param password: user password
        :type  password: string

        :return :  true in case of success, false if password does not match
        :rtype :   boolean

        :todo: extend to support htpasswd passwords:
             http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
        '''

        log.info("[checkPass] checking password for user %s" % uid)
        userInfo = self.getUserInfo(uid, suppress_password=False)

        if not userInfo["password"]:
            log.error("[checkPass] password is not defined in SQL mapping!")
            return False

        result = check_password(
            password, userInfo["password"], userInfo.get("salt"))

        if result:
            log.info("[checkPass] successfully authenticated "
                         "user uid %s", uid)
            return True

        log.warning("[checkPass] user %s failed to authenticate.", uid)
        return False


    @classmethod
    def getResolverClassType(cls):
        return 'sqlresolver'

    def getResolverType(self):
        '''
        getResolverType - return the type of the resolver

        :return: returns the string 'sqlresolver'
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
        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor['clazz'] = "useridresolver.SQLIdResolver.IdResolver"
        descriptor['config'] = {
                                'Driver': 'string',
                                'Server': 'string',
                                'Port': 'string',
                                'Database': 'string',
                                'User': 'string',
                                'Password': 'password',
                                'Table': 'string',
                                'Limit': 'string',
                                'Where': 'sting',
                                'Encoding': 'string',
                                'UserInfo': 'string',
                                'conParams': 'string', }

        return {typ: descriptor}

    def getResolverDescriptor(self):
        return IdResolver.getResolverClassDescriptor()

    def loadConfig(self, config, conf=""):
        '''
        loadConfig - load the config for the resolver

        :param config: configuration for the sqlresolver
        :type  config: dict
        :param conf: configuration postfix
        :type  conf: string
        '''
        log.debug("[loadConfig]")

        self.conf = conf

        l_config, missing = self.filter_config(config, conf)
        if missing:
            log.error("missing config entries: %r", missing)
            raise ResolverLoadConfigError(" missing config entries:"
                                          " %r" % missing)

        #  example for connect:
        #      postgres://otpd:linotp2d@localhost:521/otpdb

        connect = l_config.get("Connect")
        if not connect:

            driver = l_config.get("Driver")
            server = l_config.get("Server")
            port = l_config.get("Port")
            db = l_config.get("Database")
            user = l_config.get("User")
            conParams = l_config.get("conParams")

            # ------------------------------------------------------------- --

            # retriev password from Crypted Data object

            passwd = l_config.get("Password").get_unencrypted()

            connect = make_connect(driver, user, passwd,
                                   server, port, db, conParams)

        # ------------------------------------------------------------------ --

        self.sqlConnect = connect

        self.limit = l_config["Limit"]
        self.sqlTable = l_config["Table"]
        self.sqlWhere = l_config["Where"]
        self.sqlEncoding = l_config.get("Encoding") or DEFAULT_ENCODING

        # ------------------------------------------------------------------ --

        userInfo = l_config["Map"].strip("'").strip('"')
        try:

            self.sqlUserInfo = json.loads(userInfo)

        except ValueError as exx:
            raise ResolverLoadConfigError("Invalid userinfo - no json "
                                          "document: %s %r" % (userInfo, exx))

        except Exception as exx:
            raise Exception("linotp.sqlresolver.Map: %r" % exx)

        self.checkMapping()

        log.debug("[loadConfig] done")
        return self

    def checkMapping(self):
        """
        check the given sql field map against the sql table definition

        :return: -
        """
        log.debug("[checkMapping]")

        dbObj = self.connect(self.sqlConnect)
        try:

            table = dbObj.getTable(self.sqlTable)

            invalid_columns = []
            for key, sqlCol in self.sqlUserInfo.items():
                column = table.c.get(sqlCol)

                if column is None:

                    log.error('Invalid mapping: %r => %r, column not found',
                              key, sqlCol)

                    invalid_columns.append(sqlCol)

            if invalid_columns:
                dbObj.close()
                raise Exception("Invalid map with invalid columns: %r. "
                                "Possible columns: %s" %
                                (invalid_columns,
                                 [co.name for co in table.columns]))
            else:
                log.info('Valid mapping: %r', self.sqlUserInfo)

        except Exception as exx:
            log.exception('[checkMapping] Exception: %r', exx)

        log.debug('[checkMapping] done')
        return

    def getUserId(self, loginName):
        '''
        return the userId which mappes to a loginname

        :param loginName: login name of the user
        :type loginName:  string

        :return: userid - unique idenitfier for this unser
        :rtype:  string
        '''


        log.debug("[getUserId] %s[%s]" % (loginName, type(loginName)))
        userId = ""

        dbObj = self.connect(self.sqlConnect)
        try:
            table = dbObj.getTable(self.sqlTable)
            filtr = self.__getUserIdFilter(table, loginName)
            log.debug("[getUserId] filtr: %s" % filtr)
            log.debug("[getUserId] filtr type: %s" % type(filtr))
            select = table.select(filtr)
            log.debug("[getUserId] select: %s" % select)

            rows = dbObj.query(select)
            log.debug("[getUserId] length of select statement %i" %
                                                                rows.rowcount)
            for row in rows:
                colName = self.sqlUserInfo.get("userid")
                userId = row[colName]
                log.info("[getUserId] getting userid %s for user %s" %
                                                        (userId, loginName))
        except Exception as e:
            log.exception('[getUserId] Exception: %s' % (str(e)))

        log.debug('[getUserId] done')
        return userId

    def getUsername(self, userId):
        '''
        get the loginname from the given userid

        :param userId: userid descriptor
        :type userId: string

        :return: loginname
        :rtype:  string
        '''
        log.debug("[getUsername] %s[%s]" % (userId, type(userId)))

        userName = ""

        dbObj = self.connect(self.sqlConnect)
        try:

            table = dbObj.getTable(self.sqlTable)
            select = table.select(self.__getUserNameFilter(table, userId))

            for row in dbObj.query(select):
                colName = self.sqlUserInfo.get("username")
                userName = row[colName]

        except Exception as e:
            log.exception('[getUsername] Exception: %s' % (str(e)))

        log.debug('[getUsername] done')

        return userName

    def getUserInfo(self, userId, suppress_password=True):
        '''
            return all user related information

            @param userId: specied user
            @type userId:  string
            @return: dictionary, containing all user related info
            @rtype:  dict

        '''
        log.debug("[getUserInfo] %s[%s]" % (userId, type(userId)))
        userInfo = {}

        dbObj = self.connect(self.sqlConnect)
        try:

            table = dbObj.getTable(self.sqlTable)
            select = table.select(self.__getUserNameFilter(table, userId))

            for row in dbObj.query(select):
                userInfo = self.__getUserInfo(
                                    dbObj, row,
                                    suppress_password=suppress_password)

        except Exception as e:
            log.exception('[getUserInfo] Exception: %s' % (str(e)))

        log.debug('[getUserInfo] done')
        return userInfo

    def getSearchFields(self):
        '''
        return all fields on which a search could be made

        :return: dictionary of the search fields and their types
        :rtype:  dict
        '''
        log.debug("[getSearchFields]")

        sf = {}

        dbObj = self.connect(self.sqlConnect)
        try:

            table = dbObj.getTable(self.sqlTable)

            for key in self.sqlUserInfo:
                sqlCol = self.sqlUserInfo.get(key)
                sqlTyp = table.c[sqlCol].type
                #print key, " - ", sqlCol, " {",sqlTyp,"} "
                typ = "text"
                if isinstance(sqlTyp, types.String):
                    typ = "text"
                elif isinstance(sqlTyp, types.Numeric):
                    typ = "numeric"
                elif isinstance(sqlTyp, types.Integer):
                    typ = "numeric"
                sf[key] = typ

        except Exception as e:
            log.exception('[getSearchFields] Exception: %s' % (str(e)))

        log.debug('[getSearchFields] done')
        return sf

    def getUserList(self, searchDict):
        '''
        retrieve a list of users

        :param searchDict: dictionary of the search criterias
        :type  searchDict: dict
        :return: list of user descriptions (as dict)
        '''
        if not searchDict:
            searchDict = {'username': '*'}
        log.debug("[getUserList] %r" % searchDict)

        # we use a dict, where the return users are inserted to where key
        # is userid to return only a distinct list of users
        users = {}

        dbObj = self.connect()
        self.checkMapping()

        regex_dict = {}

        try:
            table = dbObj.getTable(self.sqlTable)
            log.debug("[getUserList] getting SQL users from table %s" % table)

            # as most of the SQL dialects dont support unicode, unicode chars
            # are replaced in the __createSearchString as wildcards.
            # To make the search more precise, we do postprocessing by
            # a backward compare with the original search dict values,
            # either regexp or exact compare.
            # We build up here the regex dict in case of a wildcard,
            # For all others we do the exact compare

            for key, value in list(searchDict.items()):
                if "*" in value or "." in value:
                    regex_dict[key] = re.compile(value.replace("*", ".*"))

            sStr = self.__creatSearchString(dbObj, table, searchDict)
            log.debug("[getUserList] creating searchstring <<%s>>" % sStr)
            log.debug("[getUserList] type of searchString: %s" % type(sStr))
            select = table.select(sStr, limit=self.limit)

            rows = dbObj.query(select)

            for row in rows:
                log.debug("[getUserList]  row     : %s" % row)
                ui = self.__getUserInfo(dbObj, row)
                userid = ui['userid']
                log.debug("[getUserList] user info: %s" % ui)
                for s in searchDict:
                    if s in regex_dict:
                        if regex_dict[s].match(ui[s]):
                            users[userid] = ui

                    # handle the comparisons
                    elif (">" in searchDict[s] or
                          "<" in searchDict[s] or
                          "=" in searchDict[s]):

                        users[userid] = ui

                    else:  # excat search
                        if ui[s] == searchDict[s]:
                            users[userid] = ui

        except KeyError as exx:
            log.exception('[getUserList] Invalid Mapping Error %r' % exx)
            raise KeyError("Invalid Mapping %r " % exx)

        except Exception as exx:
            log.exception('[getUserList] Exception: %r' % exx)

        log.debug("[getUserList] returning userlist %s" % list(users.values()))
        return list(users.values())

#######################
#   Helper functions
#######################
    def __replaceChars(self, string, repl='*'):
        '''
        Replaces unwanted chars with ord()>127

        :param string: string to be replaced
        :param repl: replacement pattern

        :return: string with replaced patterns
        '''
        retString = ""
        for i in string:
            if ord(i) > 127:
                retString = "%s%s" % (retString, repl)
            else:
                retString = "%s%s" % (retString, i)

        return retString

    def __getUserInfo(self, dbObj, row, suppress_password=True):
        """
        internal helper to build up the user info dict

        :param sbObj: database handle
        :param row: the user object row data
        :return: user dict
        """
        userInfo = {}

        for key in self.sqlUserInfo:
            if key == 'password' and suppress_password:
                continue

            colName = self.sqlUserInfo.get(key)

            try:
                value = row[colName]
                log.debug("[__getUserInfo] %r:%r" % (value, type(value)))

            except NoSuchColumnError as  e:
                log.exception("[__getUserInfo]")
                value = "-ERR: column mapping-"

            userInfo[key] = value

        return userInfo

    def __add_where_clause_to_filter(self, filtr):
        '''
        add to an existing filter the WHERE filter if it exist.
        This can be used for the getUserList or getUserId

        :param filtr: filter espression
        :return: new filter string
        '''
        # use the Where clause to only see certain users.
        if self.sqlWhere != "":
            clause = expression.text(self.sqlWhere)
            if filtr is None:
                filtr = clause
            else:
                filtr = clause & filtr
            log.debug("[__add_where_clause_filter] searchString: %r" % filtr)
        return filtr

    def __getUserIdFilter(self, table, loginName):
        """
        helper method to access userdata by username by creating an filter

        :param table: the database table
        :param loginname: the name of the user to be searched
        :return: filter condition, which will be added to the db query
        """
        #loginName = loginName.decode("latin1")
        column_name = self.sqlUserInfo.get("username")
        if column_name == None:
            log.error("[__getUserIdFilter] username column "
                                                        "definition required!")
            raise Exception("username column definition required!")
        log.debug("[__getUserIdFilter] type loginName: %s" % type(loginName))
        log.debug("[__getUserIdFilter] type filtr: %s" % type(column_name))

        ## DB2 will need the double quotes if the columns are not upper case.
        ## But as usually a DB2 admin uses upper case, we do not "
        ## need the double quotes.

        return self.__add_where_clause_to_filter(
                                        table.c[column_name] == loginName)

    def __getUserNameFilter(self, table, loginId):
        """
        helper method to access userdata by userid by creating an filter

        :param table: the database table
        :param loginId: the id of the user to be searched
        :return: filter condition, which will be added to the db query
        """

        column_name = self.sqlUserInfo.get("userid")
        if column_name == None:
            err = "[__getUserNameFilter] userid column definition required!"
            log.error(err)
            raise Exception(err)

        return self.__add_where_clause_to_filter(
                                            table.c[column_name] == loginId)

    def __creatSearchString(self, dbObj, table, searchDict):
        """
        Create search string
        """
        exp = None
        for key in searchDict:
            log.debug("[__createSearchString] proccessing key %s" % key)

            ## more tolerant mapping of column names for some sql dialects
            ## as you can define columnnames in mixed case but table mapping
            ## might be only available in upper or lower case (s. postgresql)
            try:
                column = table.c[self.sqlUserInfo[key]]
            except KeyError as _err:
                try:
                    column = table.c[self.sqlUserInfo[key].lower()]
                except KeyError as _err:
                    column = table.c[self.sqlUserInfo[key].upper()]

            ## for searching for names with german umlaute, they are replaced
            ## by wildcards, which is filtered in the upper level by
            ## postprocessing
            val = self.__replaceChars(searchDict.get(key))

            log.debug("[__createSearchString] key: %s, value: %s "
                                                                % (key, val))

            # First: replace wildcards. Our wildcards are * and . (shell-like),
            # and SQL wildcards are % and _.
            if '%' in val:
                val = val.replace('%', r'\%')

            if '_' in val:
                val = val.replace('_', r'\_')

            if '*' in val:
                val = val.replace('*', '%')

            if '.' in val:
                if not self.sqlConnect.startswith('mysql'):
                    val = val.replace('.', '_')
                else:
                    ## mysql replaces unicode chars with 2 placeholders,
                    ## so we rely more on postprocessing :-(
                    val = val.replace('.', '%')

            # don't match for whitespace at the beginning or the end.
            val = val.strip()

            # Now: predicates. <, <=, >=, > get translated,
            # everything else is `LIKE`.
            # No wildcards are supported for <, <=, >=, >.
            if val.startswith('<='):
                val = val[2:].strip()
                exp = column <= val

            elif val.startswith('>='):
                val = val[2:].strip()
                exp = column >= val

            elif val.startswith('>'):
                val = val[1:].strip()
                exp = column > val

            elif val.startswith('<'):
                val = val[1:].strip()
                exp = column < val

            else:
                ### for postgres no escape is required!!
                if self.sqlConnect.startswith('postg'):
                    exp = column.like(val)
                else:
                    exp = column.like(val, escape='\\')

            log.debug("[__createSearchString] searchStr : %s" % exp)

        # use the Where clause to only see certain users.
        return self.__add_where_clause_to_filter(exp)


if __name__ == "__main__":

    print("SQLIdResolver - IdResolver class test ")

    #sqlR = getResolverClass("useridresolver.SQLIdResolver", "IdResolver")()
    sqlR = IdResolver()

    # sqlite:////home/virtualbox/project/linotp2/dev/linotpd/src/token.db
    config = {
            'linotp.sqlresolver.Driver': 'mysql',
            'linotp.sqlresolver.Port': '3306',
            'linotp.sqlresolver.Database': 'LinOTP2',
            'linotp.sqlresolver.Server': 'localhost',
            'linotp.sqlresolver.User': 'linotp21',
            'linotp.sqlresolver.Password': 'test123!',
            'linotp.sqlresolver.Table': 'users_temp',
            'linotp.sqlresolver.Map': '{ "username": "user",'
                                       '"userid" : "userid", '
                                       '"password": "password", '
                                       '"salt" : "salt", '
                                       '"description" : "user"}'
             }

    sqlR.loadConfig(config)
    print("JSON", json.dumps(config.get('linotp.sqlresolver.UserInfo')))

    userId = sqlR.getUserId("kay")
    print("getUserId:\n kay = ", userId)

    userInfo = sqlR.getUserInfo(userId)
    print("getUserInfo:\n Id:", userId, "\n Info:", userInfo)

    sf = sqlR.getSearchFields()
    print("getSearchFields: \n ", sf)

    #, "id" : ">100"}
    searchDict = {"username": "k*%", "description": "*_Winkler*"}
    #searchDict=  {"userid" : ">100"}

    ulist = sqlR.getUserList(searchDict)
    print("getUserList: \n ", ulist)

    #, "id" : ">100"}
    searchDict2 = {"description": "*Winkler*"}
    #searchDict=  {"id" : ">100"}

    ulist = sqlR.getUserList(searchDict2)
    print("getUserList2: \n ", ulist)

    #, "id" : ">100"}
    searchDict3 = {"username": "k..", "description": "*Winkler.;*"}
    #searchDict=  {"id" : ">100"}

    ulist = sqlR.getUserList(searchDict3)
    print("getUserList3: \n ", ulist)

    #, "id" : ">100"}
    searchDict4 = {"username": "*"}
    #searchDict=  {"id" : ">100"}

    ulist = sqlR.getUserList(searchDict4)
    print("getUserList4: \n ", ulist)

    pwcheck = sqlR.checkPass("kay", "test123!")
    print("checkpass for kay: \n", pwcheck)

    pwcheck = sqlR.checkPass("kay", "test!")
    print("checkpass for kay: \n", pwcheck)

##eof##########################################################################

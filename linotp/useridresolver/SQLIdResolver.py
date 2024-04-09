# -*- coding: utf-8 -*-

#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010-2019 KeyIdentity GmbH
#    Copyright (C) 2019-     netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
"""
This module implements the communication and data mapping to SQL servers.
The LinOTP server imports this module to use SQL databases as a userstore.

Dependencies: UserIdResolver
"""

import base64
import hashlib
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Tuple, Union

from passlib.context import CryptContext
from passlib.exc import MissingBackendError
from sqlalchemy import MetaData, Table, and_, cast, create_engine, or_, types
from sqlalchemy.exc import NoSuchColumnError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import expression
from sqlalchemy.sql import text as sql_text

from flask import current_app

from linotp.lib.type_utils import encrypted_data, text
from linotp.model import db
from linotp.useridresolver.UserIdResolver import (
    ResolverLoadConfigError,
    ResolverNotAvailable,
    UserIdResolver,
)

from . import resolver_registry

# from sqlalchemy.event import listen


# ------------------------------------------------------------------------- --


# establish the passlib crypt context different password formats


# format like {ssha1}adsadasdad - from the RFC 2307
Ldap_crypt_schemes = [
    "ldap_sha1",
    "ldap_salted_sha1",
    "ldap_sha1_crypt",
    "ldap_sha256_crypt",
    "ldap_sha512_crypt",
    "ldap_bcrypt",
    "ldap_des_crypt",
    "ldap_bsdi_crypt",
    "ldap_md5_crypt",
    "ldap_md5",
    "ldap_salted_md5",
]

# format like {ssha1}adsadasdad but not in the RFC 2307
Ldap_similar_crypt_schemes = ["atlassian_pbkdf2_sha1", "fshp"]

# format like $identifier$content - MCF: modular crypt format
MCF_crypt_schemes = [
    "md5_crypt",
    "bcrypt",
    "bsd_nthash",
    "sha512_crypt",
    "sha256_crypt",
    "sha1_crypt",
    "sun_md5_crypt",
]

# other application related password formats
Other_crypt_schemes = [
    "bcrypt_sha256",
    "phpass",  # "argon2" # requires extra install
]

# db related password formats
DB_crypt_schemes = [
    "mssql2000",
    "mssql2005",
    "mysql323",
    "mysql41",  # "postgres_md5", # requires extra install
    "oracle11",
]

# legacy password schemes partially without identifier
Archaic_crypt_schemes = ["des_crypt", "bsdi_crypt", "bigcrypt"]


LdapCrypt = CryptContext(
    schemes=Ldap_crypt_schemes + Ldap_similar_crypt_schemes
)

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
    for various password schemes defining a passlib crypto context

    - {id}pwdata - LDAP format
    - $id$pwdata - modular crypt format
    - other format like the Atlassian or PHP passwords
    - support db format
    - support for archaic formats like Des

    the definitions of the crypto context is made above in the schema lists

    the algorithm iterates over the crypto contexts to identify the type
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
                return pw_hash.using(salt=salt, relaxed=True).verify(
                    password, crypted_password
                )
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
    """
    create a connect string from separate parts
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
    """

    connect = ""
    if "?odbc_connect=" in driver:
        # we have the need to support the odbc_connect mode
        # where the parameters of the drivers will be concatenated
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
        connect = build_simple_connect(
            driver, user, pass_, server, port, db, conParams
        )

    return connect


def build_simple_connect(
    driver,
    user=None,
    pass_=None,
    server=None,
    port=None,
    db=None,
    conParams=None,
):
    """
    build from the parameters the sql connect url

    :param driver: the url protocol / prefix
    :param user: the database accessing user
    :param pass_: the password of database accessing user
    :param server: the hostname for the server could be empty
    :param port: the port on th server host, could be empty
    :param db: the database on the server
    :param conParams: additional and optional database parameter

    return the connection string
    """

    connect = []

    # ------------------------------------------------------------------ --

    # add driver scope as protocoll

    connect.append("%s://" % driver)

    # ------------------------------------------------------------------ --

    # add the user and if avail the password

    if user and user.strip():
        user = user.strip()

        if pass_ and pass_.strip():
            connect.append("%s:%s" % (user, pass_))
        else:
            connect.append("%s" % user)

    # ------------------------------------------------------------------ --

    # add server and if available, the port -
    # - if no server, we have to add the '@' or the interpretation will
    #  fail with parding the password to be a port number

    if server and server.strip():
        server = server.strip()

        if port and port.strip():
            port = port.strip()
            connect.append("@%s:%d" % (server, int(port)))
        else:
            connect.append("@%s" % server)
    else:
        # in case of no server and a user, we have to append the empty @ sign
        # as otherwise the parser will interpret the :password as port which
        # will fail as it is not of type int

        if user and user.strip():
            connect.append("@")

    # ------------------------------------------------------------------ --

    # add database
    if db and db.strip():
        connect.append("/%s" % db.strip())

    # ------------------------------------------------------------------ --

    # add additional parameters

    if conParams:
        connect.append("?%s" % conParams)

    return "".join(connect)


class dbObject:
    def __init__(self):
        """
        constructor - initialize the database object
        """
        self.engine = None
        self.meta = None
        self.sess = None

        return None

    def connect(self, sqlConnect, db=None, timeout=5):
        """
        create a db session with the sqlConnect string or with the flask sqlalchemy db object

        :param sqlConnect: sql url for the connection
        :param db: the configured flask-sqlalchemy db object (this overrides the sqlConnect parameter)
        """

        self.meta = MetaData()

        # the managed case
        if db is not None:
            self.sess = db.session
            self.engine = db.engine
            log.debug("[dbObject::connect] %r", self.engine)
            return

        args = {"echo": False, "echo_pool": True}
        if "sqlite" not in sqlConnect:
            args["pool_timeout"] = 30
            args["connect_args"] = {"connect_timeout": timeout}
        self.engine = create_engine(sqlConnect, **args)

        log.debug("[dbObject::connect] %r", self.engine)

        Session = sessionmaker(
            bind=self.engine,
            autoflush=True,
            autocommit=True,
            expire_on_commit=True,
        )
        self.sess = Session()

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
        log.debug("[dbObject::getTable] %s", tableName)
        return Table(
            tableName, self.meta, autoload=True, autoload_with=self.engine
        )

    def count(self, table, where=""):
        log.debug("[dbObject::count] %s:%s", table, where)
        num = 0
        if where != "":
            num = self.sess.query(table).filter(sql_text(where)).count()
        else:
            num = self.sess.query(table).count()
        return num

    def query(self, select):
        log.debug("[dbObject::query] %s", select)
        return self.sess.execute(select)

    def close(self):
        log.debug("[dbObject::close]")
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

    return desc.get("rows", ""), desc.get("err_str", "")


@resolver_registry.class_entry("useridresolver.SQLIdResolver.IdResolver")
@resolver_registry.class_entry("useridresolveree.SQLIdResolver.IdResolver")
@resolver_registry.class_entry("useridresolver.sqlresolver")
@resolver_registry.class_entry("sqlresolver")
class IdResolver(UserIdResolver):
    """
    A resolver class for userIds

    Attributes
    ----------
    managed: means it uses the linotp DB [session]
    for storing and retrieving user information.
    """

    db_prefix = "useridresolver.SQLIdResolver.IdResolver"
    critical_parameters = [
        "Driver",
        "Server",
        "Port",
        "Database",
        "User",
        "Table",
    ]

    crypted_parameters = ["Password"]

    resolver_parameters: Dict[
        str, Tuple[bool, Union[str, bool, int, None], Callable[[Any], Any]]
    ] = {
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
        new_uid = json.loads(new_params.get("Map", "{}")).get("userid", "")
        prev_uid = json.loads(previous_params.get("Map", "{}")).get(
            "userid", ""
        )

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

        log.debug("[testconnection] %r", parameters)

        num = -1
        dbObj = dbObject()

        try:
            managed = parameters.get("readonly", False)

            params, _ = IdResolver.filter_config(parameters)

            connect_str = current_app.config.get("DATABASE_URI")
            if not managed:
                passwd = params.get("Password").get_unencrypted()
                connect_str = make_connect(
                    driver=params.get("Driver"),
                    user=params.get("User"),
                    pass_=passwd,
                    server=params.get("Server"),
                    port=params.get("Port"),
                    db=params.get("Database"),
                    conParams=params.get("ConnectionParams", ""),
                )

            log.debug(
                "[testconnection] testing connection with connect str: %r",
                connect_str,
            )

            dbObj.connect(connect_str)
            table = dbObj.getTable(params.get("Table"))
            num = dbObj.count(table, params.get("Where", ""))

        except Exception as exx:
            log.error("[testconnection] Exception: %r", exx)
            return False, {"err_string": "%r" % exx, "rows": num}

        finally:
            dbObj.close()
            log.debug("[testconnection] done")

        return True, {"rows": num, "err_string": ""}

    @classmethod
    def setup(cls, config=None, cache_dir=None):
        """
        this setup hook is triggered, when the server
        starts to serve the first request

        :param config: the linotp config
        :type  config: the linotp config dict
        """
        log.info("Setting up the SQLResolver")
        return

    def __init__(self):
        """initialize the SQLResolver class"""
        self.sqlConnect = ""
        self.sqlTable = ""
        self.sqlWhere = ""
        self.sqlEncoding = ""
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

        if self.managed:
            self.dbObj.connect(sqlConnect="", db=db)
        else:
            self.dbObj.connect(sqlConnect=sqlConnect)

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
        """
        checkPass - checks the password for a given uid.

        :param uid: userid to be checked
        :type  uid: string
        :param password: user password
        :type  password: string

        :return :  true in case of success, false if password does not match
        :rtype :   boolean

        :todo: extend to support htpasswd passwords:
             http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
        """

        log.info("[checkPass] checking password for user %s", uid)
        userInfo = self.getUserInfo(uid, suppress_password=False)

        if not userInfo["password"]:
            log.error("[checkPass] password is not defined in SQL mapping!")
            return False

        result = check_password(
            password, userInfo["password"], userInfo.get("salt")
        )

        if result:
            log.info("[checkPass] successfully authenticated user uid %s", uid)
            return True

        log.warning("[checkPass] user %s failed to authenticate.", uid)
        return False

    @classmethod
    def getResolverClassType(cls):
        return "sqlresolver"

    def getResolverType(self):
        """
        getResolverType - return the type of the resolver

        :return: returns the string 'sqlresolver'
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
        descriptor = {}
        typ = cls.getResolverClassType()
        descriptor["clazz"] = "useridresolver.SQLIdResolver.IdResolver"
        descriptor["config"] = {
            "Driver": "string",
            "Server": "string",
            "Port": "string",
            "Database": "string",
            "User": "string",
            "Password": "password",
            "Table": "string",
            "Limit": "string",
            "Where": "sting",
            "Encoding": "string",
            "UserInfo": "string",
            "conParams": "string",
        }

        return {typ: descriptor}

    def getResolverDescriptor(self):
        return IdResolver.getResolverClassDescriptor()

    def loadConfig(self, config, conf=""):
        """
        loadConfig - load the config for the resolver

        :param config: configuration for the sqlresolver
        :type  config: dict
        :param conf: configuration postfix
        :type  conf: string
        """
        log.debug("[loadConfig]")

        self.conf = conf

        l_config, missing = self.filter_config(config, conf)
        if missing:
            log.error("missing config entries: %r", missing)
            raise ResolverLoadConfigError(
                " missing config entries: %r" % missing
            )

        self.managed = l_config.get("readonly", False)
        # example for connect:
        #      postgres://otpd:linotp2d@localhost:521/otpdb

        if not self.managed:
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

                connect = make_connect(
                    driver, user, passwd, server, port, db, conParams
                )

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
            raise ResolverLoadConfigError(
                "Invalid userinfo - no json "
                "document: %s %r" % (userInfo, exx)
            )

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
                    log.error(
                        "Invalid mapping: %r => %r, column not found",
                        key,
                        sqlCol,
                    )

                    invalid_columns.append(sqlCol)

            if invalid_columns:
                dbObj.close()
                raise Exception(
                    "Invalid map with invalid columns: %r. "
                    "Possible columns: %s"
                    % (invalid_columns, [co.name for co in table.columns])
                )
            else:
                log.debug("Valid mapping: %r", self.sqlUserInfo)

        except Exception as exx:
            log.error("[checkMapping] Exception: %r", exx)

        log.debug("[checkMapping] done")
        return

    def getUserId(self, loginName):
        """
        return the userId which mappes to a loginname

        :param loginName: login name of the user
        :type loginName:  string

        :return: userid - unique idenitfier for this unser
        :rtype:  string
        """

        log.debug("[getUserId] %r[%s]", loginName, type(loginName))
        userId = ""

        dbObj = self.connect(self.sqlConnect)
        try:
            table = dbObj.getTable(self.sqlTable)
            filtr = self._getUserIdFilter(table, loginName)
            log.debug("[getUserId] filtr: %r", filtr)
            log.debug("[getUserId] filtr type: %s", type(filtr))
            select = table.select(filtr)
            log.debug("[getUserId] select: %r", select)

            rows = dbObj.query(select)
            log.debug(
                "[getUserId] length of select statement %i", rows.rowcount
            )
            for row in rows:
                colName = self.sqlUserInfo.get("userid")
                userId = row[colName]
                log.info(
                    "[getUserId] getting userid %s for user %s",
                    userId,
                    loginName,
                )
        except Exception as exx:
            log.error("[getUserId] Exception: %r", exx)

        log.debug("[getUserId] done")
        return userId

    def getUsername(self, userId):
        """
        get the loginname from the given userid

        :param userId: userid descriptor
        :type userId: string

        :return: loginname
        :rtype:  string
        """
        log.debug("[getUsername] %r[%s]", userId, type(userId))

        userName = ""

        dbObj = self.connect(self.sqlConnect)
        try:
            table = dbObj.getTable(self.sqlTable)
            select = table.select(self._getUserNameFilter(table, userId))

            for row in dbObj.query(select):
                colName = self.sqlUserInfo.get("username")
                userName = row[colName]

        except Exception as exx:
            log.error("[getUsername] Exception: %r", exx)

        log.debug("[getUsername] done")

        return userName

    def getUserInfo(self, userId, suppress_password=True):
        """
        return all user related information

        @param userId: specified user
        @type userId:  string
        @return: dictionary, containing all user related info
        @rtype:  dict

        """
        log.debug("[getUserInfo] %r[%s]", userId, type(userId))
        userInfo = {}

        dbObj = self.connect(self.sqlConnect)
        try:
            table = dbObj.getTable(self.sqlTable)
            select = table.select(self._getUserNameFilter(table, userId))

            for row in dbObj.query(select):
                userInfo = self._getUserInfo(
                    dbObj, row, suppress_password=suppress_password
                )

        except Exception as exx:
            log.error("[getUserInfo] Exception: %r", exx)

        log.debug("[getUserInfo] done")
        return userInfo

    def getSearchFields(self):
        """
        return all fields on which a search could be made

        :return: dictionary of the search fields and their types
        :rtype:  dict
        """
        log.debug("[getSearchFields]")

        sf = {}

        dbObj = self.connect(self.sqlConnect)
        try:
            table = dbObj.getTable(self.sqlTable)

            for key in self.sqlUserInfo:
                sqlCol = self.sqlUserInfo.get(key)
                sqlTyp = table.c[sqlCol].type
                # print key, " - ", sqlCol, " {",sqlTyp,"} "
                typ = "text"
                if isinstance(sqlTyp, types.String):
                    typ = "text"
                elif isinstance(sqlTyp, types.Numeric):
                    typ = "numeric"
                elif isinstance(sqlTyp, types.Integer):
                    typ = "numeric"
                sf[key] = typ

        except Exception as exx:
            log.error("[getSearchFields] Exception: %r", exx)

        log.debug("[getSearchFields] done")
        return sf

    def getUserList(self, searchDict):
        """
        retrieve a list of users

        :param searchDict: dictionary of the search criteria
        :type  searchDict: dict
        :return: list of user descriptions (as dict)
        """
        if not searchDict:
            searchDict = {"username": "*"}
        log.debug("[getUserList] %r", searchDict)

        dbObj = self.connect()
        self.checkMapping()

        try:
            table = dbObj.getTable(self.sqlTable)
            log.debug("[getUserList] getting SQL users from table %r", table)

            sStr = self._createSearchString(dbObj, table, searchDict)
            log.debug("[getUserList] creating searchString <<%r>>", sStr)
            log.debug("[getUserList] type of searchString: %s", type(sStr))
            select = table.select(sStr, limit=self.limit)

            rows = dbObj.query(select)

            user_info_list = [self._getUserInfo(dbObj, row) for row in rows]
            users = {
                user_info["userid"]: user_info for user_info in user_info_list
            }

        except KeyError as exx:
            log.error("[getUserList] Invalid Mapping Error: %r", exx)
            raise KeyError("Invalid Mapping %r " % exx)

        except Exception as exx:
            log.error("[getUserList] Exception: %r", exx)
            users = {}

        log.debug("[getUserList] returning userlist %r", list(users.values()))
        return list(users.values())

    #######################
    #   Helper functions
    #######################
    def _getUserInfo(self, dbObj, row, suppress_password=True):
        """
        internal helper to build up the user info dict

        :param sbObj: database handle
        :param row: the user object row data
        :return: user dict
        """
        userInfo = {}

        for key in self.sqlUserInfo:
            if key == "password" and suppress_password:
                continue

            colName = self.sqlUserInfo.get(key)

            try:
                value = row[colName]
                log.debug("[_getUserInfo] %r:%r", value, type(value))

            except NoSuchColumnError as e:
                log.error("[_getUserInfo]")
                value = "-ERR: column mapping-"

            userInfo[key] = value

        return userInfo

    def _add_where_clause_to_filter(self, filtr):
        """
        add to an existing filter the WHERE filter if it exist.
        This can be used for the getUserList or getUserId

        :param filtr: filter expression
        :return: new filter string
        """
        # use the Where clause to only see certain users.
        if self.sqlWhere != "":
            clause = expression.text(self.sqlWhere)
            if filtr is None:
                filtr = clause
            else:
                filtr = and_(clause, filtr)
            log.debug("[__add_where_clause_filter] searchString: %r", filtr)
        return filtr

    def _getUserIdFilter(self, table, loginName):
        """
        helper method to access userdata by username by creating an filter

        :param table: the database table
        :param loginname: the name of the user to be searched
        :return: filter condition, which will be added to the db query
        """
        # loginName = loginName.decode("latin1")
        column_name = self.sqlUserInfo.get("username")
        if column_name is None:
            log.error(
                "[_getUserIdFilter] username column definition required!"
            )
            raise Exception("username column definition required!")
        log.debug("[_getUserIdFilter] type loginName: %s", type(loginName))
        log.debug("[_getUserIdFilter] type filtr: %s", type(column_name))

        # DB2 will need the double quotes if the columns are not upper case.
        # But as usually a DB2 admin uses upper case, we do not "
        # need the double quotes.

        return self._add_where_clause_to_filter(
            table.c[column_name] == loginName
        )

    def _getUserNameFilter(self, table, loginId):
        """
        helper method to access userdata by userid by creating an filter

        :param table: the database table
        :param loginId: the id of the user to be searched
        :return: filter condition, which will be added to the db query
        """

        column_name = self.sqlUserInfo.get("userid")
        if column_name is None:
            err = "[_getUserNameFilter] userid column definition required!"
            log.error(err)
            raise Exception(err)

        return self._add_where_clause_to_filter(
            table.c[column_name] == loginId
        )

    def _createSearchString(self, dbObj, table, searchDict: dict):
        def get_column(column_name: str):
            # case-insensitive fetching of all possible column_names
            possible_column_name_list = [
                possible_column_name
                for column_mapping_key, possible_column_name in self.sqlUserInfo.items()
                if column_name.lower() == column_mapping_key.lower()
            ]
            if not possible_column_name_list:
                raise KeyError(
                    "[_createSearchString] no column found for %s", column_name
                )

            # more tolerant mapping of column names for some sql dialects
            # as you can define columnnames in mixed case but table mapping
            # might be only available in upper or lower case (s. postgresql)
            for column_name in possible_column_name_list:
                try:
                    return table.c[column_name]
                except KeyError as _err:
                    try:
                        return table.c[column_name.lower()]
                    except KeyError as _err:
                        return table.c[column_name.upper()]

        def get_sql_expression(column, value):
            log.debug(
                "[__createSearchString] column: %s, value: %s ", column, value
            )

            # First: replace wildcards. Our wildcards are * and . (shell-like),
            # and SQL wildcards are % and _.
            if "%" in value:
                value = value.replace("%", r"\%")

            if "_" in value:
                value = value.replace("_", r"\_")

            if "*" in value:
                value = value.replace("*", "%")

            if "." in value:
                if not self.sqlConnect.startswith("mysql"):
                    value = value.replace(".", "_")
                else:
                    # mysql replaces unicode chars with 2 placeholders,
                    # so we rely more on postprocessing :-(
                    value = value.replace(".", "%")

            # don't match for whitespace at the beginning or the end.
            value = value.strip()

            # Now: predicates. <, <=, >=, > get translated,
            # everything else is `LIKE`.
            # No wildcards are supported for <, <=, >=, >.
            if value.startswith("<="):
                value = value[2:].strip()
                exp = column <= value

            elif value.startswith(">="):
                value = value[2:].strip()
                exp = column >= value

            elif value.startswith(">"):
                value = value[1:].strip()
                exp = column > value

            elif value.startswith("<"):
                value = value[1:].strip()
                exp = column < value

            else:
                # for postgres no escape is required!!
                # but we have to cast its type to string
                # as it does not support dynamic typing like sqlite
                if self.sqlConnect.startswith("postg"):
                    column_cast_to_string = cast(column, types.String)
                    exp = column_cast_to_string.like(value)
                else:
                    exp = column.like(value, escape="\\")

            log.debug("[__createSearchString] searchStr : %s", exp)
            return exp

        """
        Create search string
        """
        exp = None

        # OR filter
        searchTermValue = searchDict.pop("searchTerm", None)
        if searchTermValue:
            for column_name in self.sqlUserInfo.keys():
                column = get_column(column_name)
                if exp is None:
                    exp = get_sql_expression(column, searchTermValue)
                else:
                    exp = or_(exp, get_sql_expression(column, searchTermValue))

        # AND filter
        for key, value in searchDict.items():
            log.debug("[__createSearchString] processing key %s", key)

            try:
                column = get_column(key)
            except KeyError:
                log.warning("[__createSearchString] no column named %s", key)
                continue
            if exp is None:
                exp = get_sql_expression(column, value)
            else:
                exp = and_(exp, get_sql_expression(column, value))

        # use the Where clause to only see certain users.
        return self._add_where_clause_to_filter(exp)


if __name__ == "__main__":
    print("SQLIdResolver - IdResolver class test ")

    # sqlR = getResolverClass("useridresolver.SQLIdResolver", "IdResolver")()
    sqlR = IdResolver()

    # sqlite:////home/virtualbox/project/linotp2/dev/linotpd/src/token.db
    config = {
        "linotp.sqlresolver.Driver": "mysql",
        "linotp.sqlresolver.Port": "3306",
        "linotp.sqlresolver.Database": "LinOTP2",
        "linotp.sqlresolver.Server": "localhost",
        "linotp.sqlresolver.User": "linotp21",
        "linotp.sqlresolver.Password": "test123!",
        "linotp.sqlresolver.Table": "users_temp",
        "linotp.sqlresolver.Map": '{ "username": "user",'
        '"userid" : "userid", '
        '"password": "password", '
        '"salt" : "salt", '
        '"description" : "user"}',
    }

    sqlR.loadConfig(config)
    print("JSON", json.dumps(config.get("linotp.sqlresolver.UserInfo")))

    userId = sqlR.getUserId("kay")
    print("getUserId:\n kay = ", userId)

    userInfo = sqlR.getUserInfo(userId)
    print("getUserInfo:\n Id:", userId, "\n Info:", userInfo)

    sf = sqlR.getSearchFields()
    print("getSearchFields: \n ", sf)

    # , "id" : ">100"}
    searchDict = {"username": "k*%", "description": "*_Winkler*"}
    # searchDict=  {"userid" : ">100"}

    ulist = sqlR.getUserList(searchDict)
    print("getUserList: \n ", ulist)

    # , "id" : ">100"}
    searchDict2 = {"description": "*Winkler*"}
    # searchDict=  {"id" : ">100"}

    ulist = sqlR.getUserList(searchDict2)
    print("getUserList2: \n ", ulist)

    # , "id" : ">100"}
    searchDict3 = {"username": "k..", "description": "*Winkler.;*"}
    # searchDict=  {"id" : ">100"}

    ulist = sqlR.getUserList(searchDict3)
    print("getUserList3: \n ", ulist)

    # , "id" : ">100"}
    searchDict4 = {"username": "*"}
    # searchDict=  {"id" : ">100"}

    ulist = sqlR.getUserList(searchDict4)
    print("getUserList4: \n ", ulist)

    pwcheck = sqlR.checkPass("kay", "test123!")
    print("checkpass for kay: \n", pwcheck)

    pwcheck = sqlR.checkPass("kay", "test!")
    print("checkpass for kay: \n", pwcheck)

##eof##########################################################################
